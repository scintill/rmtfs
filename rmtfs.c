#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libqrtr.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "qmi_rmtfs.h"
#include "util.h"
#include "rmtfs.h"

#define RMTFS_QMI_SERVICE	14
#define RMTFS_QMI_VERSION	1
#define RMTFS_QMI_INSTANCE	0

static struct rmtfs_mem *rmem;

/* TODO: include from kernel? */
struct msm_ipc_port_addr {
	uint32_t node_id;
	uint32_t port_id;
};

struct msm_ipc_addr {
	unsigned char  addrtype;
	union {
		struct msm_ipc_port_addr port_addr;
	} addr;
};

#define MSM_IPC_ADDR_ID			2

struct sockaddr_msm_ipc {
	unsigned short family;
	struct msm_ipc_addr address;
	unsigned char reserved;
};

static bool dbgprintf_enabled;
static void dbgprintf(const char *fmt, ...)
{
	va_list ap;

	if (!dbgprintf_enabled)
		return;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

static void qmi_result_error(struct rmtfs_qmi_result *result, unsigned error)
{
	/* Only propagate initial error */
	if (result->result == QMI_RMTFS_RESULT_FAILURE)
		return;

	result->result = QMI_RMTFS_RESULT_FAILURE;
	result->error = error;
}

static void rmtfs_open(int sock, unsigned node, unsigned port, void *msg, size_t msg_len)
{
	struct rmtfs_qmi_result result = {};
	struct rmtfs_open_resp *resp;
	struct rmtfs_open_req *req;
	int caller_id = -1;
	unsigned txn;
	size_t len;
	void *ptr;
	char path[256] = {};
	int ret;

	req = rmtfs_open_req_parse(msg, msg_len, &txn);
	if (!req) {
		qmi_result_error(&result, QMI_RMTFS_ERR_MALFORMED_MSG);
		goto respond;
	}

	ret = rmtfs_open_req_get_path(req, path, sizeof(path));
	if (ret < 0) {
		qmi_result_error(&result, QMI_RMTFS_ERR_MALFORMED_MSG);
		goto respond;
	}

	caller_id = storage_get(node, path);
	if (caller_id < 0)
		qmi_result_error(&result, QMI_RMTFS_ERR_INTERNAL);

respond:
	dbgprintf("[RMTFS] open %s => %d (%d:%d)\n", path, caller_id, result.result, result.error);

	resp = rmtfs_open_resp_alloc(txn);
	rmtfs_open_resp_set_result(resp, &result);
	rmtfs_open_resp_set_caller_id(resp, caller_id);
	ptr = rmtfs_open_resp_encode(resp, &len);
	if (!ptr)
		goto free_resp;

	ret = qrtr_sendto(sock, node, port, ptr, len);
	if (ret < 0)
		fprintf(stderr, "[RMTFS] failed to send open-response: %s\n", strerror(-ret));

free_resp:
	rmtfs_open_resp_free(resp);
	rmtfs_open_req_free(req);
}

static void rmtfs_close(int sock, unsigned node, unsigned port, void *msg, size_t msg_len)
{
	struct rmtfs_qmi_result result = {};
	struct rmtfs_close_resp *resp;
	struct rmtfs_close_req *req;
	uint32_t caller_id;
	unsigned txn;
	size_t len;
	void *ptr;
	int ret;

	req = rmtfs_close_req_parse(msg, msg_len, &txn);
	if (!req) {
		qmi_result_error(&result, QMI_RMTFS_ERR_MALFORMED_MSG);
		goto respond;
	}

	ret = rmtfs_close_req_get_caller_id(req, &caller_id);
	if (ret < 0) {
		qmi_result_error(&result, QMI_RMTFS_ERR_MALFORMED_MSG);
		goto respond;
	}

	ret = storage_put(node, caller_id);
	if (ret < 0)
		qmi_result_error(&result, QMI_RMTFS_ERR_INTERNAL);

	rmtfs_mem_free(rmem);

respond:
	dbgprintf("[RMTFS] close %d => (%d:%d)\n", caller_id, result.result, result.error);

	resp = rmtfs_close_resp_alloc(txn);
	rmtfs_close_resp_set_result(resp, &result);
	ptr = rmtfs_close_resp_encode(resp, &len);
	if (!ptr)
		goto free_resp;

	ret = qrtr_sendto(sock, node, port, ptr, len);
	if (ret < 0)
		fprintf(stderr, "[RMTFS] failed to send close-response: %s\n", strerror(-ret));

free_resp:
	rmtfs_close_resp_free(resp);
	rmtfs_close_req_free(req);
}

static void rmtfs_iovec(int sock, unsigned node, unsigned port, void *msg, size_t msg_len)
{
	struct rmtfs_iovec_entry *entries = NULL;
	struct rmtfs_qmi_result result = {};
	struct rmtfs_iovec_resp *resp;
	struct rmtfs_iovec_req *req;
	unsigned long phys_offset;
	uint32_t caller_id;
	size_t num_entries;
	uint8_t is_write;
	uint8_t force;
	unsigned txn;
	ssize_t n;
	size_t len;
	void *ptr;
	char buf[SECTOR_SIZE];
	int ret;
	int fd;
	int i;
	int j;

	req = rmtfs_iovec_req_parse(msg, msg_len, &txn);
	if (!req) {
		qmi_result_error(&result, QMI_RMTFS_ERR_MALFORMED_MSG);
		goto respond;
	}

	ret = rmtfs_iovec_req_get_caller_id(req, &caller_id);
	if (ret < 0) {
		qmi_result_error(&result, QMI_RMTFS_ERR_MALFORMED_MSG);
		goto respond;
	}

	ret = rmtfs_iovec_req_get_direction(req, &is_write);
	if (ret < 0) {
		qmi_result_error(&result, QMI_RMTFS_ERR_MALFORMED_MSG);
		goto respond;
	}

	entries = rmtfs_iovec_req_get_iovec(req, &num_entries);
	if (!entries) {
		qmi_result_error(&result, QMI_RMTFS_ERR_MALFORMED_MSG);
		goto respond;
	}

	ret = rmtfs_iovec_req_get_is_force_sync(req, &force);
	if (ret < 0) {
		qmi_result_error(&result, QMI_RMTFS_ERR_MALFORMED_MSG);
		goto respond;
	}

	fd = storage_get_handle(node, caller_id);
	if (fd < 0) {
		fprintf(stderr, "[RMTFS] iovec request for non-existing caller\n");
		qmi_result_error(&result, QMI_RMTFS_ERR_INTERNAL);
		goto respond;
	}

	for (i = 0; i < num_entries; i++) {
		phys_offset = entries[i].phys_offset;

		n = lseek(fd, entries[i].sector_addr * SECTOR_SIZE, SEEK_SET);
		if (n < 0) {
			fprintf(stderr, "[RMTFS] failed to seek sector %d\n", entries[i].sector_addr);
			qmi_result_error(&result, QMI_RMTFS_ERR_INTERNAL);
			goto respond;
		}

		for (j = 0; j < entries[i].num_sector; j++) {
			if (is_write) {
				n = rmtfs_mem_read(rmem, phys_offset, buf, SECTOR_SIZE);
				n = write(fd, buf, n);
			} else {
				n = read(fd, buf, SECTOR_SIZE);
				n = rmtfs_mem_write(rmem, phys_offset, buf, n);
			}

			if (n != SECTOR_SIZE) {
				fprintf(stderr, "[RMTFS] failed to %s sector %d\n",
					is_write ? "write" : "read", entries[i].sector_addr + j);
				qmi_result_error(&result, QMI_RMTFS_ERR_INTERNAL);
				goto respond;
			}

			phys_offset += SECTOR_SIZE;
		}
	}

respond:
	dbgprintf("[RMTFS] iovec %d, %sforced => (%d:%d)\n", caller_id, force ? "" : "not ",
							     result.result, result.error);
	for (i = 0; i < num_entries; i++) {
		dbgprintf("[RMTFS]       %s %d:%d 0x%x\n", is_write ? "write" : "read",
							   entries[i].sector_addr,
							   entries[i].num_sector,
							   entries[i].phys_offset);
	}

	resp = rmtfs_iovec_resp_alloc(txn);
	rmtfs_iovec_resp_set_result(resp, &result);
	ptr = rmtfs_iovec_resp_encode(resp, &len);
	if (!ptr)
		goto free_resp;

	ret = qrtr_sendto(sock, node, port, ptr, len);
	if (ret < 0)
		fprintf(stderr, "[RMTFS] failed to send iovec-response: %s\n", strerror(-ret));

free_resp:
	rmtfs_iovec_resp_free(resp);
	rmtfs_iovec_req_free(req);
}

static void rmtfs_alloc_buf(int sock, unsigned node, unsigned port, void *msg, size_t msg_len)
{
	struct rmtfs_alloc_buf_resp *resp;
	struct rmtfs_alloc_buf_req *req;
	struct rmtfs_qmi_result result = {};
	uint32_t alloc_size;
	uint32_t caller_id;
	int64_t address = 0;
	unsigned txn;
	size_t len;
	void *ptr;
	int ret;

	req = rmtfs_alloc_buf_req_parse(msg, msg_len, &txn);
	if (!req) {
		qmi_result_error(&result, QMI_RMTFS_ERR_MALFORMED_MSG);
		goto respond;
	}

	ret = rmtfs_alloc_buf_req_get_caller_id(req, &caller_id);
	if (ret < 0) {
		qmi_result_error(&result, QMI_RMTFS_ERR_MALFORMED_MSG);
		goto respond;
	}

	ret = rmtfs_alloc_buf_req_get_buff_size(req, &alloc_size);
	if (ret < 0) {
		qmi_result_error(&result, QMI_RMTFS_ERR_MALFORMED_MSG);
		goto respond;
	}

	address = rmtfs_mem_alloc(rmem, alloc_size);
	if (address < 0)
		qmi_result_error(&result, QMI_RMTFS_ERR_INTERNAL);

respond:
	dbgprintf("[RMTFS] alloc %d, %d => 0x%lx (%d:%d)\n", caller_id, alloc_size, address, result.result, result.error);

	resp = rmtfs_alloc_buf_resp_alloc(txn);
	rmtfs_alloc_buf_resp_set_result(resp, &result);
	rmtfs_alloc_buf_resp_set_buff_address(resp, address);
	ptr = rmtfs_alloc_buf_resp_encode(resp, &len);
	if (!ptr)
		goto free_resp;

	ret = qrtr_sendto(sock, node, port, ptr, len);
	if (ret < 0)
		fprintf(stderr, "[RMTFS] failed to send alloc-response: %s\n", strerror(-ret));

free_resp:
	rmtfs_alloc_buf_resp_free(resp);
	rmtfs_alloc_buf_req_free(req);
}

static void rmtfs_get_dev_error(int sock, unsigned node, unsigned port, void *msg, size_t msg_len)
{
	struct rmtfs_dev_error_resp *resp;
	struct rmtfs_dev_error_req *req;
	struct rmtfs_qmi_result result = {};
	uint32_t caller_id;
	int dev_error = 0;
	unsigned txn;
	size_t len;
	void *ptr;
	int ret;

	req = rmtfs_dev_error_req_parse(msg, msg_len, &txn);
	if (!req) {
		qmi_result_error(&result, QMI_RMTFS_ERR_MALFORMED_MSG);
		goto respond;
	}

	ret = rmtfs_dev_error_req_get_caller_id(req, &caller_id);
	if (ret < 0) {
		qmi_result_error(&result, QMI_RMTFS_ERR_MALFORMED_MSG);
		goto respond;
	}

	dev_error = storage_get_error(node, caller_id);
	if (dev_error < 0)
		qmi_result_error(&result, QMI_RMTFS_ERR_INTERNAL);

respond:
	dbgprintf("[RMTFS] dev_error %d => %d (%d:%d)\n", caller_id, dev_error, result.result, result.error);

	resp = rmtfs_dev_error_resp_alloc(txn);
	rmtfs_dev_error_resp_set_result(resp, &result);
	rmtfs_dev_error_resp_set_status(resp, dev_error);
	ptr = rmtfs_dev_error_resp_encode(resp, &len);
	if (!ptr)
		goto free_resp;

	ret = qrtr_sendto(sock, node, port, ptr, len);
	if (ret < 0)
		fprintf(stderr, "[RMTFS] failed to send error-response: %s\n", strerror(-ret));

free_resp:
	rmtfs_dev_error_resp_free(resp);
	rmtfs_dev_error_req_free(req);
}

static int rmtfs_bye(uint32_t node, void *data)
{
	dbgprintf("[RMTFS] bye from %d\n", node);

	return 0;
}

static int rmtfs_del_client(uint32_t node, uint32_t port, void *data)
{
	dbgprintf("[RMTFS] del_client %d:%d\n", node, port);

	return 0;
}

struct qrtr_ind_ops rmtfs_ctrl_ops = {
	.bye = rmtfs_bye,
	.del_client = rmtfs_del_client,
};

static int handle_rmtfs(int sock)
{
	struct sockaddr_msm_ipc smi;
	struct qmi_packet *qmi;
	socklen_t sl;
	char buf[4096];
	int ret;
	uint32_t sq_node, sq_port;

	sl = sizeof(smi);
	ret = recvfrom(sock, buf, sizeof(buf), 0, (void *)&smi, &sl);
	if (ret < 0) {
		ret = -errno;
		if (ret != -ENETRESET)
			fprintf(stderr, "[RMTFS] recvfrom failed: %d\n", ret);
		return ret;
	}

	if (smi.address.addrtype != MSM_IPC_ADDR_ID) {
		fprintf(stderr, "[RMTFS] unexpected IPC addrtype\n");
		return -EINVAL;
	}

	sq_node = smi.address.addr.port_addr.node_id;
	sq_port = smi.address.addr.port_addr.port_id;
	dbgprintf("[RMTFS] packet; from: %d:%d\n", sq_node, sq_port);

	if (qrtr_is_ctrl_addr(&smi)) {
		return qrtr_handle_ctrl_msg(&smi, buf, sizeof(buf),
					    &rmtfs_ctrl_ops, NULL);
	}

	qmi = (struct qmi_packet*)buf;
	if (qmi->msg_len != ret - sizeof(struct qmi_packet)) {
		fprintf(stderr, "[RMTFS] Invalid length of incoming qmi request\n");
		return -EINVAL;
	}

	switch (qmi->msg_id) {
	case QMI_RMTFS_OPEN:
		rmtfs_open(sock, sq_node, sq_port, qmi, qmi->msg_len);
		break;
	case QMI_RMTFS_CLOSE:
		rmtfs_close(sock, sq_node, sq_port, qmi, qmi->msg_len);
		break;
	case QMI_RMTFS_RW_IOVEC:
		rmtfs_iovec(sock, sq_node, sq_port, qmi, qmi->msg_len);
		break;
	case QMI_RMTFS_ALLOC_BUFF:
		rmtfs_alloc_buf(sock, sq_node, sq_port, qmi, qmi->msg_len);
		break;
	case QMI_RMTFS_GET_DEV_ERROR:
		rmtfs_get_dev_error(sock, sq_node, sq_port, qmi, qmi->msg_len);
		break;
	default:
		fprintf(stderr, "[RMTFS] Unknown request: %d\n", qmi->msg_id);
		ret = -EINVAL;
		break;
	}

	return ret;
}

int main(int argc, char **argv)
{
	bool do_register = true;
	int rmtfs_fd;
	fd_set rfds;
	int nfds;
	int ret;

	if (argc == 2 && strcmp(argv[1], "-v") == 0)
		dbgprintf_enabled = true;

	rmem = rmtfs_mem_open();
	if (!rmem)
		return 1;

	ret = storage_open();
	if (ret) {
		fprintf(stderr, "failed to initialize storage system\n");
		goto close_rmtfs_mem;
	}

	rmtfs_fd = qrtr_open(RMTFS_QMI_SERVICE);
	if (rmtfs_fd < 0) {
		fprintf(stderr, "failed to create qrtr socket\n");
		goto close_storage;
	}

	for (;;) {
		if (do_register) {
			dbgprintf("registering services\n");

			ret = qrtr_publish(rmtfs_fd, RMTFS_QMI_SERVICE, RMTFS_QMI_VERSION, RMTFS_QMI_INSTANCE);
			if (ret < 0) {
				fprintf(stderr, "failed to publish rmtfs service. waiting and trying again...");
				sleep(3);
				ret = qrtr_publish(rmtfs_fd, RMTFS_QMI_SERVICE, RMTFS_QMI_VERSION, RMTFS_QMI_INSTANCE);
				if (ret < 0) {
					fprintf(stderr, "failed to publish rmtfs service");
					break;
				}
			}

			do_register = false;
		}

		FD_ZERO(&rfds);
		FD_SET(rmtfs_fd, &rfds);

		nfds = rmtfs_fd + 1;
		ret = select(nfds, &rfds, NULL, NULL, NULL);
		if (ret < 0) {
			fprintf(stderr, "select failed: %d\n", ret);
			break;
		} else if (ret == 0) {
			continue;
		}

		if (FD_ISSET(rmtfs_fd, &rfds))
			ret = handle_rmtfs(rmtfs_fd);

		if (ret == -ENETRESET)
			do_register = true;
	}

	qrtr_bye(rmtfs_fd, RMTFS_QMI_SERVICE, RMTFS_QMI_VERSION, RMTFS_QMI_INSTANCE);
close_storage:
	storage_close();
close_rmtfs_mem:
	rmtfs_mem_close(rmem);

	return 0;
}
