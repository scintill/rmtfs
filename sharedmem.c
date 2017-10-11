#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#ifndef NO_UDEV
#include <libudev.h>
#endif
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>
#include "rmtfs.h"

static int rmtfs_mem_enumerate(struct rmtfs_mem *rmem);

struct rmtfs_mem {
	unsigned long address;
	unsigned long size;
	uint8_t *base;
	int fd;
};

#ifndef NO_UDEV
static int parse_hex_sysattr(struct udev_device *dev, const char *name,
			     unsigned long *value)
{
	unsigned long val;
	const char *buf;
	char *endptr;

	buf = udev_device_get_sysattr_value(dev, name);
	if (!buf)
		return -ENOENT;

	errno = 0;
	val = strtoul(buf, &endptr, 16);
	if ((val == LONG_MAX && errno == ERANGE) || endptr == buf) {
		return -errno;
	}

	*value = val;

	return 0;
}
#endif

static int parse_hex_sysfsfile(int dir_fd, const char *name,
			     unsigned long *value)
{
	unsigned long val;
	char buf[32];
	char *endptr;
	int fd;

	fd = openat(dir_fd, name, O_RDONLY);
	if (fd < 0) {
		return -errno;
	}

	if (read(fd, buf, sizeof(buf)) < 0) {
		close(fd);
		return -errno;
	}

	close(fd);

	errno = 0;
	val = strtoul(buf, &endptr, 16);
	if ((val == LONG_MAX && errno == ERANGE) || endptr == buf) {
		return -errno;
	}

	*value = val;

	return 0;
}

#ifndef NO_UDEV
static int rmtfs_mem_open_rfsa(struct rmtfs_mem *rmem, int client_id)
{
	struct udev_device *dev;
	struct udev *udev;
	int saved_errno;
	struct stat sb;
	char path[32];
	int ret;
	int fd;

	sprintf(path, "/dev/qcom_rmtfs_mem%d", client_id);

	fd = open(path, O_RDWR);
	if (fd < 0) {
		saved_errno = errno;
		LOG("failed to open %s: %s\n", path, strerror(errno));
		return -saved_errno;
	}
	rmem->fd = fd;

	ret = fstat(fd, &sb);
	if (ret < 0) {
		saved_errno = errno;
		LOG("failed to stat %s: %s\n", path, strerror(errno));
		close(fd);
		goto err_close_fd;
	}

	udev = udev_new();
	if (!udev) {
		saved_errno = errno;
		LOG("failed to create udev context\n");
		goto err_close_fd;
	}

	dev = udev_device_new_from_devnum(udev, 'c', sb.st_rdev);
	if (!dev) {
		saved_errno = errno;
		LOG("unable to find udev device\n");
		goto err_unref_udev;
	}

	ret = parse_hex_sysattr(dev, "phys_addr", &rmem->address);
	if (ret < 0) {
		LOG("failed to parse phys_addr of %s\n", path);
		saved_errno = -ret;
		goto err_unref_dev;
	}

	ret = parse_hex_sysattr(dev, "size", &rmem->size);
	if (ret < 0) {
		LOG("failed to parse size of %s\n", path);
		saved_errno = -ret;
		goto err_unref_dev;
	}

	udev_device_unref(dev);
	udev_unref(udev);

	return 0;

err_unref_dev:
	udev_device_unref(dev);
err_unref_udev:
	udev_unref(udev);
err_close_fd:
	close(fd);
	return -saved_errno;
}
#endif

static int rmtfs_mem_open_uio(struct rmtfs_mem *rmem)
{
	int saved_errno;
	char path[64];
	char buf[32];
	int ret;
	int dir_fd;
	int fd;
	int uio_index;

	for (uio_index = 0; uio_index < 8; uio_index++) {
		snprintf(path, sizeof(path), "/sys/class/uio/uio%d", uio_index);
		dir_fd = open(path, O_DIRECTORY);
		if (dir_fd < 0) {
			saved_errno = errno;
			if (saved_errno != ENOENT) {
				LOG("failed to open %s: %s\n", path, strerror(errno));
			}
			goto ret;
		}

		fd = openat(dir_fd, "name", O_RDONLY);
		if (fd < 0) {
			saved_errno = errno;
			LOG("failed to open %s/name: %s\n", path, strerror(errno));
			goto close_dirfd;
		}

		if (read(fd, buf, sizeof(buf)) < 0) {
			saved_errno = errno;
			LOG("failed to read %s/name: %s\n", path, strerror(errno));
			close(fd);
			goto close_dirfd;
		}

		close(fd);

		if (strncmp(buf, "rmtfs\n", 6)) {
			continue;
		}

		ret = parse_hex_sysfsfile(dir_fd, "maps/map0/addr", &rmem->address);
		if (ret < 0) {
			LOG("failed to parse addr of %s\n", path);
			saved_errno = -ret;
			goto close_dirfd;
		}

		ret = parse_hex_sysfsfile(dir_fd, "maps/map0/size", &rmem->size);
		if (ret < 0) {
			LOG("failed to parse size of %s\n", path);
			saved_errno = -ret;
			goto close_dirfd;
		}

		snprintf(path, sizeof(path), "/dev/uio%d", uio_index);
		rmem->fd = open(path, O_RDWR);
		if (rmem->fd < 0) {
			saved_errno = errno;
			LOG("failed to open %s: %s\n", path, strerror(errno));
			return -saved_errno;
		}

		rmem->base = mmap(0, rmem->size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
		if (rmem->base == MAP_FAILED) {
			saved_errno = errno;
			LOG("failed to mmap: %s\n", strerror(errno));
			close(rmem->fd);
			goto close_dirfd;
		}

		saved_errno = 0;
		goto close_dirfd;
	}

	saved_errno = ENOENT;

close_dirfd:
	close(dir_fd);
ret:
	return -saved_errno;
}

struct rmtfs_mem *rmtfs_mem_open(void)
{
	struct rmtfs_mem *rmem;
	void *base;
	int ret;
	int fd;

	rmem = malloc(sizeof(*rmem));
	if (!rmem)
		return NULL;

	memset(rmem, 0, sizeof(*rmem));

#ifndef NO_UDEV
	ret = rmtfs_mem_open_rfsa(rmem, 1);
#else
	ret = -ENOENT;
#endif
	if (ret < 0 && ret != -ENOENT) {
		goto err;
	} else if (ret < 0) {
		ret = rmtfs_mem_open_uio(rmem);
		if (ret < 0 && ret != -ENOENT) {
			goto err;
		} else if (ret < 0) {
			LOG("falling back to /dev/mem access\n");

			ret = rmtfs_mem_enumerate(rmem);
			if (ret < 0)
				goto err;

			fd = open("/dev/mem", O_RDWR|O_SYNC);
			if (fd < 0) {
				LOG("failed to open /dev/mem\n");
				goto err;
			}

			base = mmap(0, rmem->size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, rmem->address);
			if (base == MAP_FAILED) {
				LOG("failed to mmap: %s\n", strerror(errno));
				goto err_close_fd;
			}

			rmem->base = base;
			rmem->fd = fd;
		}
	}

	return rmem;

err_close_fd:
	close(fd);
err:
	free(rmem);
	return NULL;
}

int64_t rmtfs_mem_alloc(struct rmtfs_mem *rmem, size_t alloc_size)
{
	if (alloc_size > rmem->size) {
		fprintf(stderr,
			"[RMTFS] rmtfs shared memory not large enough for allocation request 0x%zx vs 0x%lx\n",
			alloc_size, rmem->size);
		return -EINVAL;
	}

	return rmem->address;
}

void rmtfs_mem_free(struct rmtfs_mem *rmem)
{
}

static void *rmtfs_mem_ptr(struct rmtfs_mem *rmem, unsigned phys_address, ssize_t len)
{
	uint64_t start;
	uint64_t end;

	if (len < 0)
		return NULL;

	start = phys_address;
	end = start + len;

	if (start < rmem->address || end > rmem->address + rmem->size)
		return NULL;

	return rmem->base + phys_address - rmem->address;
}

ssize_t rmtfs_mem_read(struct rmtfs_mem *rmem, unsigned long phys_address, void *buf, ssize_t len)
{
	off_t offset;
	void *ptr;

	if (rmem->base) {
		ptr = rmtfs_mem_ptr(rmem, phys_address, len);
		if (!ptr)
			return -EINVAL;

		memcpy(buf, ptr, len);
	} else {
		offset = phys_address - rmem->address;
		len = pread(rmem->fd, buf, len, offset);
	}

	return len;
}

ssize_t rmtfs_mem_write(struct rmtfs_mem *rmem, unsigned long phys_address, const void *buf, ssize_t len)
{
	off_t offset;
	void *ptr;

	if (rmem->base) {
		ptr = rmtfs_mem_ptr(rmem, phys_address, len);
		if (!ptr)
			return -EINVAL;

		memcpy(ptr, buf, len);
	} else {
		offset = phys_address - rmem->address;
		len = pwrite(rmem->fd, buf, len, offset);
	}

	return len;
}

void rmtfs_mem_close(struct rmtfs_mem *rmem)
{
	if (rmem->base)
		munmap(rmem->base, rmem->size);

	close(rmem->fd);

	free(rmem);
}

static int rmtfs_mem_enumerate(struct rmtfs_mem *rmem)
{
	union {
		uint32_t dw[2];
		uint64_t qw[2];
	} reg;
	struct dirent *de;
	int basefd;
	int dirfd;
	int regfd;
	DIR *dir;
	int ret = 0;
	int n;

	basefd = open("/proc/device-tree/reserved-memory/", O_DIRECTORY);
	dir = fdopendir(basefd);
	if (!dir) {
		fprintf(stderr,
			"Unable to open reserved-memory device tree node: %s\n",
			strerror(-errno));
		close(basefd);
		return -1;
	}

	while ((de = readdir(dir)) != NULL) {
		if (strncmp(de->d_name, "rmtfs", 5) != 0)
			continue;

		dirfd = openat(basefd, de->d_name, O_DIRECTORY);
		if (dirfd < 0) {
			LOG("failed to open %s: %s\n",
				de->d_name, strerror(-errno));
			ret = -1;
			goto out;
		}

		regfd = openat(dirfd, "reg", O_RDONLY);
		if (regfd < 0) {
			LOG("failed to open reg of %s: %s\n",
				de->d_name, strerror(-errno));
			ret = -1;
			goto out;
		}

		n = read(regfd, &reg, sizeof(reg));
		if (n == 2 * sizeof(uint32_t)) {
			rmem->address = be32toh(reg.dw[0]);
			rmem->size = be32toh(reg.dw[1]);
		} else if (n == 2 * sizeof(uint64_t)) {
			rmem->address = be64toh(reg.qw[0]);
			rmem->size = be64toh(reg.qw[1]);
		} else {
			LOG("failed to read reg of %s: %s\n",
				de->d_name, strerror(-errno));
			ret = -1;
		}

		close(regfd);
		close(dirfd);
		break;
	}

out:
	closedir(dir);
	close(basefd);
	return ret;
}
