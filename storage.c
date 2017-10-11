#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "rmtfs.h"

#define MAX_CALLERS 10

struct partition {
	const char *path;
	const char *actual;
	int fd; // NB since all callers share the fd, they share state such as current offset - that'll work here, since we're single-threaded
};

struct caller {
	unsigned id;
	unsigned node;
	unsigned dev_error;
	const struct partition *partition;
};

static struct partition partition_table[] = {
#ifndef RMTFS_PARTITION_TABLE
	{ .path = "/boot/modem_fs1", .actual = "/boot/modem_fs1" },
	{ .path = "/boot/modem_fs2", .actual = "/boot/modem_fs2" },
	{ .path = "/boot/modem_fsc", .actual = "/boot/modem_fsc" },
	{ .path = "/boot/modem_fsg", .actual = "/boot/modem_fsg" },
#else
	RMTFS_PARTITION_TABLE
#endif
	{ 0 }
};

static struct caller caller_handles[MAX_CALLERS];

int storage_open(void)
{
	int i;
	struct partition *part;
	int saved_errno;

	for (i = 0; i < MAX_CALLERS; i++) {
		caller_handles[i].id = i;
		caller_handles[i].partition = NULL;
	}

	for (part = partition_table; part->path; part++) {
		part->fd = open(part->actual, O_RDWR);
		if (part->fd <= 0) {
			saved_errno = errno;
			LOG("[storage] failed to open '%s' (requested '%s'): %s\n",
					part->actual, part->path, strerror(-errno));
			return -saved_errno;
		}
	}

	return 0;
}

int storage_get(unsigned node, const char *path)
{
	const struct partition *part;
	struct caller *caller = NULL;
	int saved_errno;
	int i;

	for (part = partition_table; part->path; part++) {
		if (strcmp(part->path, path) == 0)
			goto found;
	}

	LOG("[RMTFS storage] request for unknown partition '%s', rejecting\n", path);
	return -EPERM;

found:
	/* Check if this node already has the requested path open */
	for (i = 0; i < MAX_CALLERS; i++) {
		if (caller_handles[i].node == node &&
		    caller_handles[i].partition == part)
			return caller_handles[i].id;
	}

	for (i = 0; i < MAX_CALLERS; i++) {
		if (caller_handles[i].partition == NULL) {
			caller = &caller_handles[i];
			break;
		}
	}
	if (!caller) {
		LOG("[storage] out of free caller handles\n");
		return -EBUSY;
	}

	caller->node = node;
	caller->partition = part;

	return caller->id;
}

int storage_put(unsigned node, int caller_id)
{
	struct caller *caller;

	if (caller_id >= MAX_CALLERS)
		return -EINVAL;

	caller = &caller_handles[caller_id];
	if (caller->node != node)
		return -EINVAL;

	caller->partition = NULL;

	return 0;
}

int storage_get_handle(unsigned node, int caller_id)
{
	struct caller *caller;

	if (caller_id >= MAX_CALLERS)
		return -EINVAL;

	caller = &caller_handles[caller_id];
	if (caller->node != node || caller->partition == NULL)
		return -EINVAL;

	return caller->partition->fd;
}

int storage_get_error(unsigned node, int caller_id)
{
	struct caller *caller;

	if (caller_id >= MAX_CALLERS)
		return -EINVAL;

	caller = &caller_handles[caller_id];
	if (caller->node != node)
		return -EINVAL;

	return caller->dev_error;
}

void storage_close(void)
{
	int i;
	const struct partition *part;

	for (part = partition_table; part->path; part++) {
		if (part->fd > 0)
			close(part->fd);
	}
}

