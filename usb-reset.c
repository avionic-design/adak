/**
 * Copyright (C) 2011 Avionic Design GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/usbdevice_fs.h>

int main(int argc, char *argv[])
{
	int err;
	int fd;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s DEVICE\n", argv[0]);
		return 1;
	}

	fd = open(argv[1], O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: %s: %s\n", argv[0], argv[1],
				strerror(errno));
		return 1;
	}

	err = ioctl(fd, USBDEVFS_RESET, 0);
	if (err < 0) {
		fprintf(stderr, "%s: %s: %s\n", argv[0], argv[1],
				strerror(errno));
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}
