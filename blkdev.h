/**
 * Copyright (C) 2012 Avionic Design GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef ADAK_BLKDEV_H
#define ADAK_BLKDEV_H

#include <stdlib.h>
#include <unistd.h>

struct blkdev;

struct blkdev_ops {
	ssize_t (*write)(struct blkdev *dev, loff_t offset, const void *buffer, size_t size);
	ssize_t (*read)(struct blkdev *dev, loff_t offset, void *buffer, size_t size);
	void (*free)(struct blkdev *dev);
};

struct blkdev {
	struct blkdev_ops *ops;
	size_t block_size;
	loff_t offset;
	size_t size;
};

static inline void *blkdev_priv(struct blkdev *dev)
{
	return (void *)dev + sizeof(*dev);
}

int blkdev_create(struct blkdev **devp, size_t extra);
int blkdev_free(struct blkdev *dev);

loff_t blkdev_seek(struct blkdev *dev, loff_t offset, int whence);
ssize_t blkdev_write(struct blkdev *dev, const void *buffer, size_t size);
ssize_t blkdev_read(struct blkdev *dev, void *buffer, size_t size);

#endif /* ADAK_BLKDEV_H */
