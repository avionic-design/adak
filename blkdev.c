/**
 * Copyright (C) 2012 Avionic Design GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "blkdev.h"

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

int blkdev_create(struct blkdev **devp, size_t extra)
{
	struct blkdev *dev;

	dev = calloc(1, sizeof(*dev) + extra);
	if (!dev)
		return -ENOMEM;

	*devp = dev;
	return 0;
}

int blkdev_free(struct blkdev *dev)
{
	if (!dev)
		return -EINVAL;

	if (!dev->ops)
		return -ENOSYS;

	if (dev->ops->free)
		dev->ops->free(dev);

	free(dev);
	return 0;
}

loff_t blkdev_seek(struct blkdev *dev, loff_t offset, int whence)
{
	if (!dev)
		return -EINVAL;

	switch (whence) {
	case SEEK_SET:
		dev->offset = offset;
		break;

	case SEEK_END:
		dev->offset = dev->size - offset;
		break;

	case SEEK_CUR:
		if (offset > 0) {
			if ((dev->offset + offset) > dev->size)
				dev->offset = dev->size;
			else
				dev->offset += offset;
		} else {
			if ((dev->offset + offset) >= 0)
				dev->offset += offset;
			else
				dev->offset = 0;
		}
		break;

	default:
		return -EINVAL;
	}

	return dev->offset;
}

ssize_t blkdev_write(struct blkdev *dev, const void *buffer, size_t size)
{
	size_t count = 0;
	loff_t offset;
	ssize_t err;
	void *cache;

	if (!dev)
		return -EINVAL;

	if (!dev->ops || !dev->ops->read)
		return -ENOSYS;

	cache = malloc(dev->block_size);
	if (!cache)
		return -ENOMEM;

	offset = dev->offset % dev->block_size;

	while (count < size) {
		size_t num = min(size - count, dev->block_size);

		if ((offset > 0) || (num < dev->block_size)) {
			err = dev->ops->read(dev, dev->offset - offset, cache, dev->block_size);
			if (err < 0) {
				free(cache);
				return err;
			}

			if (offset > 0)
				num = min(num, dev->block_size - offset);

			memcpy(cache + offset, buffer + count, num);

			err = dev->ops->write(dev, dev->offset - offset, cache, dev->block_size);
			if (err < 0) {
				free(cache);
				return err;
			}
		} else {
			err = dev->ops->write(dev, dev->offset, buffer + count, num);
			if (err < 0) {
				free(cache);
				return err;
			}
		}

		count += dev->block_size - offset;
		dev->offset += num;
		offset = 0;
	}

	return count;
}

ssize_t blkdev_read(struct blkdev *dev, void *buffer, size_t size)
{
	size_t count = 0;
	loff_t offset;
	ssize_t err;
	void *cache;

	if (!dev)
		return -EINVAL;

	if (!dev->ops || !dev->ops->write)
		return -ENOSYS;

	cache = malloc(dev->block_size);
	if (!cache)
		return -ENOMEM;

	offset = dev->offset % dev->block_size;

	while (count < size) {
		size_t num = min(size - count, dev->block_size);

		if ((offset > 0) || (num < dev->block_size)) {
			err = dev->ops->read(dev, dev->offset - offset, cache, dev->block_size);
			if (err < 0) {
				free(cache);
				return err;
			}

			if (offset > 0)
				num = min(num, dev->block_size - offset);

			memcpy(buffer + count, cache + offset, num);
		} else {
			err = dev->ops->read(dev, dev->offset, buffer + count, num);
			if (err < 0) {
				free(cache);
				return err;
			}
		}

		count += dev->block_size - offset;
		dev->offset += num;
		offset = 0;
	}

	return count;
}
