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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "stream.h"

#define min(a, b) (((a) < (b)) ? (a) : (b))

struct stream {
	int fd;
	off_t position;
	off_t offset;

	size_t capacity;
	size_t length;
	void *buffer;
};

int stream_open(struct stream **streamp, const char *filename, size_t capacity)
{
	struct stream *stream;
	int err = 0;

	stream = calloc(1, sizeof(*stream));
	if (!stream)
		return -ENOMEM;

	stream->fd = open(filename, O_RDONLY);
	if (stream->fd < 0) {
		err = -errno;
		goto free;
	}

	stream->position = -capacity;
	stream->offset = 0;

	stream->capacity = capacity;
	stream->length = 0;

	stream->buffer = calloc(1, capacity);
	if (!stream->buffer) {
		err = -ENOMEM;
		goto close;
	}

	*streamp = stream;
	return 0;

close:
	close(stream->fd);
free:
	free(stream);
	return err;
}

int stream_close(struct stream *stream)
{
	if (!stream)
		return -EINVAL;

	free(stream->buffer);
	close(stream->fd);
	free(stream);
	return 0;
}

off_t stream_seek(struct stream *stream, off_t offset, int whence)
{
	switch (whence) {
	case SEEK_SET:
		return -EINVAL;

	case SEEK_CUR:
		if (offset > 0) {
			size_t blocks;

			offset = stream->offset + offset;

			if (offset <= stream->length) {
				stream->offset = offset;
				break;
			}

			blocks = offset / stream->capacity;
			if (blocks > 0) {
				stream->position = lseek(stream->fd,
						(blocks - 1) * stream->capacity,
						SEEK_CUR);
			}

			stream->offset = offset % stream->capacity;
			stream->length = 0;
		} else {
			if (-offset < stream->offset)
				stream->offset += offset;
			else {
				/*
				 * FIXME: Implement seeking backwards across
				 *        a block boundary.
				 */
				return -ENXIO;
			}
		}
		break;

	case SEEK_END:
		return -EINVAL;
	}

	return stream->position + stream->offset;
}

static ssize_t stream_copy(struct stream *stream, void *buf, size_t len)
{
	size_t num = min(stream->length - stream->offset, len);
	memcpy(buf, stream->buffer + stream->offset, num);
	stream->offset += num;
	return num;
}

static ssize_t stream_fill(struct stream *stream)
{
	stream->length = 0;

	while (stream->length < stream->capacity) {
		size_t rem = stream->capacity - stream->length;
		ssize_t err;

		err = read(stream->fd, stream->buffer + stream->length, rem);
		if (err <= 0) {
			if (errno == EINTR)
				continue;

			if (err == 0)
				break;

			return -errno;
		}

		stream->position += err;
		stream->length += err;
	}

	return stream->length;
}

ssize_t stream_read(struct stream *stream, void *buf, size_t len)
{
	off_t pos = 0;

	while (pos < len) {
		size_t remaining = len - pos;
		size_t available;
		size_t num;

		if (stream->offset >= stream->length) {
			ssize_t err = stream_fill(stream);
			if (err < 0) {
				if (pos)
					break;

				return err;
			}

			stream->offset = 0;
		}

		available = stream->length - stream->offset;

		num = min(remaining, available);
		stream_copy(stream, buf + pos, num);
		pos += num;
	}

	return pos;
}

ssize_t stream_read_byte(struct stream *stream, uint8_t *valuep)
{
	return stream_read(stream, valuep, sizeof(*valuep));
}

ssize_t stream_read_be16(struct stream *stream, uint16_t *valuep)
{
	uint16_t data = 0;
	ssize_t ret;

	ret = stream_read(stream, &data, sizeof(data));
	*valuep = be16toh(data);

	return ret;
}

ssize_t stream_read_be32(struct stream *stream, uint32_t *valuep)
{
	uint32_t data = 0;
	ssize_t ret;

	ret = stream_read(stream, &data, sizeof(data));
	*valuep = be32toh(data);

	return ret;
}
