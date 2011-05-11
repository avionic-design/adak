/**
 * Copyright (C) 2011 Avionic Design GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef STREAM_H
#define STREAM_H 1

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stream;

int stream_open(struct stream **streamp, const char *filename, size_t capacity);
int stream_close(struct stream *stream);
off_t stream_seek(struct stream *stream, off_t offset, int whence);
ssize_t stream_read(struct stream *stream, void *buf, size_t len);
ssize_t stream_read_byte(struct stream *stream, uint8_t *valuep);
ssize_t stream_read_be16(struct stream *stream, uint16_t *valuep);
ssize_t stream_read_be32(struct stream *stream, uint32_t *valuep);

#ifdef __cplusplus
}
#endif

#endif /* STREAM_H */
