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
#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"

static const char DEFAULT_FILE[] = "/dev/mtd0";

struct cli_opts {
	const char *file;
	bool help;
	bool version;
};

static const char options_help[] = "Options:\n"
	"  -f, --file      Path to filename to extract the FPGA version from.\n"
	"  -h, --help      Display help screen and exit.\n"
	"  -V, --version   Display program version and exit.\n";

static void usage(FILE *fp, const char *program)
{
	fprintf(fp, "Usage: %s [options]\n", program);
	fputs(options_help, fp);
}

static int parse_command_line(struct cli_opts *opts, int argc, char *argv[])
{
	static const struct option options[] = {
		{ "file", 1, NULL, 'f' },
		{ "help", 0, NULL, 'h' },
		{ "version", 0, NULL, 'V' },
		{ NULL, 0, NULL, 0 }
	};
	int opt;

	memset(opts, 0, sizeof(*opts));
	opts->file = DEFAULT_FILE;
	opts->help = false;
	opts->version = false;

	while ((opt = getopt_long(argc, argv, "f:hV", options, NULL)) != -1) {
		switch (opt) {
		case 'f':
			opts->file = optarg;
			break;

		case 'h':
			opts->help = true;
			break;

		case 'V':
			opts->version = true;
			break;

		default:
			return -1;
		}
	}

	return 0;
}

struct stream {
	size_t capacity;
	size_t length;
	size_t offset;
	void *buf;

	size_t position;
	int fd;
};

struct stream *stream_open(const char *filename)
{
	struct stream *stream;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return NULL;

	stream = calloc(1, sizeof(*stream));
	if (!stream)
		return NULL;

	stream->buf = calloc(1, 512);
	if (!stream->buf) {
		free(stream);
		return NULL;
	}

	stream->capacity = 512;
	stream->length = 0;
	stream->offset = 0;

	stream->position = 0;
	stream->fd = fd;

	return stream;
}

void stream_close(struct stream *stream)
{
	assert(stream != NULL);

	if (stream->buf)
		free(stream->buf);

	close(stream->fd);
	free(stream);
}

ssize_t stream_fill(struct stream *stream)
{
	if (stream->offset >= stream->length) {
		ssize_t err;

		stream->position += stream->length;

		err = read(stream->fd, stream->buf, stream->capacity);
		if (err < 0)
			return errno;

		stream->length = err;
		stream->offset = 0;
	}

	return stream->length - stream->offset;
}

ssize_t stream_skip(struct stream *stream, size_t amount)
{
	size_t skipped = 0;

	while (skipped < amount) {
		size_t remaining;
		size_t count;

		ssize_t err = stream_fill(stream);
		if (err < 0)
			return err;

		remaining = stream->length - stream->offset;
		count = amount - skipped;

		if (count < remaining) {
			stream->offset += count;
			skipped += count;
		} else {
			stream->offset += remaining;
			skipped += remaining;
		}
	}

	return skipped;
}

ssize_t stream_read(struct stream *stream, void *buf, size_t len)
{
	size_t pos = 0;
	ssize_t err;
	size_t copy;

	while ((len - pos) > (stream->length - stream->offset)) {
		if (stream->offset < stream->length) {
			size_t size = stream->length - stream->offset;
			memcpy(buf, stream->buf + stream->offset, size);
			stream->offset += size;
			pos += size;
		}

		err = stream_fill(stream);
		if (err <= 0) {
			if (err == 0)
				break;

			return err;
		}
	}

	copy = min(len - pos, stream->length - stream->offset);
	if (copy > 0) {
		memcpy(buf + pos, stream->buf + stream->offset, copy);
		stream->offset += copy;
	}

	return pos + copy;
}

ssize_t stream_find(struct stream *stream, const void *buf, size_t len)
{
	const uint8_t *ptr = buf;
	ssize_t found = -ENODATA;
	const uint8_t *bufptr;
	size_t match = 0;
	ssize_t err;

	while (found < 0) {
		err = stream_fill(stream);
		if (err <= 0) {
			if (err < 0)
				found = err;

			break;
		}

		bufptr = stream->buf;

		for (stream->offset = stream->offset; stream->offset < stream->length; stream->offset++) {
			if (bufptr[stream->offset] == ptr[match]) {
				if (match == (len - 1)) {
					stream->offset -= len - 1;
					found = stream->position + stream->offset;
					break;
				}

				match++;
			} else {
				stream->offset -= match;
				match = 0;
			}
		}
	}

	return found;
}

ssize_t stream_tell(struct stream *stream)
{
	return stream->position + stream->offset;
}

ssize_t stream_read_byte(struct stream *stream, uint8_t *value)
{
	return stream_read(stream, value, sizeof(*value));
}

ssize_t stream_read_be16(struct stream *stream, uint16_t *value)
{
	uint16_t data = 0;
	ssize_t ret;

	ret = stream_read(stream, &data, sizeof(data));
	*value = be16toh(data);

	return ret;
}

ssize_t stream_read_be32(struct stream *stream, uint32_t *value)
{
	uint32_t data = 0;
	ssize_t ret;

	ret = stream_read(stream, &data, sizeof(data));
	*value = be32toh(data);

	return ret;
}

uint32_t revl(uint32_t value)
{
	uint32_t ret = value;

	ret = ((ret >>  1) & 0x55555555) | ((ret <<  1) & 0xaaaaaaaa);
	ret = ((ret >>  2) & 0x33333333) | ((ret <<  2) & 0xcccccccc);
	ret = ((ret >>  4) & 0x0f0f0f0f) | ((ret <<  4) & 0xf0f0f0f0);
	ret = ((ret >>  8) & 0x00ff00ff) | ((ret <<  8) & 0xff00ff00);
	ret = ((ret >> 16) & 0x0000ffff) | ((ret << 16) & 0xffff0000);

	return ret;
}

static int stream_find_user_code(struct stream *stream)
{
	static const uint8_t header_end[] = { 0xff, 0xff, 0xbd, 0xb3 };
	static const uint8_t reset_addr[] = { 0x62, 0x00, 0x00, 0x00 };
	static const uint8_t frame_stop[] = { 0xff, 0xff, 0xff, 0xff };
	static const uint8_t end_marker[] = { 0x2c, 0xce, 0x43, 0x00, 0x00, 0x00 };
	uint16_t frame_count = 0;
	uint8_t frame_start = 0;
	size_t start;
	ssize_t err;
	size_t end;

	err = stream_find(stream, header_end, sizeof(header_end));
	if (err < 0)
		return err;

	err = stream_skip(stream, sizeof(header_end));
	if (err < 0)
		return err;

	err = stream_find(stream, reset_addr, sizeof(reset_addr));
	if (err < 0)
		return err;

	err = stream_skip(stream, sizeof(reset_addr) + 2);
	if (err < 0)
		return err;

	err = stream_read_be16(stream, &frame_count);
	if (err < 0)
		return err;

	err = stream_tell(stream);
	if (err < 0)
		return err;

	start = err;

	err = stream_read_byte(stream, &frame_start);
	if (err < 0)
		return err;

	if (frame_start != 0xf0)
		return EILSEQ;

	err = stream_find(stream, frame_stop, sizeof(frame_stop));
	if (err < 0)
		return err;

	err = stream_skip(stream, sizeof(frame_stop));
	if (err < 0)
		return err;

	err = stream_tell(stream);
	if (err < 0)
		return err;

	end = err;

	err = stream_skip(stream, (end - start) * (frame_count - 1));
	if (err < 0)
		return err;

	err = stream_tell(stream);
	if (err < 0)
		return err;

	err = stream_find(stream, end_marker, sizeof(end_marker));
	if (err < 0)
		return err;

	err = stream_skip(stream, sizeof(end_marker));
	if (err < 0)
		return err;

	return 0;
}

static ssize_t stream_read_user_code(struct stream *stream, uint32_t *code)
{
	uint32_t user_code = 0;
	ssize_t err;

	err = stream_read_be32(stream, &user_code);
	if (err < 0)
		return -errno;

	*code = revl(user_code);
	return 0;
}

int main(int argc, char *argv[])
{
	uint32_t user_code = 0;
	struct stream *stream;
	struct cli_opts opts;
	ssize_t err;

	err = parse_command_line(&opts, argc, argv);
	if (err < 0) {
		usage(stderr, argv[0]);
		return 1;
	}

	if (opts.help) {
		usage(stdout, argv[0]);
		return 0;
	}

	if (opts.version) {
		adak_program_version(stdout, argv[0]);
		return 0;
	}

	stream = stream_open(opts.file);
	if (!stream) {
		fprintf(stderr, "stream_open(): %s\n", strerror(errno));
		return 1;
	}

	err = stream_find_user_code(stream);
	if (err < 0)
		return ENXIO;

	err = stream_read_user_code(stream, &user_code);
	if (err < 0)
		return EIO;

	printf("user-code: %08x\n", user_code);

	stream_close(stream);
	return 0;
}
