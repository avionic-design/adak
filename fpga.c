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

#include "stream.h"
#include "utils.h"

static const char DEFAULT_FILE[] = "/dev/mtd0";

struct cli_opts {
	const char *file;
	bool help;
	bool version;
};

static const char help_summary[] = ""
	"Usage: %s [options]\n"
	"\n"
	"Extract FPGA version information from a bitfile or an MTD device.\n"
	"\n";

static const char help_options[] = "Options:\n"
	"  -f, --file      Path to bitfile or MTD device file.\n"
	"  -h, --help      Display help screen and exit.\n"
	"  -V, --version   Display program version and exit.\n";

static void usage(FILE *fp, const char *program)
{
	fprintf(fp, help_summary, program);
	fputs(help_options, fp);
	fputs("\n", fp);
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

static off_t stream_find(struct stream *stream, const void *buf, size_t len)
{
	off_t found = -ENODATA;
	off_t match = 0;
	ssize_t err;

	while (found < 0) {
		uint8_t byte;

		err = stream_read(stream, &byte, sizeof(byte));
		if (err <= 0) {
			if (err < 0)
				found = err;

			break;
		}

		if (((uint8_t *)buf)[match] == byte) {
			if (match == (len - 1)) {
				found = stream_seek(stream, -len, SEEK_CUR);
				break;
			}

			match++;
		} else if (match > 0) {
			err = stream_seek(stream, -match, SEEK_CUR);
			if (err < 0)
				break;

			match = 0;
		}
	}

	return found;
}

static uint32_t revl(uint32_t value)
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

	err = stream_seek(stream, sizeof(header_end), SEEK_CUR);
	if (err < 0)
		return err;

	err = stream_find(stream, reset_addr, sizeof(reset_addr));
	if (err < 0)
		return err;

	err = stream_seek(stream, sizeof(reset_addr) + 2, SEEK_CUR);
	if (err < 0)
		return err;

	err = stream_read_be16(stream, &frame_count);
	if (err < 0)
		return err;

	err = stream_seek(stream, 0, SEEK_CUR);
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

	err = stream_seek(stream, sizeof(frame_stop), SEEK_CUR);
	if (err < 0)
		return err;

	end = err;

	err = stream_seek(stream, (end - start) * (frame_count - 1), SEEK_CUR);
	if (err < 0)
		return err;

	err = stream_find(stream, end_marker, sizeof(end_marker));
	if (err < 0)
		return err;

	err = stream_seek(stream, sizeof(end_marker), SEEK_CUR);
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

#define USER_CODE_UNRELEASED (1 << 31)

static const struct {
	uint16_t platform;
	const char *name;
} platform_names[] = {
	{ 0xff7, "Medatom" },
	{ 0, NULL },
};

static const char *lookup_platform_name(uint16_t platform)
{
	unsigned int i;

	for (i = 0; platform_names[i].name; i++) {
		if (platform_names[i].platform == platform)
			return platform_names[i].name;
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	uint32_t user_code = 0;
	struct stream *stream;
	struct cli_opts opts;
	uint16_t platform;
	const char *name;
	uint8_t major;
	uint8_t minor;
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

	err = stream_open(&stream, opts.file, 512);
	if (err < 0) {
		fprintf(stderr, "%s: %s: %s\n", argv[0], opts.file,
				strerror(-err));
		return 1;
	}

	err = stream_find_user_code(stream);
	if (err < 0) {
		fprintf(stderr, "%s: %s: version information not found\n",
				argv[0], opts.file);
		return 1;
	}

	err = stream_read_user_code(stream, &user_code);
	if (err < 0) {
		fprintf(stderr, "%s: %s: cannot read version information\n",
				argv[0], opts.file);
		return 1;
	}

	platform = (user_code >> 16) & 0xfff;
	major = (user_code >> 8) & 0xff;
	minor = (user_code >> 0) & 0xff;

	name = lookup_platform_name(platform);
	if (!name)
		printf("Unknown (%#x)", platform);
	else
		printf("%s", name);

	printf(" v%u.%u", major, minor);

	if (user_code & USER_CODE_UNRELEASED)
		printf(" (unreleased)");

	printf("\n");

	stream_close(stream);
	return 0;
}
