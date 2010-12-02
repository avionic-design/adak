/**
 * Copyright (C) 2010 Avionic Design GmbH
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
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "command.h"

#if __WORDSIZE == 64
#  define FMT_UINT64 "lu"
#else
#  define FMT_UINT64 "llu"
#endif

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define BIT(x) (1 << (x))

static const char DEFAULT_INTERFACE[] = "eth0";

struct context {
	const char *interface;
	int help;
};

int eth_get_hwaddr(const char *interface, uint8_t *hwaddr, size_t size)
{
	struct ifreq req;
	int err;
	int fd;

	memset(&req, 0, sizeof(req));
	strncpy(req.ifr_name, interface, IFNAMSIZ);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;

	err = ioctl(fd, SIOCGIFHWADDR, &req);
	if (err < 0) {
		err = -errno;
		close(fd);
		return err;
	}

	err = min(size, ETH_ALEN);

	memcpy(hwaddr, req.ifr_hwaddr.sa_data, err);

	close(fd);
	return err;
}

/**
 * "help" command
 */
static int help_exec(int argc, char *argv[], void *data)
{
	const struct command *command;
	int maxlen = 0;

	if (argc < 2) {
		fprintf(stdout, "Commands:\n\n");

		foreach_command(command) {
			int len = strlen(command->synopsis);

			if (len > maxlen)
				maxlen = len;
		}

		foreach_command(command) {
			fprintf(stdout, "    %-*s    %s\n", maxlen,
					command->synopsis, command->summary);
		}

		fprintf(stdout, "\n");
	} else {
		command = find_command(argv[1]);
		if (!command) {
			fprintf(stderr, "no such command: %s\n", argv[1]);
			return 1;
		}

		fprintf(stdout, "%s - %s\n", command->synopsis, command->summary);

		if (command->help)
			fprintf(stdout, "%s\n", command->help);
	}

	return 0;
}

DEFINE_COMMAND(help, "help [command]",
		"display help screen or command-specific help",
		NULL, help_exec);

/**
 * "dump" command
 */
static int dump_exec(int argc, char *argv[], void *data)
{
	struct context *context = data;
	uint8_t hwaddr[ETH_ALEN];
	int fd = -1;
	int err;
	int num;

	err = eth_get_hwaddr(context->interface, hwaddr, sizeof(hwaddr));
	if (err < 0)
		return -err;

	num = err;

	if (argc > 1) {
		if (strcmp(argv[1], "-") != 0) {
			fd = open(argv[1], O_CREAT | O_WRONLY);
			if (fd < 0)
				return errno;
		}
	}

	if (fd < 0)
		fd = STDOUT_FILENO;

	err = write(fd, hwaddr, num);
	if (err < 0)
		err = errno;
	else
		err = 0;

	if (fd != STDOUT_FILENO)
		close(fd);

	return err;
}

DEFINE_COMMAND(dump, "dump [filename]",
		"dump MAC address to file",
		NULL, dump_exec);

/**
 * "serial" command
 */
static int parse_mask(const char *octets, unsigned int *maskp)
{
	unsigned int start = 0;
	unsigned int last = 0;
	unsigned int mask = 0;
	unsigned int i;

	while (*octets) {
		unsigned int octet;
		char *end = NULL;

		if (*octets == '-') {
			start = last ?: 1;
			octets++;
			continue;
		}

		if (*octets == ',') {
			octets++;
			continue;
		}

		octet = strtoul(octets, &end, 10);
		if (end == octets)
			return -EINVAL;

		if ((octet == 0) || (octet > 6))
			return -EINVAL;

		if (start) {
			for (i = start; i <= octet; i++)
				mask |= 1 << i;

			start = 0;
			octet = 0;
		} else {
			if (last)
				mask |= 1 << last;
		}

		octets = end;
		last = octet;
	}

	if (start) {
		for (i = start; i <= 6; i++)
			mask |= 1 << i;
	} else {
		if (last)
			mask |= 1 << last;
	}

	if (maskp)
		*maskp = mask;

	return 0;
}

static int serial_exec(int argc, char *argv[], void *data)
{
	unsigned int mask = BIT(5) | BIT(6);
	struct context *context = data;
	uint8_t hwaddr[ETH_ALEN];
	unsigned int bits = 0;
	uint64_t serial = 0;
	uint64_t max = 0;
	unsigned int i;
	int err;

	err = eth_get_hwaddr(context->interface, hwaddr, sizeof(hwaddr));
	if (err < 0)
		return -err;

	if (argc > 1) {
		err = parse_mask(argv[1], &mask);
		if (err < 0) {
			fprintf(stderr, "parse_mask(): %s\n", strerror(-err));
			return 1;
		}
	}

	for (i = 0; i < ETH_ALEN; i++) {
		if (mask & (1 << (i + 1))) {
			serial = (serial << 8) | hwaddr[i];
			bits += 8;
		}
	}

	max = (1 << bits) - 1;
	i = 0;

	while (max) {
		max /= 10;
		i++;
	}

	printf("%0*" FMT_UINT64 "\n", i, serial);
	return 0;
}

DEFINE_COMMAND(serial, "serial [format]",
		"generate serial number from MAC address",
		NULL, serial_exec);

/**
 * "show" command
 */
static int show_exec(int argc, char *argv[], void *data)
{
	struct context *context = data;
	uint8_t hwaddr[ETH_ALEN];
	int err;

	err = eth_get_hwaddr(context->interface, hwaddr, sizeof(hwaddr));
	if (err < 0)
		return -err;

	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", hwaddr[0], hwaddr[1],
			hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);

	return 0;
}

DEFINE_COMMAND(show, "show", "show MAC address", NULL, show_exec);

static const char help_summary[] = ""
	"usage: %s [options] [command]\n"
	"\n"
	"Perform miscellaneous operations on the MAC address of a given\n"
	"network interface.\n"
	"\n";

static const char help_options[] = ""
	"Options:\n"
	"    -h, --help                   show this help screen\n"
	"    -i, --interface INTERFACE    network interface to use\n";

static void usage(FILE *fp, const char *program)
{
	const struct command *command;
	int maxlen = 0;

	fprintf(fp, help_summary, program);
	fprintf(fp, "%s\n", help_options);

	fprintf(fp, "Commands:\n");

	foreach_command(command) {
		int len = strlen(command->synopsis);
		if (len > maxlen)
			maxlen = len;
	}

	foreach_command(command) {
		fprintf(fp, "    %-*s    %s\n", maxlen, command->synopsis,
				command->summary);
	}

	fprintf(stderr, "\n");
}

int main(int argc, char *argv[])
{
	static const struct option options[] = {
		{ "help", 0, NULL, 'h' },
		{ "interface", 1, NULL, 'i' },
		{ NULL, 0, NULL, 0 }
	};
	struct context context;
	int opt;

	memset(&context, 0, sizeof(context));
	context.interface = DEFAULT_INTERFACE;
	context.help = 0;

	while ((opt = getopt_long(argc, argv, "hi:", options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			context.help = 1;
			break;

		case 'i':
			context.interface = optarg;
			break;

		default:
			usage(stderr, argv[0]);
			return 1;
		}
	}

	if (context.help) {
		usage(stdout, argv[0]);
		return 0;
	}

	if (optind >= argc) {
		usage(stderr, argv[0]);
		return 1;
	}

	return exec_command(argc - optind, &argv[optind], &context);
}
