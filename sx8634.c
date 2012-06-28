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

#include <stdbool.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blkdev.h"
#include "hexdump.h"
#include "i2c.h"
#include "utils.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define SPM_BLOCK_SIZE 8
#define SPM_SIZE 128

#define I2C_SPM_STAT 0x08

#define I2C_SPM_CFG 0x0d
#define I2C_SPM_CFG_WRITE (0 << 3)
#define I2C_SPM_CFG_READ (1 << 3)
#define I2C_SPM_CFG_OFF (0 << 4)
#define I2C_SPM_CFG_ON (1 << 4)
#define I2C_SPM_BASE 0x0e

#define I2C_KEY_MSB 0xac
#define I2C_KEY_LSB 0xad
#define I2C_SOFT_RESET 0xb1

struct spm {
	int fd;
};

ssize_t spm_write(struct blkdev *dev, loff_t offset, const void *buffer, size_t size)
{
	uint8_t enable = I2C_SPM_CFG_ON | I2C_SPM_CFG_WRITE;
	struct spm *spm = blkdev_priv(dev);
	ssize_t err = 0;

	err = i2c_smbus_write_byte_data(spm->fd, I2C_SPM_CFG, enable);
	if (err < 0)
		return err;

	err = i2c_smbus_write_byte_data(spm->fd, I2C_SPM_BASE, offset);
	if (err < 0)
		return err;

	err = i2c_smbus_write_i2c_block_data(spm->fd, 0, size, buffer);
	if (err < 0)
		return err;

	err = i2c_smbus_write_byte_data(spm->fd, I2C_SPM_CFG, I2C_SPM_CFG_OFF);
	if (err < 0)
		return err;

	return err;
}

ssize_t spm_read(struct blkdev *dev, loff_t offset, void *buffer, size_t size)
{
	uint8_t enable = I2C_SPM_CFG_ON | I2C_SPM_CFG_READ;
	struct spm *spm = blkdev_priv(dev);
	ssize_t err = 0;

	err = i2c_smbus_write_byte_data(spm->fd, I2C_SPM_CFG, enable);
	if (err < 0)
		return err;

	err = i2c_smbus_write_byte_data(spm->fd, I2C_SPM_BASE, offset);
	if (err < 0)
		return err;

	err = i2c_smbus_read_i2c_block_data(spm->fd, 0, size, buffer);
	if (err < 0)
		return err;

	err = i2c_smbus_write_byte_data(spm->fd, I2C_SPM_CFG, I2C_SPM_CFG_OFF);
	if (err < 0)
		return err;

	return err;
}

void spm_free(struct blkdev *dev)
{
}

static struct blkdev_ops spm_ops = {
	.write = spm_write,
	.read = spm_read,
	.free = spm_free,
};

static int spm_create(struct blkdev **devp, int fd)
{
	struct blkdev *dev;
	struct spm *spm;
	int err;

	err = blkdev_create(&dev, sizeof(*spm));
	if (err < 0)
		return err;

	dev->block_size = SPM_BLOCK_SIZE;
	dev->size = SPM_SIZE;
	dev->ops = &spm_ops;

	spm = blkdev_priv(dev);
	spm->fd = fd;

	*devp = dev;
	return 0;
}

struct cli {
	struct blkdev *spm;
	int fd;
};

struct command {
	const char *name;
	int (*exec)(struct cli *cli, int argc, char *argv[]);
};

static int exec_dump(struct cli *cli, int argc, char *argv[])
{
	uint8_t data[SPM_SIZE];
	int err;

	err = blkdev_read(cli->spm, data, sizeof(data));
	if (err < 0)
		return err;

	print_hex_dump(stdout, data, sizeof(data), SPM_BLOCK_SIZE, true);

	return 0;
}

static int exec_status(struct cli *cli, int argc, char *argv[])
{
	int err;

	err = i2c_smbus_read_byte_data(cli->fd, I2C_SPM_STAT);
	if (err < 0)
		return err;

	if ((err & 0x8) == 0x8)
		printf("SPM: NVM (written %d times)\n", err & 0x7);
	else
		printf("SPM: QSM\n");

	return 0;
}

static int exec_set_slave(struct cli *cli, int argc, char *argv[])
{
	char *end = NULL;
	uint8_t slave;
	ssize_t err;

	slave = strtoul(argv[1], &end, 0);
	if (end == argv[1])
		return -EINVAL;

	err = blkdev_seek(cli->spm, 4, SEEK_SET);
	if (err < 0)
		return err;

	err = blkdev_write(cli->spm, &slave, sizeof(slave));
	if (err < 0)
		return err;

	return 0;
}

static int exec_reset(struct cli *cli, int argc, char *argv[])
{
	int err;

	err = i2c_smbus_write_byte_data(cli->fd, I2C_SOFT_RESET, 0xde);
	if (err < 0)
		return err;

	err = i2c_smbus_write_byte_data(cli->fd, I2C_SOFT_RESET, 0x00);
	if (err < 0)
		return err;

	return 0;
}

static int exec_burn(struct cli *cli, int argc, char *argv[])
{
	int err;

	err = i2c_smbus_write_byte_data(cli->fd, I2C_KEY_MSB, 0x62);
	if (err < 0)
		return err;

	err = i2c_smbus_write_byte_data(cli->fd, I2C_KEY_LSB, 0x9d);
	if (err < 0)
		return err;

	err = i2c_smbus_write_byte_data(cli->fd, I2C_SPM_BASE, 0xa5);
	if (err < 0)
		return err;

	err = i2c_smbus_write_byte_data(cli->fd, I2C_SPM_BASE, 0x5a);
	if (err < 0)
		return err;

	return 0;
}

static struct command commands[] = {
	{ "dump", exec_dump },
	{ "status", exec_status },
	{ "set-slave", exec_set_slave },
	{ "reset", exec_reset },
	{ "burn", exec_burn },
};

static void usage(FILE *fp, const char *program)
{
	fprintf(fp, "usage: %s [options] command\n", program);
}

struct cli_opts {
	const char *bus;
	uint8_t slave;
	bool version;
	bool help;
	int verbose;
};

static int parse_command_line(struct cli_opts *opts, int argc, char *argv[])
{
	static struct option options[] = {
		{ "bus", 1, NULL, 'b' },
		{ "help", 0, NULL, 'h' },
		{ "slave", 1, NULL, 's' },
		{ "verbose", 0, NULL, 'v' },
		{ "version", 0, NULL, 'V' },
		{ NULL, 0, NULL, 0 },
	};
	int opt;

	memset(opts, 0, sizeof(*opts));
	opts->bus = "/dev/i2c-0";
	opts->slave = 0x2b;

	while ((opt = getopt_long(argc, argv, "b:hs:V", options, NULL)) != -1) {
		switch (opt) {
		case 'b':
			opts->bus = optarg;
			break;

		case 'h':
			opts->help = true;
			break;

		case 's':
			opts->slave = strtoul(optarg, NULL, 0);
			break;

		case 'v':
			opts->verbose++;
			break;

		case 'V':
			opts->version = true;
			break;

		default:
			return -EINVAL;
		}
	}

	return optind;
}

int main(int argc, char *argv[])
{
	struct cli_opts opts;
	struct cli cli;
	unsigned int i;
	ssize_t err;
	int cmd;

	err = parse_command_line(&opts, argc, argv);
	if (err < 0 || err >= argc) {
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

	cmd = err;

	if (opts.verbose) {
		printf("bus: %s\n", opts.bus);
		printf("slave: %02x\n", opts.slave);
	}

	err = i2c_open(opts.bus, opts.slave);
	if (err < 0) {
		fprintf(stderr, "i2c_open(): %s\n", strerror(-err));
		return 1;
	}

	cli.fd = err;

	err = spm_create(&cli.spm, cli.fd);
	if (err < 0) {
		i2c_close(cli.fd);
		return 1;
	}

	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[cmd], commands[i].name) == 0) {
			err = commands[i].exec(&cli, argc - cmd, &argv[cmd]);
			if (err < 0) {
				fprintf(stderr, "%s: %s\n", argv[cmd],
						strerror(-err));
				err = 1;
			} else {
				err = 0;
			}

			break;
		}
	}

	if (i == ARRAY_SIZE(commands)) {
		fprintf(stderr, "%s: command not found\n", argv[cmd]);
		err = 1;
	}

	blkdev_free(cli.spm);
	i2c_close(cli.fd);
	return err;
}
