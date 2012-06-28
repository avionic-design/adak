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
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "i2c.h"

int i2c_open(const char *device, uint8_t slave)
{
	int err;
	int fd;

	if (!device || (slave > 0x7f))
		return -EINVAL;

	fd = open(device, O_RDWR);
	if (fd < 0)
		return -errno;

	err = ioctl(fd, I2C_SLAVE, slave);
	if (err < 0) {
		err = -errno;
		close(fd);
		return err;
	}

	return fd;
}

int i2c_close(int fd)
{
	int err;

	if (fd < 0)
		return -EINVAL;

	err = close(fd);
	if (err < 0)
		return -errno;

	return 0;
}

int i2c_smbus_access(int fd, uint8_t read_write, uint8_t command,
		uint8_t size, union i2c_smbus_data *data)
{
	struct i2c_smbus_ioctl_data args;
	int err;

	args.read_write = read_write;
	args.command = command;
	args.size = size;
	args.data = data;

	err = ioctl(fd, I2C_SMBUS, &args);
	if (err < 0)
		err = -errno;

	return err;
}

int i2c_smbus_read_byte_data(int fd, uint8_t command)
{
	uint8_t size = I2C_SMBUS_BYTE_DATA;
	union i2c_smbus_data data;
	int err;

	err = i2c_smbus_access(fd, I2C_SMBUS_READ, command, size, &data);
	if (err < 0)
		return err;

	return data.byte & 0xff;
}

int i2c_smbus_write_byte_data(int fd, uint8_t command, uint8_t value)
{
	uint8_t size = I2C_SMBUS_BYTE_DATA;
	union i2c_smbus_data data;

	data.byte = value;

	return i2c_smbus_access(fd, I2C_SMBUS_WRITE, command, size, &data);
}

int i2c_smbus_read_i2c_block_data(int fd, uint8_t command, uint8_t length,
		uint8_t *values)
{
	uint8_t size = I2C_SMBUS_I2C_BLOCK_DATA;
	union i2c_smbus_data data;
	int err;

	if (length > I2C_SMBUS_BLOCK_MAX)
		length = I2C_SMBUS_BLOCK_MAX;

	data.block[0] = length;

	err = i2c_smbus_access(fd, I2C_SMBUS_READ, command, size, &data);
	if (err < 0)
		return err;

	memcpy(values, &data.block[1], data.block[0]);

	return data.block[0];
}

int i2c_smbus_write_i2c_block_data(int fd, uint8_t command, uint8_t length,
		const uint8_t *values)
{
	uint8_t size = I2C_SMBUS_I2C_BLOCK_DATA;
	union i2c_smbus_data data;

	if (length > I2C_SMBUS_BLOCK_MAX)
		length = I2C_SMBUS_BLOCK_MAX;

	data.block[0] = length;
	memcpy(&data.block[1], values, length);

	return i2c_smbus_access(fd, I2C_SMBUS_WRITE, command, size, &data);
}

int i2c_transfer(int fd, struct i2c_msg *msgs, int num)
{
	struct i2c_rdwr_ioctl_data transfer;

	transfer.msgs = msgs;
	transfer.nmsgs = num;

	return ioctl(fd, I2C_RDWR, &transfer);
}
