/**
 * Copyright (C) 2012 Avionic Design GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef ADAK_I2C_H
#define ADAK_I2C_H

#include <errno.h>
#include <stdint.h>

#include <sys/ioctl.h>

#include <linux/i2c.h>
#include <linux/i2c-dev.h>

int i2c_open(const char *device, uint8_t slave);
int i2c_close(int fd);

int i2c_transfer(int fd, struct i2c_msg *msgs, int num);
int i2c_smbus_access(int fd, uint8_t read_write, uint8_t command,
		uint8_t size, union i2c_smbus_data *data);
int i2c_smbus_read_byte_data(int fd, uint8_t command);
int i2c_smbus_write_byte_data(int fd, uint8_t command, uint8_t value);
int i2c_smbus_read_i2c_block_data(int fd, uint8_t command, uint8_t length,
		uint8_t *values);
int i2c_smbus_write_i2c_block_data(int fd, uint8_t command, uint8_t length,
		const uint8_t *values);

#endif /* ADAK_I2C_H */
