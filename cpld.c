/*
 * Copyright (C) 2012 Avionic Design GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * TODO:  - implement supporting other CPLDs (cfg flash size)
 *        - implement reading/writing UFM
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <ctype.h>
#include <endian.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "i2c.h"
#include "utils.h"


#ifndef ARRAY_SIZE
	#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef DIV_ROUND_UP
	#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#endif


#define debug_print(p2cli, fmt, arg...)		\
	{										\
		if (p2cli->verbose > 2)	\
			printf(fmt, ##arg);				\
	}

#define warn_print(p2cli, fmt, arg...)		\
	{										\
		if (p2cli->verbose > 1)	\
			printf(fmt, ##arg);				\
	}

#define error_print(p2cli, fmt, arg...)		\
	{										\
		if (p2cli->verbose > 0)	\
			printf(fmt, ##arg);				\
	}

#define info_print(p2cli, fmt, arg...)		\
	{										\
		if (p2cli->verbose > 0)	\
			printf(fmt, ##arg);				\
	}

/* 16 bytes per config page */
#define CPLD_CFG_PAGE_SIZE				16
/* Configuration flash memory size for MachXO2-1200/640U ONLY */
#define CPLD_CFG_FLASH_SIZE				(2175*16)
/* User flash memory size for MachXO2-1200/640U ONLY */
#define CPLD_UFM_SIZE					(512*16)
/* Calculate number of pages to be read out of flash memory */
#define CPLD_BYTES_TO_PAGES_MSB(X)		\
		((uint8_t) ((DIV_ROUND_UP(X, CPLD_CFG_PAGE_SIZE) >> 8) & 0x3F))
#define CPLD_BYTES_TO_PAGES_LSB(X)		 \
		((uint8_t) (DIV_ROUND_UP(X, CPLD_CFG_PAGE_SIZE) & 0xFF))
/* 4 dummy bytes are read on each transfer */
#define CPLD_NUM_DUMMY_BYTES			4
/* i2c-dev.c tells 8192 bytes but single page transfers are easier to handle
 * in the CPLD */
#define CPLD_MAX_BYTES_PER_TRANSFER		\
		(CPLD_CFG_PAGE_SIZE + CPLD_NUM_DUMMY_BYTES)

struct jedec_file {
	uint32_t fuse_count;
	uint32_t num_pages;
	uint8_t pages[CPLD_CFG_FLASH_SIZE/CPLD_CFG_PAGE_SIZE][CPLD_CFG_PAGE_SIZE];
	uint32_t usercode;
	uint64_t feature_row;
	uint16_t fea_bits;
	unsigned file_valid        : 1;
	unsigned fuse_count_valid  : 1;
	unsigned usercode_valid    : 1;
	unsigned feature_row_valid : 1;
	unsigned fea_bits_valid    : 1;
};

#define CPLD_WRITE_FMT_HEX				0x0
#define CPLD_WRITE_FMT_BINARY			0x1
struct cli {
	const char *bus;
	uint8_t slave;
	bool version;
	bool help;
	bool write_feature_row;
	bool write_usercode;
	bool verify;
	int verbose;
	int write_format;
	char *input_file;
	char *output_file;
	int fd;
	int num_rows;
	struct jedec_file jedec_file;
};

/* Following commands and information concerning MachXO2 CPLDs
 * are taken from...
 * 
 * 1) 'Lattice MachXO2 Programming and Configuration Usage Guide',
 *     TN1204, Sept. 2012
 * 
 * 2) 'Using User Flash Memory and Hardened Control Functions in
 *     MachXO2 Devices Reference Guide', TN1246, August 2012.
 *
 * The comment field 'EN required' means that the cfg interface has
 * to be enabled prior to using the command.
 */

static struct cpld_device {
	uint32_t devid;
	char *name;
	uint32_t sz_cfg_flash;
	uint32_t sz_ufm;
} cpld_devlist[] = {
	{
		0x012B0043, "256",
		(575*CPLD_CFG_PAGE_SIZE), (0*CPLD_CFG_PAGE_SIZE),
	},{
		0x012B1043, "640",
		(1151*CPLD_CFG_PAGE_SIZE), (192*CPLD_CFG_PAGE_SIZE),
	},{
		0x012B2043, "1200/640U",
		(2175*CPLD_CFG_PAGE_SIZE), (512*CPLD_CFG_PAGE_SIZE),
	},{
		0x012B3043, "2000/1200U",
		(3198*CPLD_CFG_PAGE_SIZE), (640*CPLD_CFG_PAGE_SIZE),
	},{
		0x012B4043, "4000/2000U",
		(5758*CPLD_CFG_PAGE_SIZE), (768*CPLD_CFG_PAGE_SIZE),
	},{
		0x012B5043, "7000",
		(9212*CPLD_CFG_PAGE_SIZE), (2048*CPLD_CFG_PAGE_SIZE),
	},
};
#define CPLD_DEVID_HC_DEVICE_BIT			0x00008000

static struct cpld_device *find_cpld_dev_by_id(uint32_t devid) {
	int i;

	/* Remove 'HC device' bit for comparison */
	devid &= ~CPLD_DEVID_HC_DEVICE_BIT;

	for (i = 0; i < ARRAY_SIZE(cpld_devlist); i += 1)
		if (devid == cpld_devlist[i].devid)
			return &cpld_devlist[i];

	return NULL;
}

static int cpld_i2c_read(int fd, uint8_t slave,
						 uint8_t *cmd_buf, uint16_t cmd_len,
						 uint8_t *dat_buf, uint16_t dat_len)
{
	int err;

	struct i2c_msg msgs[2] = {
		{
			.addr  = slave,
			.flags = 0,
			.len   = cmd_len,
			.buf   = cmd_buf,
		},
		{
			.addr  = slave,
			.flags = I2C_M_RD,
			.len   = dat_len,
			.buf   = dat_buf,
		},
	};

	err = i2c_transfer(fd, msgs, ARRAY_SIZE(msgs));
	return err < 0 ? err : 0;
}

static int cpld_i2c_write(int fd, uint8_t slave,
						 uint8_t *cmd_buf, uint16_t cmd_len,
						 uint8_t *dat_buf, uint16_t dat_len)
{
	int err, msg_cnt = 2;

	struct i2c_msg msgs[2] = {
		{
			.addr  = slave,
			.flags = 0,
			.len   = cmd_len,
			.buf   = cmd_buf,
		},
		{
			.addr  = slave,
			.flags = 0,
			.len   = dat_len,
			.buf   = dat_buf,
		},
	};

	if (dat_buf == NULL || dat_len == 0)
		msg_cnt = 1;

	err = i2c_transfer(fd, msgs, msg_cnt);
	return err < 0 ? err : 0;
}

#define CPLD_BUSY_FLAG		0x80
static int cpld_read_busy_flag(int fd, uint8_t slave, uint8_t *flag)
{
	uint8_t cmd_buf[] = {0xF0, 0x00, 0x00, 0x00};

	return cpld_i2c_read(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf),
						 flag, sizeof(*flag));
}

static int cpld_busy_wait(int fd, uint8_t slave, useconds_t usec)
{
	int ret;
	uint8_t flag;

	if (usec)
		return usleep(usec);

	do {
		ret = cpld_read_busy_flag(fd, slave, &flag);
	} while ((ret == 0) && (flag & CPLD_BUSY_FLAG));

	return ret;
}

#define CPLD_STATUS_DONE		(1 <<  8)
#define CPLD_STATUS_BUSY		(1 << 12)
#define CPLD_STATUS_FAIL		(1 << 13)
#define CPLD_STATUS_VERIFY		(1 << 27)
#define CPLD_STATUS_CFG_CHECK	((1 << 25) | (1 << 24) | (1 << 23))
static int cpld_read_status_reg(int fd, uint8_t slave, uint32_t *status)
{
	uint8_t cmd_buf[] = {0x3C, 0x00, 0x00, 0x00};
	int ret = cpld_i2c_read(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf),
							(uint8_t *) status, sizeof(*status));
	if (ret)
		return ret;

	*status = be32toh(*status);

	return 0;
}

static int cpld_check_status_failed(int fd, uint8_t slave, useconds_t usec)
{
	uint32_t status;
	int ret = cpld_busy_wait(fd, slave, usec);

	if (ret)
		return ret;

	ret = cpld_read_status_reg(fd, slave, &status);
	if (ret)
		return ret;

	return (status & CPLD_STATUS_FAIL) ? -EAGAIN : 0;
}

static int cpld_read_devid(int fd, uint8_t slave, uint32_t *devid)
{
	uint8_t cmd_buf[] = {0xE0, 0x00, 0x00, 0x00};
	int ret = cpld_i2c_read(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf),
							(uint8_t *) devid, sizeof(*devid));
	if (ret)
		return ret;

	*devid = be32toh(*devid);

	return 0;
}

#define CPLD_TRACE_ID_USER_POS		56
#define CPLD_TRACE_ID_POS			0
#define CPLD_TRACE_ID_USER_MASK		(0xFF << CPLD_TRACE_ID_USER_POS)
#define CPLD_TRACE_ID_MASK			(0xFFFFFFFFFFFFFF << CPLD_TRACE_ID_POS)
static int cpld_read_traceid(int fd, uint8_t slave, uint64_t *traceid)
{
	uint8_t cmd_buf[] = {0x19, 0x00, 0x00, 0x00};
	int ret = cpld_i2c_read(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf),
							(uint8_t *) traceid, sizeof(*traceid));
	if (ret)
		return ret;

	*traceid = be32toh(*traceid);

	return 0;
}

/* Transparent mode -> user logic remains working */
static int cpld_enable_cfg_if_transparent(int fd, uint8_t slave)
{
	uint8_t cmd_buf[] = {0x74, 0x08, 0x00};
	int ret = cpld_i2c_write(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf), NULL, 0);

	return ret ? ret : cpld_check_status_failed(fd, slave, 0);
}

/* Offline mode -> user logic stops */
static int cpld_enable_cfg_if_offline(int fd, uint8_t slave)
{
	uint8_t cmd_buf[] = {0xC6, 0x08, 0x00};
	int ret = cpld_i2c_write(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf), NULL, 0);

	return ret ? ret : cpld_busy_wait(fd, slave, 0);
}

#define CPLD_ERASE_SRAM				0x01
#define CPLD_ERASE_FEATURE_ROW		0x02
#define CPLD_ERASE_CONFIG_FLASH		0x04
#define CPLD_ERASE_UFM				0x08
#define CPLE_ERASE_MASK								\
		(CPLD_ERASE_SRAM | CPLD_ERASE_FEATURE_ROW |	\
		CPLD_ERASE_CONFIG_FLASH | CPLD_ERASE_UFM)
/* EN required */
static int cpld_erase(int fd, uint8_t slave, uint8_t mode)
{
	uint8_t cmd_buf[] = {0x0E, mode & CPLE_ERASE_MASK, 0x00, 0x00};
	int ret = cpld_i2c_write(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf),
						 NULL, 0);

	return ret ? ret : cpld_check_status_failed(fd, slave, 0);
}

/* EN required */
static int cpld_erase_ufm(int fd, uint8_t slave)
{
	uint8_t cmd_buf[] = {0xCB, 0x00, 0x00, 0x00};
	int ret = cpld_i2c_write(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf),
							 NULL, 0);

	return ret ? ret : cpld_busy_wait(fd, slave, 0);
}

/* EN required */
static int cpld_reset_cfg_flash_address(int fd, uint8_t slave)
{
	uint8_t cmd_buf[] = {0x46, 0x00, 0x00, 0x00};

	return cpld_i2c_write(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf),
						  NULL, 0);
}

/* EN required */
static int cpld_reset_ufm_address(int fd, uint8_t slave)
{
	uint8_t cmd_buf[] = {0x47, 0x00, 0x00, 0x00};

	return cpld_i2c_write(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf),
						  NULL, 0);
}

#define CPLD_MEM_CFG_FLASH				0x00
#define CPLD_MEM_UFM					0x40
#define CPLD_MEM_MASK					(CPLD_MEM_CFG_FLASH | CPLD_MEM_UFM)

#define CPLD_PAGE_ADDR_MSBYTE(X)		(((X) >> 8) & 0x3F)
#define CPLD_PAGE_ADDR_LSBYTE(X)		((X)& 0xFF)
/* EN required */
static int cpld_set_flash_address(int fd, uint8_t slave, uint8_t mem,
								  uint16_t addr)
{
	uint8_t cmd_buf[] = {0xB4, 0x00, 0x00, 0x00};
	uint8_t data[] = {
		mem & CPLD_MEM_MASK, 0x00,
		CPLD_PAGE_ADDR_MSBYTE(addr),
		CPLD_PAGE_ADDR_LSBYTE(addr),
	};

	return cpld_i2c_write(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf),
						  data, ARRAY_SIZE(data));
}

/* EN required */
static int cpld_program_page(int fd, uint8_t slave, uint8_t *page)
{
	uint8_t cmd_buf[] = {0x70, 0x00, 0x00, 0x01};
	int ret = cpld_i2c_write(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf),
							 page, CPLD_CFG_PAGE_SIZE);

	return ret ? ret : cpld_busy_wait(fd, slave, 0);
}

/* EN required */
static int cpld_program_usercode(int fd, uint8_t slave, uint32_t usercode)
{
	uint8_t cmd_buf[] = {0xC2, 0x00, 0x00, 0x00};
	int ret;

	usercode = htobe32(usercode);

	ret = cpld_i2c_write(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf),
						 (uint8_t *) &usercode, sizeof(usercode));

	return ret ? ret : cpld_check_status_failed(fd, slave, 0);
}

/* EN -> '0': read out of CFG sector, '1': read out of SRAM */
static int cpld_read_usercode(int fd, uint8_t slave, uint32_t *usercode)
{
	uint8_t cmd_buf[] = {0xC0, 0x00, 0x00, 0x00};
	int ret = cpld_i2c_read(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf),
							(uint8_t *) usercode, sizeof(*usercode));
	if (ret)
		return ret;

	*usercode = be32toh(*usercode);

	return 0;
}

struct cpld_feature_row {
	uint32_t custom_id_code;
	uint8_t trace_id;
	uint8_t i2c_slave_addr;
	uint16_t reserved;
} __attribute__((packed));

#define CPLD_FROW_I2C_SLAVE_ADDR_MASK		0x0000FF0000000000
#define CPLD_FROW_TRACE_ID_MASK				0x000000FF00000000
#define CPLD_FROW_CUSTOM_ID_MASK			0x00000000FFFFFFFF
/* EN required */
static int cpld_write_feature_row(int fd, uint8_t slave, uint64_t feature_row)
{
	uint8_t cmd_buf[] = {0xE4, 0x00, 0x00, 0x00};
	int ret;

	feature_row = htobe64(feature_row);
	ret = cpld_i2c_write(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf),
						 (uint8_t *) &feature_row, sizeof(feature_row));

	return ret ? ret : cpld_check_status_failed(fd, slave, 0);
}

/* EN required */
static int cpld_read_feature_row(int fd, uint8_t slave, uint64_t *feature_row)
{
	uint8_t cmd_buf[] = {0xE7, 0x00, 0x00, 0x00};
	int ret = cpld_i2c_read(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf),
							(uint8_t *) feature_row, sizeof(*feature_row));
	if (ret)
		return ret;

	*feature_row = be64toh(*feature_row);

	return 0;
}

#define CPLD_FEA_BITS_BOOT_SEQUENCE_MASK		((1 << 13) | (1 << 12))
#define CPLD_FEA_BITS_MASTER_SPI_PORT_PERSIST	(1 << 11)
#define CPLD_FEA_BITS_I2C_PORT_PERSIST			(1 << 10)
#define CPLD_FEA_BITS_SLAVE_SPI_PORT_PERSIST	(1 <<  9)
#define CPLD_FEA_BITS_JTAG_PORT_PERSIST			(1 <<  8)
#define CPLD_FEA_BITS_DONE_PERSIST				(1 <<  7)
#define CPLD_FEA_BITS_INITN_PERSIST				(1 <<  6)
#define CPLD_FEA_BITS_PROGRAMN_PERSIST			(1 <<  5)
#define CPLD_FEA_BITS_MY_ASSP_PERSIST			(1 <<  4)
/* EN required */
static int cpld_write_fea_bits(int fd, uint8_t slave, uint16_t fea_bits)
{
	uint8_t cmd_buf[] = {0xF8, 0x00, 0x00, 0x00};
	int ret;

	fea_bits = htobe16(fea_bits);
	ret = cpld_i2c_write(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf),
						 (uint8_t *) &fea_bits, sizeof(fea_bits));

	return ret ? ret : cpld_check_status_failed(fd, slave, 0);
}

/* EN required */
static int cpld_read_fea_bits(int fd, uint8_t slave, uint16_t *fea_bits)
{
	uint8_t cmd_buf[] = {0xFB, 0x00, 0x00, 0x00};
	int ret = cpld_i2c_read(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf),
							(uint8_t *) fea_bits, sizeof(*fea_bits));
	if (ret)
		return ret;

	*fea_bits = be16toh(*fea_bits);

	return 0;
}

static int cpld_bypass(int fd, uint8_t slave)
{
	uint8_t cmd_buf[] = {0xFF, 0xFF, 0xFF, 0xFF};

	return cpld_i2c_write(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf), NULL, 0);
}

static int cpld_disable_cfg_if(int fd, uint8_t slave)
{
	uint8_t cmd_buf[] = {0x26, 0x00, 0x00};
	int ret = cpld_i2c_write(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf), NULL, 0);

	if (ret)
		return ret;

	ret = cpld_busy_wait(fd, slave, 0);

	return ret ? ret : cpld_bypass(fd, slave);
}

static int cpld_refresh(int fd, uint8_t slave)
{
	uint8_t cmd_buf[] = {0x79, 0x00, 0x00};

	return cpld_i2c_write(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf), NULL, 0);
}

/* EN required */
static int cpld_set_program_done(int fd, uint8_t slave)
{
	uint8_t cmd_buf[] = {0x5E, 0x00, 0x00, 0x00};
	uint32_t status;
	int ret = cpld_i2c_write(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf), NULL, 0);
	if (ret)
		return ret;

	ret = cpld_busy_wait(fd, slave, 0);
	if (ret)
		return ret;

	ret = cpld_read_status_reg(fd, slave, &status);
	if (ret)
		return ret;

	return (status & CPLD_STATUS_DONE) ? 0 : -EAGAIN;
}

/* EN required */
static int cpld_read_cfg_flash_page(int fd, uint8_t slave, uint8_t *dest,
									int size)
{
	int ret;
	uint8_t rbuf[CPLD_MAX_BYTES_PER_TRANSFER];
	uint8_t cmd_buf[] = {0x73, 0x00, 0x00, 0x01};

	ret = cpld_busy_wait(fd, slave, 200);
	if (ret)
		return ret;

	ret = cpld_i2c_read(fd, slave, cmd_buf, ARRAY_SIZE(cmd_buf),
						rbuf, ARRAY_SIZE(rbuf));
	if (ret)
		return ret;

	memcpy(dest, rbuf, min(size, ARRAY_SIZE(rbuf)));

	return 0;
}

 /*!
 *	\brief	Get the length of a ascii-coded bitstream ('0's and '1's).
 *	\param	str The character array containing the bitstream.
 *	\param	max The maximum at which counting will be stopped.
 *	\return	The number of '0's and '1's, a negative errno otherwise.
 *
 * This function counts up the number of consecutive '0's and '1's in the input
 * string. The first invalid character leads to leaving the function. The max
 * parameter can be used as an upper threshold.
 */
static int get_bitstream_length(const char *str, int max)
{
	int i = 0;

	if (str == NULL)
		return -EINVAL;

	while ((str[i] == '0' || str[i] == '1') && (i < max))
		i += 1;

	return i;
}

 /*!
 *	\brief	Parse an ascii-coded bitstream.
 *	\param	src The source array (containing the bitstream).
 *	\param	dest The destination array.
 *	\param	sz_dest The size of the destination array.
 *	\return	The number of parsed bytes, a negative errno otherwise.
 *
 *	Note that this function parses in big endian order only!
 *	Conversion to host is not implemented since the CPLD's
 *	I2C interface expects data in big endian order.
 */
static int parse_ascii_bitstream(const char *src, char *dest, size_t sz_dest)
{
	int bytes, length;

	if (!dest || !src || !sz_dest)
		return -EINVAL;

	length = get_bitstream_length(src, sz_dest*8) / 8;
	if (length <= 0)
		return -EINVAL;

	for (bytes = 0; bytes < length; bytes += 1) {
		int bit;

		*dest = 0;
		for (bit = 0; bit < 8; bit += 1) {
			if (*src == '1')
				*dest |= (128 >> bit);
			src += 1;
		}
		dest += 1;
	}

	return bytes;
}

 /*!
 *	\brief	Convert a string to an ascii-coded binary string.
 *	\param	src Pointer to the source string.
 *	\param	sz_src The size of the source string.
  *	\param	dest Pointer to the detination string.
 *	\param	sz_dest The size of the destination string.
 *	\return	The number of bytes written, a negative errno otherwise.
 *
 * Note that no no EOL is appended!
 */
static int strntoasciibin(char *src, size_t sz_src, char *dest, size_t sz_dest)
{
	char *dest_ptr = dest;
	size_t size;
	int bytes;

	if (!src || !dest)
		return -EINVAL;

	size = min(sz_src*8, sz_dest) / 8;

	if (size <= 0)
		return -EINVAL;

	for (bytes = 0; bytes < size; bytes += 1) {
		int bit;

		for (bit = 0; bit < 8; bit += 1) {
			*dest_ptr = '0' + !!((128 >> bit) & *src);
			dest_ptr += 1;
		}
		src += 1;
	}

	return dest_ptr - dest;
}

 /*!
 *	\brief	Read the complete config flah mem and write it to a file.
 *	\param	cli Pointer to a client structure.
 *	\param	ofd Output file descriptor, the flash mem is to be written to.
 *	\return	The number of parsed bytes, a negative errno otherwise.
 */
static int read_cfm_to_fd(struct cli *cli, int ofd)
{
	int pages;
	int pages_max = DIV_ROUND_UP(CPLD_CFG_FLASH_SIZE, CPLD_CFG_PAGE_SIZE);
	uint8_t page[CPLD_CFG_PAGE_SIZE];
	uint8_t wbuf[ARRAY_SIZE(page)*8+1];

	debug_print(cli, "Ready for %d I2C messages, reading a total of %d bytes\n",
				pages_max*2, pages_max * CPLD_CFG_PAGE_SIZE);

	for (pages = 0; pages < pages_max; pages += 1) {
		int ret, wr_bytes = 0;

		//TODO: 'step' could cause errors here, if it is not a multiple of 16
		ret = cpld_read_cfg_flash_page(cli->fd, cli->slave,
									   page, CPLD_CFG_PAGE_SIZE);
		if (ret) {
			error_print(cli, "Failed reading page %d/%d\n",
						pages + 1, pages_max);
			return ret;
		}

		/* Write (ascii-coded) binary ('0's and '1's) */
		if (cli->write_format == CPLD_WRITE_FMT_BINARY) {
			wr_bytes = ARRAY_SIZE(page) * 8;
			ret = strntoasciibin((char *) page, ARRAY_SIZE(page),
								 (char *) wbuf, wr_bytes);
			if (ret != wr_bytes) {
				error_print(cli, "Converting to binary string failed: %d/%d\n",
							ret, wr_bytes);
				return -EINVAL;
			}
			wbuf[wr_bytes] = '\n';
			wr_bytes += 1;

		/* Write (ascii-coded) hexadecimal */
		} else {
			int bytes;
			uint8_t *wbuf_ptr = wbuf;

			wr_bytes = 0;
			for (bytes = 0; bytes < ARRAY_SIZE(page); bytes += 1) {
				int step = snprintf((char *) wbuf_ptr, 4, "%.02x ", page[bytes]);
				if (step <= 0) {
					error_print(cli, "Converting to hex string failed\n");
					return -EINVAL;
				}
				wbuf_ptr += step;
				wr_bytes += step;
			}

			/* Replace last blank with a newline */
			wbuf_ptr -= 1;
			*wbuf_ptr = '\n';
		}

		ret = write(ofd, wbuf, wr_bytes);
		if (ret != wr_bytes) {
			int err = -errno;

			error_print(cli, "Write resulted in %d/%d bytes for page %d\n",
						ret, wr_bytes, pages + 1);

			return -err;
		}
	}

	return 0;
}

static int parse_uint32(char *rbuf, uint32_t *dest)
{ 
	errno = 0;
	*dest = strtoul(rbuf, NULL, 10);

	return -errno;
}

 /*!
 *	\brief	Parse the feature row out of a given character array.
 *	\param	cli Pointer to the I2C client structure.
 *	\param	rbuf Pointer to the chracter array containing the feature row.
 *	\return	0 on success, else negative errno.
 * 
 * The feature row will be parsed into the appropriate field of the given
 * pointer cli.
 */
static int parse_feature_row(struct cli *cli, char *rbuf)
{
	uint64_t *f_row = &cli->jedec_file.feature_row;
	int ret;

	if (rbuf[0] == 'H') {
		errno = 0;
		sscanf(&rbuf[1], "%016"PRIX64"*", f_row);

		ret = -errno;
	} else {
		ret = parse_ascii_bitstream(&rbuf[0], (char *) f_row, sizeof(*f_row));
		if (ret == sizeof(*f_row))
			ret = 0;

		*f_row = be64toh(*f_row);
	}

	return ret;
}

 /*!
 *	\brief	Parse the FEA bits out of a given character array.
 *	\param	cli Pointer to the I2C client structure.
 *	\param	rbuf Pointer to the chracter array containing the feature row.
 *	\return	0 on success, else negative errno.
 *
 * The FEA bits will be parsed into the appropriate field of the given
 * pointer cli.
 *
 * NOTE: This function assumes to get passed the complete read line, NOT
 *       SHORTENED like e.g. for parse_feature_row, since it must find out
 *       out whether feature row and fea bits are on the same line or on
 *       separate ones
 */
static int parse_fea_bits(struct cli *cli, char *rbuf, int hex)
{
	uint16_t *fea_bits = &cli->jedec_file.fea_bits;
	int ret = 0;

	if (hex) {
		uint32_t tmp;

		errno = 0;
		sscanf(rbuf, "%04"PRIX16"*", &tmp);
		ret = -errno;

		*fea_bits = (uint16_t) tmp;
	} else {
		ret = parse_ascii_bitstream(rbuf, (char *) fea_bits, sizeof(*fea_bits));
		if (ret == sizeof(*fea_bits)) {
			*fea_bits = be16toh(*fea_bits);
			ret = 0;
		} else {
			ret = ret >= 0 ? -EINVAL : ret;
		}
	}

	return ret;
}

 /*!
 *	\brief	Parse the usercode out of a given character array.
 *	\param	cli Pointer to the I2C client structure.
 *	\param	rbuf Pointer to the chracter array containing the feature row.
 *	\return	0 on success, else negative errno.
 *
 * The usercode will be parsed into the appropriate field of the given
 * pointer cli.
 */
static int parse_usercode(struct cli *cli, char *rbuf)
{
	uint32_t *usercode = &cli->jedec_file.usercode;
	int ret = -EINVAL;

	if (rbuf[0] == 'A') {
		int len = strlen(&rbuf[1]);

		if (len >= sizeof(usercode)) {
			ret = 0;
			memcpy(usercode, &rbuf[1], sizeof(*usercode));
		}
	} else if (rbuf[0] == 'H') {
		errno = 0;
		sscanf(&rbuf[1], "%08"PRIX32"*", usercode);
		ret = -errno;
	} else {
		ret = parse_ascii_bitstream(&rbuf[0], (char *) usercode,
									sizeof(*usercode));
		if (ret == sizeof(*usercode))
			ret = 0;
		else if (ret == 0)
			ret = -ENODATA;

		*usercode = be32toh(*usercode);
	}

	return ret;
}

 /*!
 *	\brief	Verify one page of cfg flash data against the given one.
 *	\param	cli Pointer to the I2C client structure.
 *	\param	page Pointer to the page expected inside the cfg flash.
 *	\return	0 on success, else negative errno.
 *
 * Note that the page pointer is expected to be at least
 * CPLD_CFG_PAGE_SIZE bytes long.
 */
 static int verify_page(struct cli *cli, uint8_t *page)
{
	int ret;
	uint8_t page_verif[CPLD_CFG_PAGE_SIZE];

	ret = cpld_read_cfg_flash_page(cli->fd, cli->slave, page_verif,
								   ARRAY_SIZE(page_verif));
	if (ret) {
		error_print(cli, "%s: failed reading page\n",
					__func__);
		return ret;
	}

	if (memcmp(page, page_verif, ARRAY_SIZE(page_verif))){
		int i;

		error_print(cli, "Verify: page data does not match\n");
		error_print(cli, "written: ");
		for (i = 0; i < ARRAY_SIZE(page_verif); i += 1)
			error_print(cli, "%02X ", page[i]);
		error_print(cli, "\nread   : ");
		for (i = 0; i < ARRAY_SIZE(page_verif); i += 1)
			error_print(cli, "%02X ", page_verif[i]);
		error_print(cli, "\n");

		return -EINVAL;
	}
	return 0;
}

 /*!
 *	\brief	Check if the read line is the last of a block.
 *	\param	rbuf Pointer to the character array holding the read line.
 *	\return	1 if block ends on this line, 0 else.
 *
 * Blocks in a JEDEC file always end with a '*'. Some blocks end on
 * a separate line while some end at the end of a line.
 */
static int line_is_last(char *rbuf) {

	while (*rbuf && *rbuf != '*') {
		rbuf += 1;
	}

	return (*rbuf == '*') ? 1 : 0;
}

 /*!
 *	\brief	Parse known/needed fields of a JEDEC file.
 *	\param	cli Pointer to the I2C client structure.
 *	\param	FILE Pointer to the JEDEC file.
 *	\return	0 on success, negative errno else.
 *
 * This function reads a given JEDEC file line by line and parses the
 * known/needed information fields into the struct jedec_file-field inside
 * the cli structure.
 */
static int parse_jedec_file(struct cli *cli, FILE *fp)
{
	int ret, size, hex = 0;
	char rbuf[256];
	uint8_t *row;
	uint32_t line = 0, row_idx = 0;
	enum jedec_file_position {
		pos_idle,
		pos_cfg_flash_data,
		pos_fea_bits,
	} filepos = pos_idle;
	struct jedec_file *jedec = &cli->jedec_file;

	rewind(fp);
	memset(&cli->jedec_file, 0, sizeof(cli->jedec_file));

	jedec->num_pages = 0;

	while (fgets(rbuf, ARRAY_SIZE(rbuf), fp) != NULL) {
		line += 1;

		switch (filepos) {
		case pos_idle:
			switch (rbuf[0]) {
			case 'Q':
				if (rbuf[1] == 'F') {
					if (jedec->fuse_count_valid) {
						warn_print(cli, "Fuse count already parsed\n");
						break;
					}
					jedec->fuse_count_valid = 1;

					ret = parse_uint32(&rbuf[2], &jedec->fuse_count);
					if (ret) {
						warn_print(cli, "Parsing fuse count failed\n");
						break;
					}
				}
				break;

			case 'L':

				/* This line hinders 'all-zero'-fields from being parsed */
				if (jedec->num_pages > 0) {
					warn_print(cli, "Config flash data already parsed\n");
					break;
				}

				ret = parse_uint32(&rbuf[1], &row_idx);
				if (ret) {
					error_print(cli, "Parsing the row index failed\n");
					return ret;
				}

				row_idx /= 8; /* To bytes */
				row_idx /= CPLD_CFG_PAGE_SIZE; /* To page/row index */

				if (row_idx != jedec->num_pages) {
					error_print(cli, "Internal row index [%u] and parsed one "
								"[%u] do not match\n", jedec->num_pages,
								row_idx);
					return -EINVAL;
				}

				filepos = pos_cfg_flash_data;

				break;

			case 'E': /* Feature row */
				if (jedec->feature_row_valid) {
					warn_print(cli, "Feature row already parsed\n");
					break;
				}
				jedec->feature_row_valid = 1;

				ret = parse_feature_row(cli, &rbuf[1]);
				if (ret) {
					error_print(cli, "Parsing feature row failed\n");
					return ret;
				}
				hex = rbuf[1] == 'H' ? 1 : 0;

				/* If the feature row information ends on one line the FEA
				 * bits are appended (else they're on the next line). */
				if (line_is_last(rbuf)) {
					/* hex == 1: skip 'E' + 'H' + 8 * 2 feature row nibbles */
					/* hex == 0: skip 'E' + 8 * 8 feature row bits */
					int fea_pos = hex ? 1 + 1 + 8 * 2 : 1 + 8 * 8;

					ret = parse_fea_bits(cli, rbuf+fea_pos, hex);
					if (ret) {
						error_print(cli, "Parsing FEA bits failed\n");
						return ret;
					}
					jedec->fea_bits_valid = 1;
				} else {
					filepos = pos_fea_bits;
				}

				break;

			/* Usercode */
			case 'U':

				if (jedec->usercode_valid) {
					warn_print(cli, "Usercode already parsed\n");
					break;
				}
				jedec->usercode_valid = 1;

				ret = parse_usercode(cli, &rbuf[1]);
				if (ret) {
					error_print(cli, "Failed parsing usercode\n");
					return ret;
				}

				break;

			default:
				debug_print(cli, "Skipping line: %s", rbuf);
				break;
			} /* switch (rbuf[0]) */

			break; /* case pos_idle */


		case pos_cfg_flash_data:
			switch(rbuf[0]) {
			case '0':
			case '1':
				row = jedec->pages[jedec->num_pages];
				size = ARRAY_SIZE(jedec->pages[jedec->num_pages]);

				ret = parse_ascii_bitstream(rbuf, (char *) row, size);
				if (ret != size) {
					error_print(cli, "Parsing cfg flash failed on line %u"
									 "of JEDEC file\n", line);
					return ret;
				}
				jedec->num_pages += 1;

				/* Intended conditional break: stop if cfg flash data ends on
				 * this line */
				if (!line_is_last(rbuf))
					break;
			case '*':
				filepos = pos_idle;
				debug_print(cli, "\n%u rows of config flash data parsed.\n",
							jedec->num_pages);
				break;
			default:
				warn_print(cli, "Cfg flash parse: skipping line: %s", rbuf);
				break;
			};
			break;


		case pos_fea_bits:
			filepos = pos_idle;

			if (jedec->fea_bits_valid) {
				warn_print(cli, "FEA bits already written\n");
				break;
			}
			jedec->fea_bits_valid = 1;

			ret = parse_fea_bits(cli, rbuf, hex);
			if (ret) {
				error_print(cli, "Parsing FEA bits failed\n");
				return ret;
			}
			break;


		default:
			filepos = pos_idle;
			error_print(cli, "Unknown state %d\n", (int) filepos);
			break;
		}
	}

	cli->jedec_file.file_valid = 1;
	return 0;
}

static int exec_read(struct cli *cli, int argc, char *argv[])
{
	int ret = -EINVAL, ofd;
	char wbuf[256];
	uint64_t f_row;
	uint32_t usercode, devid;
	uint16_t fea_bits;
	struct cpld_device *cpld;

	info_print(cli, "Dumping CPLD data to file...\n");

	if (cli->output_file == NULL) {
		warn_print(cli, "%s: Output file must be specified for read command\n",
				   __func__);
		goto exec_read_out;
	}

	ofd = open(cli->output_file, O_WRONLY | O_CREAT);
	if (ofd < 0) {
		error_print(cli, "%s: opening output file '%s' failed\n",
					__func__, cli->output_file);
		goto exec_read_out;
	}

	ret = cpld_read_devid(cli->fd, cli->slave, &devid);
	if (ret) {
		error_print(cli, "%s: reading DeviceID failed\n", __func__);
		goto exec_read_end;
	}

	cpld = find_cpld_dev_by_id(devid);
	if (!cpld) {
		error_print(cli, "%s: couldn't match DeviceID [0x%08"PRIX32"]\n",
					__func__, devid);
		goto exec_read_end;
	}

	ret = cpld_read_usercode(cli->fd, cli->slave, &usercode);
	if (ret) {
		error_print(cli, "%s: reading usercode failed\n", __func__);
		goto exec_read_end;
	}

	/* TODO: fix static width, width must match fuse count width */
	ret = snprintf(wbuf, ARRAY_SIZE(wbuf), "QF%u*\nL%06u*\n",
				   (cpld->sz_cfg_flash + cpld->sz_ufm) * 8, 0);
	if (ret > 0) {
		int wr_cnt = write(ofd, wbuf, ret);

		if (wr_cnt != ret) {
			ret = -errno;
			error_print(cli, "%s: writing fuse count and link field failed\n",
						__func__);
			goto exec_read_end;
		}
	}

	ret = cpld_enable_cfg_if_transparent(cli->fd, cli->slave);
	if (ret) {
		error_print(cli, "%s: enabling cfg if (transparent) failed\n",
					__func__);
		goto exec_read_end;
	}

	ret = cpld_set_flash_address(cli->fd, cli->slave,
								 CPLD_MEM_CFG_FLASH, 0);
	if (ret) {
		error_print(cli, "%s: setting flash address failed\n", __func__);
		goto exec_read_end;
	}

	ret = read_cfm_to_fd(cli, ofd);
	if (ret) {
		error_print(cli, "%s: reading CPLD data into memory failed\n", __func__);
		goto exec_read_end;
	}

	ret = cpld_read_feature_row(cli->fd, cli->slave, &f_row);
	if (ret) {
		error_print(cli, "%s: reading feature row failed\n", __func__);
		goto exec_read_end;
	}

	ret = cpld_read_fea_bits(cli->fd, cli->slave, &fea_bits);
	if (ret) {
		error_print(cli, "%s: reading FEA bits failed\n", __func__);
		goto exec_read_end;
	}

	ret = snprintf(wbuf, ARRAY_SIZE(wbuf), "EH%016"PRIX64"\n%04"PRIX16"*\n"
				   "UH%08"PRIX32"*\n", f_row, fea_bits, usercode);
	if (ret > 0) {
		int wr_cnt = write(ofd, wbuf, ret);
		if (wr_cnt != ret)
			error_print(cli, "%s: writing additional info failed\n", __func__);
	}

	ret = cpld_disable_cfg_if(cli->fd, cli->slave);
	if (ret) {
		error_print(cli, "%s: disabling cfg if failed\n", __func__);
	}

exec_read_end:
	close(ofd);

exec_read_out:
	info_print(cli, "Dumping CPLD %s\n", ret ? "failed" : "was successful");
	return ret;
}


static int exec_verify(struct cli *cli, int argc, char *argv[])
{
	int ret, err, i;

	info_print(cli, "Verifying CPLD...\n");

	if (cli->jedec_file.file_valid == 0) {
		error_print(cli, "%s: write must be performed prior to verify\n",
					__func__);
		ret = -ENODATA;
		goto exec_verify_out;
	}

	ret = cpld_enable_cfg_if_transparent(cli->fd, cli->slave);
	if (ret) {
		error_print(cli, "%s: enabling cfg if failed\n", __func__);
		goto exec_verify_out;
	}

	ret = cpld_set_flash_address(cli->fd, cli->slave, CPLD_MEM_CFG_FLASH, 0);
	if (ret) {
		error_print(cli, "%s: setting cfg flash address failed\n", __func__);
		goto exec_verify_end;
	}

	for (i = 0; i < cli->jedec_file.num_pages; i += 1) {
		ret = verify_page(cli, cli->jedec_file.pages[i]);
		if (ret)
			error_print(cli, "%s: verify failed at page %d\n", __func__, i + 1);
		goto exec_verify_end;
	}

exec_verify_end:
	err = cpld_disable_cfg_if(cli->fd, cli->slave);
	if (err) {
		error_print(cli, "%s: disabling cfg if  failed\n", __func__);
		if (!ret)
			ret = err;
	}

exec_verify_out:
	info_print(cli, "Verifying CPLD %s\n", ret ? "failed" : "was successful");
	return ret;
}

static int exec_write(struct cli *cli, int argc, char *argv[])
{
	int ret, err, i;
	FILE *fp;
	uint8_t mem = CPLD_ERASE_CONFIG_FLASH | CPLD_ERASE_UFM;

	info_print(cli, "Writing to CPLD...\n");

	if (cli->input_file == NULL) {
		error_print(cli, "%s: input file must be speciefied for programming "
						 "the device\n", __func__);
		ret = -EINVAL;
		goto exec_write_out;
	}

	fp = fopen(cli->input_file, "r");
	if (fp == NULL) {
		ret = -errno;
		error_print(cli, "%s: opening input file failed '%s'",
					__func__, cli->input_file);
		goto exec_write_out;
	}

	ret = parse_jedec_file(cli, fp);
	if (ret) {
		error_print(cli, "%s: parsing JEDEC file failed\n", __func__);
		goto exec_write_end;
	}

	ret = cpld_enable_cfg_if_transparent(cli->fd, cli->slave);
	if (ret) {
		error_print(cli, "%s: enabling cfg if (transparent) failed\n",
					__func__);
		goto exec_write_end;
	}

	if (cli->write_feature_row)
		mem |= CPLD_ERASE_FEATURE_ROW;

	ret = cpld_erase(cli->fd, cli->slave, mem);
	if (ret) {
		error_print(cli, "%s: erasing the CPLD failed\n",
					__func__);
		goto exec_write_end;
	}

	ret = cpld_set_flash_address(cli->fd, cli->slave, CPLD_MEM_CFG_FLASH, 0);
	if (ret) {
		error_print(cli, "%s: setting cfg flash address failed\n", __func__);
		goto exec_write_end;
	}

	for (i = 0; i < cli->jedec_file.num_pages; i += 1) {
		ret = cpld_program_page(cli->fd, cli->slave, cli->jedec_file.pages[i]);
		if (ret) {
			error_print(cli, "%s: programming page %d failed\n", __func__, i+1);
			goto exec_write_end;
		}
	}

	if (cli->write_usercode) {
		uint32_t uc_verif;

		ret = cpld_program_usercode(cli->fd, cli->slave, cli->jedec_file.usercode);
		if (ret) {
			error_print(cli, "%s: writing usercode failed\n", __func__);
			goto exec_write_cleanup;
		}

		ret = cpld_read_usercode(cli->fd, cli->slave, &uc_verif);
		if (ret) {
			error_print(cli, "%s: (verify) reading usercode failed\n",
						__func__);
			goto exec_write_cleanup;
		}

		if (cli->jedec_file.usercode != uc_verif) {
			error_print(cli, "%s: usercode written [%08"PRIX32"] and read"
						" [%08"PRIX32"] do not match\n", __func__,
						cli->jedec_file.usercode, uc_verif);
			goto exec_write_cleanup;
		}
	}

	if (cli->write_feature_row) {
		uint64_t frow_verif;
		uint16_t fea_verif;

		ret = cpld_write_feature_row(cli->fd, cli->slave,
									 cli->jedec_file.feature_row);
		if (ret) {
			error_print(cli, "%s: writing feature row failed\n", __func__);
			goto exec_write_cleanup;
		}

		ret = cpld_read_feature_row(cli->fd, cli->slave, &frow_verif);
		if (ret) {
			error_print(cli, "%s: (verify) reading feature row failed\n",
						__func__);
			goto exec_write_cleanup;
		}

		if (cli->jedec_file.feature_row != frow_verif) {
			error_print(cli, "%s: feature row written [%016"PRIX64"] and read"
						" [%016"PRIX64"] do not match\n", __func__,
						cli->jedec_file.feature_row, frow_verif);
			goto exec_write_cleanup;
		}

		ret = cpld_write_fea_bits(cli->fd, cli->slave, cli->jedec_file.fea_bits);
		if (ret) {
			error_print(cli, "%s: writing FEA bits failed\n", __func__);
			goto exec_write_cleanup;
		}

		ret = cpld_read_fea_bits(cli->fd, cli->slave, &fea_verif);
		if (ret) {
			error_print(cli, "%s: (verify) reading FEA bits failed\n",
						__func__);
			goto exec_write_cleanup;
		}

		if (cli->jedec_file.fea_bits != fea_verif) {
			error_print(cli, "%s: FEA btis written [%04"PRIX16"] and read"
						" [%04"PRIX16"] do not match\n", __func__,
						cli->jedec_file.fea_bits, fea_verif);
			goto exec_write_cleanup;
		}
	}

	ret = cpld_set_program_done(cli->fd, cli->slave);
	if (ret) {
		error_print(cli, "%s: setting program done failed\n", __func__);
		goto exec_write_cleanup;
	}
	goto exec_write_end;

exec_write_cleanup:
	err = cpld_erase(cli->fd, cli->slave, mem);
	if (err)
		error_print(cli, "%s: (cleanup) erasing CPLD failed\n", __func__);

exec_write_end:
	err = cpld_disable_cfg_if(cli->fd, cli->slave);
	if (err) {
		error_print(cli, "%s: disabling cfg if failed\n", __func__);
		if (!ret)
			ret = err;
	}

	fclose(fp);

exec_write_out:
	info_print(cli, "Writing to CPLD %s\n", ret ? "failed" : "was successful");
	return ret ? ret : cli->verify ? exec_verify(cli, argc, argv) : 0;
}

static int exec_devinfo(struct cli *cli, int argc, char *argv[])
{
	int ret, err;
	uint16_t fea_bits;
	uint32_t usercode, devid;
	uint64_t traceid;
	struct cpld_feature_row frow;
	struct cpld_device *cpld;

	info_print(cli, "Reading CPLD info...\n");

	ret = cpld_read_devid(cli->fd, cli->slave, &devid);
	if (ret) {
		error_print(cli, "%s: reading DeviceID failed\n", __func__);
		goto exec_devinfo_out;
	}

	ret = cpld_read_traceid(cli->fd, cli->slave, &traceid);
	if (ret) {
		error_print(cli, "%s: reading TraceID failed\n", __func__);
		goto exec_devinfo_out;
	}

	ret = cpld_read_usercode(cli->fd, cli->slave, &usercode);
	if (ret) {
		error_print(cli, "%s: reading usercode failed\n", __func__);
		goto exec_devinfo_out;
	}

	ret = cpld_enable_cfg_if_transparent(cli->fd, cli->slave);
	if (ret) {
		error_print(cli, "%s: enablind cfg if (transparent) failed\n",
					__func__);
		goto exec_devinfo_out;
	}

	ret = cpld_read_feature_row(cli->fd, cli->slave, (uint64_t *) &frow);
	if (ret) {
		error_print(cli, "%s: reading feature row failed\n", __func__);
		goto exec_devinfo_end;
	}

	ret = cpld_read_fea_bits(cli->fd, cli->slave, &fea_bits);
	if (ret) {
		error_print(cli, "%s: reading FEA bits failed\n", __func__);
		goto exec_devinfo_end;
	}

	printf("Device                : ");
	cpld = find_cpld_dev_by_id(devid);
	if (cpld)
		printf("MachXO2-%s %s\n", cpld->name,
			   devid & CPLD_DEVID_HC_DEVICE_BIT ? "HC" : "HE/ZE");
	else
		printf("unknown [0x%08"PRIX32"]\n", devid);

	printf("TraceID               : 0x%016"PRIX64"\n", traceid);
	printf("Usercode              : 0x%08"PRIX32"\n", usercode);
	printf("Feature row\n");
	printf("    I2C slave address : 0x%02X\n", frow.i2c_slave_addr);
	printf("    TraceID           : 0x%02X\n", frow.trace_id);
	printf("    Custom ID code    : 0x%08"PRIX32"\n", frow.custom_id_code);
	printf("FEA bits              : 0x%04"PRIX16"\n", fea_bits);


exec_devinfo_end:
	err = cpld_disable_cfg_if(cli->fd, cli->slave);
	if (err) {
		error_print(cli, "%s: disabling cfg if failed\n", __func__);
		if (!ret)
			ret = err;
	}

exec_devinfo_out:
	info_print(cli, "Reading CPLD info %s\n", ret ? "failed" : "was successful");
	return ret;
}

struct command {
	const char *name;
	int (*exec)(struct cli *cli, int argc, char *argv[]);
} static commands[] = {
	{ "read", exec_read },
	{ "write", exec_write },
	{ "devinfo", exec_devinfo },
};

static const char help_summary[] = ""
	"Usage: %s [options] command\n"
	"\n"
	"Read/Write from/to MACHXO2 CPLD Flash Memory.\n"
	"\n";

static const char help_options[] = "Options:\n"
	"  -b, --bus           Path to I2C bus the CPLD resides on.\n"
	"  -B, --binary-fmt    Write CPLD's read out cfg flash in binary format.\n"
	"  -f, --feature-row   Write feature row as well (not recommended).\n"
	"  -h, --help          Display help screen and exit.\n"
	"  -i, --input-file    Path to JEDEC input file the CPLD's cfg flash is written from.\n"
	"  -n, --non-verified  Do not verify written CPLD image (not recommended).\n"
	"  -o, --output-file   Path to output file CPLD's cfg flash is written to.\n"
	"  -s, --slave         I2C slave address the CPLD responds to.\n"
	"  -u, --no-usercode   Do not write the USERCODE.\n"
	"  -v, --verbose       Be verbose.\n"
	"  -V, --version       Display program version and exit.\n";

static void usage(FILE *fp, const char *program)
{
	int i;

	fprintf(fp, help_summary, program);
	fputs(help_options, fp);
	fputs("\ncommand\n", fp);

	fprintf(fp, "\t%s", commands[0].name);
	for (i = 1; i < ARRAY_SIZE(commands); i += 1)
		fprintf(fp, " | %s", commands[i].name);

	fputs("\n\n", fp);
}

static int parse_command_line(struct cli *cli, int argc, char *argv[])
{
	static struct option options[] = {
		{ "bus",          1, NULL, 'b' },
		{ "binary-fmt",   0, NULL, 'B' },
		{ "feature-row",  0, NULL, 'f' },
		{ "help",         0, NULL, 'h' },
		{ "input-file",   1, NULL, 'i' },
		{ "non-verified", 0, NULL, 'n' },
		{ "output-file",  1, NULL, 'o' },
		{ "slave",        1, NULL, 's' },
		{ "no-usercode",  0, NULL, 'u' },
		{ "verbose",      0, NULL, 'v' },
		{ "version",      0, NULL, 'V' },
		{ NULL,           0, NULL,  0  },
	};
	int opt;

	memset(cli, 0, sizeof(*cli));
	cli->bus = "/dev/i2c-0";
	cli->slave = 0x40;
	cli->write_feature_row = false;
	cli->write_usercode = true;
	cli->write_format = CPLD_WRITE_FMT_HEX;
	cli->verify = true;

	while ((opt = getopt_long(argc, argv, "b:Bfhi:no:s:uvV", options, NULL)) != -1) {
		switch (opt) {
		case 'b':
			cli->bus = optarg;
			break;

		case 'B':
			cli->write_format = CPLD_WRITE_FMT_BINARY;
			break;

		case 'f':
			cli->write_feature_row = true;
			break;

		case 'h':
			cli->help = true;
			break;

		case 'i':
			cli->input_file = optarg;
			break;

		case 'n':
			cli->verify = false;
			break;

		case 'o':
			cli->output_file = optarg;
			break;

		case 's':
			cli->slave = strtoul(optarg, NULL, 0);
			break;

		case 'u':
			cli->write_usercode = false;
			break;

		case 'v':
			cli->verbose += 1;
			break;

		case 'V':
			cli->version = true;
			break;

		default:
			return -EINVAL;
		}
	}

	return optind;
}

int main(int argc, char *argv[])
{
	struct cli cli;
	ssize_t err;
	int i, cmd;

	err = parse_command_line(&cli, argc, argv);
	if (err < 0 || err >= argc) {
		usage(stderr, argv[0]);
		return 1;
	}

	if (cli.help) {
		usage(stdout, argv[0]);
		return 0;
	}

	if (cli.version) {
		adak_program_version(stdout, argv[0]);
		return 0;
	}

	if (cli.verbose) {
		printf("bus   : %s\n", cli.bus);
		printf("slave : 0x%02x\n", cli.slave);
	}

	cmd = err;

	err = i2c_open(cli.bus, cli.slave);
	if (err < 0) {
		fprintf(stderr, "i2c_open(): %s\n", strerror(-err));
		return 1;
	}

	cli.fd = err;

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

	i2c_close(cli.fd);
	return err;
}
