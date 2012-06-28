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

#include <ctype.h>
#include <stdint.h>

#include "hexdump.h"

int print_hex_dump(FILE *fp, const void *buffer, size_t size, size_t cols, bool ascii)
{
	const uint8_t *ptr = buffer;
	size_t i, j;

	for (j = 0; j < size; j += cols) {
		for (i = 0; (i < cols) && ((j + i) < size); i++)
			fprintf(fp, " %02x", ptr[j + i]);

		for (i = i; i < cols; i++)
			fprintf(fp, "   ");

		if (ascii) {
			fprintf(fp, " | ");

			for (i = 0; (i < cols) && ((j + i) < size); i++) {
				if (isprint(ptr[j + i]))
					fprintf(fp, "%c", ptr[j + i]);
				else
					fprintf(fp, ".");
			}
		}

		fprintf(fp, "\n");
	}

	return 0;
}
