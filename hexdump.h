/**
 * Copyright (C) 2012 Avionic Design GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef ADAK_HEXDUMP_H
#define ADAK_HEXDUMP_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

int print_hex_dump(FILE *fp, const void *buffer, size_t size, size_t cols, bool ascii);

#endif /* ADAK_HEXDUMP_H */
