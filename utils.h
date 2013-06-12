/**
 * Copyright (C) 2011 Avionic Design GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef UTILS_H
#define UTILS_H 1

#include <stdio.h>

#ifndef min
#  define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef ARRAY_SIZE
#  define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef DIV_ROUND_UP
#  define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#endif

extern void adak_program_version(FILE *fp, const char *program);

#endif /* UTILS_H */
