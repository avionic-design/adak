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

#include <libgen.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

void adak_program_version(FILE *fp, const char *program)
{
	char *copy = strdup(program);
	fprintf(fp, "%s " VERSION "\n", basename(copy));
	free(copy);
}
