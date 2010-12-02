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
#include <string.h>

#include "command.h"

const struct command *find_command(const char *name)
{
	const struct command *command;

	foreach_command(command) {
		if (strcmp(command->name, name) == 0)
			return command;
	}

	return 0;
}

int exec_command(int argc, char *argv[], void *data)
{
	const struct command *command;
	int ret = -ENOSYS;

	foreach_command(command) {
		if (strcmp(argv[0], command->name) == 0) {
			if (command->exec)
				ret = command->exec(argc, argv, data);

			break;
		}
	}

	return ret;
}
