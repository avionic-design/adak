/**
 * Copyright (C) 2010 Avionic Design GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef COMMAND_H
#define COMMAND_H 1

#define _command_ __attribute__((unused, section(".commands")))

struct command {
	const char *name;
	const char *synopsis;
	const char *summary;
	const char *help;
	int (*exec)(int argc, char *argv[], void *data);
} __attribute__((aligned(COMMAND_ALIGN)));

extern const struct command commands_start;
extern const struct command commands_end;

#define foreach_command(pos) \
	for (pos = &commands_start; pos < &commands_end; pos++)

#define DEFINE_COMMAND(_name, _synopsis, _summary, _help, _exec) \
	const struct command cmd_##_name _command_ = { \
		.name = #_name, \
		.synopsis = _synopsis, \
		.summary = _summary, \
		.help = _help, \
		.exec = _exec, \
	}

const struct command *find_command(const char *name);
int exec_command(int argc, char *argv[], void *data);

#endif /* COMMAND_H */
