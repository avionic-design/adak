AC_PREREQ(2.67)
AC_INIT([adak], [0.2.1], [bugs@avionic-design.de])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_HEADER([config.h])
AC_CANONICAL_HOST

AM_INIT_AUTOMAKE([dist-bzip2 dist-xz foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AM_MAINTAINER_MODE

AC_PROG_LIBTOOL
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL

CFLAGS="$CFLAGS -Wall"

AC_ARG_ENABLE([werror],
	[AS_HELP_STRING([--enable-werror],
		[Treat warnings as errors (default: enabled)])],
		[enable_werror="$enableval"],
		[enable_werror=yes])
if test "x$enable_werror" = "xyes"; then
	CFLAGS="$CFLAGS -Werror"
fi

COMMAND_ALIGN=32
AC_DEFINE_UNQUOTED([COMMAND_ALIGN], [$COMMAND_ALIGN],
	  [Define to the number of bytes to align commands to.])
AC_SUBST(COMMAND_ALIGN)

AC_OUTPUT([
	Makefile
	adak.lds
])
