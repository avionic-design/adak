ACLOCAL_AMFLAGS = -I m4

noinst_LTLIBRARIES = \
	libadak.la

bin_PROGRAMS = \
	adak-mac

libadak_la_SOURCES = \
	command.c \
	command.h \
	utils.c \
	utils.h

adak_mac_SOURCES = \
	mac.c

adak_mac_LDADD = \
	libadak.la \
	adak.lds

EXTRA_DIST = \
	NEWS \
	TODO
