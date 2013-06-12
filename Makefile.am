ACLOCAL_AMFLAGS = -I m4

noinst_LTLIBRARIES = \
	libadak.la

bin_PROGRAMS = \
	adak-mac \
	adak-sx8634

sbin_PROGRAMS = \
	adak-cpld \
	adak-fpga \
	adak-usb-reset

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

adak_sx8634_SOURCES = \
	blkdev.c \
	blkdev.h \
	hexdump.c \
	hexdump.h \
	i2c.c \
	i2c.h \
	sx8634.c

adak_sx8634_LDADD = \
	libadak.la

adak_fpga_SOURCES = \
	fpga.c \
	stream.c \
	stream.h

adak_fpga_LDADD = \
	libadak.la \
	adak.lds

adak_cpld_SOURCES = \
	i2c.c \
	i2c.h \
	cpld.c

adak_cpld_LDADD = \
	libadak.la \
	adak.lds

adak_usb_reset_SOURCES = \
	usb-reset.c

EXTRA_DIST = \
	NEWS \
	TODO
