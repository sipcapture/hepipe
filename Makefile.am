#
# makefile
#

bin_PROGRAMS = hepipe

hepipe_LDFLAGS = \
	-lpcap -lsocket

hepipe_CFLAGS = \
	-g -Wall -DUSE_IPV6 -DUSE_HEP3 -DUSE_CONFFILE

hepipe_SOURCES = \
	minIni/minIni.c \
	hepipe.c

noinst_HEADERS = \
	hepipe.h \
	minIni/minGlue-ccs.h \
	minIni/minGlue-efsl.h \
	minIni/minGlue-FatFs.h \
	minIni/minGlue-ffs.h \
	minIni/minGlue.h \
	minIni/minGlue-mdd.h \
	minIni/minGlue-stdio.h \
	minIni/minIni.h \
	minIni/wxMinIni.h

confdir = $(sysconfdir)/hepipe
dist_conf_DATA = \
	hepipe.ini
