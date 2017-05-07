ACLOCAL_AMFLAGS = -I m4

CLEANFILES =
EXTRA_DIST =
conf_DATA = conf/pmd.conf
pkginclude_HEADERS = include/pmd.h include/pmdtypes.h include/pmderror.h
pkgconfigdir = $(libdir)/pkgconfig

SUBDIRS = \
    idl \
    common \
    jsonutils \
    client \
    server \
    tools

if ENABLE_PYTHON
    SUBDIRS += python
endif

pkgconfig_DATA = pmdclient.pc
pmdclient.pc: $(top_srcdir)/pmdclient.pc.in
	./config.status --file=${subdir}/pmdclient.pc:${subdir}/pmdclient.pc.in
CLEANFILES += pmdclient.pc
EXTRA_DIST += pmdclient.pc.in
