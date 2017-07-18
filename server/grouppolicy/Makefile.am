noinst_LTLIBRARIES = libpmdgpwrappers.la

libpmdgpwrappers_la_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/idl \
    @LW_INCLUDES@ \
    @CREST_INCLUDES@ \
    @VMAFD_INCLUDES@

libpmdgpwrappers_la_SOURCES = \
    gpwrappers.c \
    gpmgmtrpcapi.c \
    gpmgmt_sstub.c

gpmgmt_sstub.c:
	cp ../../idl/gpmgmt_sstub.c .

SUBDIRS = gpmgmtplugin

CLEANFILES = \
    gpmgmt_sstub.c

libpmdgpwrappers_la_LDFLAGS = \
     -shared

libpmdgpwrappers_la_LIBADD = \
    $(top_builddir)/common/libcommon.la \
    -ldl