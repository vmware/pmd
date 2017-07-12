noinst_LTLIBRARIES = libpmdgp.la

libpmdgp_la_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/idl \
    @LW_INCLUDES@

libpmdgp_la_SOURCES = \
    gpmgmt_api.c \
    gpmgmt_rpcapi.c \
    gpmgmt_sstub.c

gpmgmt_sstub.c:
	cp ../../idl/gpmgmt_sstub.c .

CLEANFILES = \
    gpmgmt_sstub.c

libpmdgp_la_LDFLAGS = \
    -static \
    @top_builddir@/common/libcommon.la
