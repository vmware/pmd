noinst_LTLIBRARIES = libpmdgpo.la

libpmdgpo_la_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/idl \
    @LW_INCLUDES@

libpmdgpo_la_SOURCES = \
    gpomgmt_api.c \
    gpomgmt_rpcapi.c \
    gpomgmt_sstub.c

gpomgmt_sstub.c:
	cp ../../idl/gpomgmt_sstub.c .

CLEANFILES = \
    gpomgmt_sstub.c

libpmdgpo_la_LDFLAGS = \
    -static \
    @top_builddir@/common/libcommon.la
