noinst_LTLIBRARIES = libpmdextras.la

libpmdextras_la_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/idl

libpmdextras_la_SOURCES =

rolemgmt_sstub.c:
	cp ../../idl/rolemgmt_sstub.c .

CLEANFILES = \
    rolemgmt_sstub.c

libpmdextras_la_LDFLAGS = \
    -static \
    @top_builddir@/common/libcommon.la \
    @top_builddir@/jsonutils/libjsonutils.la \
    @top_builddir@/server/security/libpmdsecurity.la
