noinst_LTLIBRARIES = librolemgmt.la

librolemgmt_la_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/idl \
    @UUID_CFLAGS@
    
librolemgmt_la_SOURCES = \
    rolemgmt_api.c \
    rolemgmt_config.c \
    rolemgmt_global.c \
    rolemgmt_plugin.c \
    rolemgmt_restapi.c \
    rolemgmt_rpcapi.c \
    rolemgmt_sstub.c

rolemgmt_sstub.c:
	cp ../../idl/rolemgmt_sstub.c .

CLEANFILES = \
    rolemgmt_sstub.c

librolemgmt_la_LDFLAGS =  \
    -static \
    @top_builddir@/common/libcommon.la \
    @top_builddir@/jsonutils/libjsonutils.la \
    @UUID_LIBS@ \
    -ldl
