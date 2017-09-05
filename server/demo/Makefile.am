noinst_LTLIBRARIES = libdemosrv.la

AM_CFLAGS += $(JANSSON_CFLAGS)

libdemosrv_la_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/idl \
    @LW_INCLUDES@

libdemosrv_la_SOURCES = \
    demoapi.c \
    demo_sstub.c \
    demorestapi.c \
    demorpcapi.c

demo_sstub.c:
	cp ../../idl/demo_sstub.c .

CLEANFILES = \
    demo_sstub.c

libdemosrv_la_LDFLAGS =  \
    -static \
    -lm \
    @top_builddir@/common/libcommon.la \
    @top_builddir@/client/libpmdclient.la \
    @top_builddir@/server/security/libpmdsecurity.la \
    @top_builddir@/server/common/libsrvcommon.la \
    @DCERPC_LDFLAGS@ \
    @DCERPC_LIBS@ \
    @JANSSON_LIBS@
