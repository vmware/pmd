noinst_LTLIBRARIES = libdemosrv.la

libdemosrv_la_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/idl \
    @LW_INCLUDES@
    
libdemosrv_la_SOURCES = \
    demo_privsep_sstub.c \
    demoapi.c \
    demorpcapi.c

demo_privsep_sstub.c:
	cp $(top_srcdir)/idl/demo_privsep_sstub.c .

CLEANFILES = \
    demo_privsep_sstub.c

libdemosrv_la_LDFLAGS =  \
    -static \
    -lm \
    @top_builddir@/common/libcommon.la \
    @DCERPC_LDFLAGS@ \
    @DCERPC_LIBS@ \
    @JANSSON_LIBS@
