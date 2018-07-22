noinst_LTLIBRARIES = librestutils.la

AM_CFLAGS += $(JANSSON_CFLAGS)
AM_CFLAGS += $(COPENAPI_CFLAGS)

librestutils_la_CPPFLAGS = \
    -I$(top_srcdir)/include \
    @LW_INCLUDES@ \
    @VMDIRCLI_INCLUDES@
    
librestutils_la_SOURCES = \
    global.c \
    restauth.c \
    restutils.c

librestutils_la_LDFLAGS =  \
    -static \
    -lkrb5 \
    -lgssapi_krb5 \
    @top_builddir@/jsonutils/libjsonutils.la \
    @JANSSON_LIBS@ \
    @COPENAPI_LIBS@
