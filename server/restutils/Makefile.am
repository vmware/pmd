noinst_LTLIBRARIES = librestutils.la

AM_CFLAGS += $(JANSSON_CFLAGS)
AM_CFLAGS += $(COPENAPI_CFLAGS)

librestutils_la_CPPFLAGS = \
    -I$(top_srcdir)/include \
    @LW_INCLUDES@
    
librestutils_la_SOURCES = \
    restauth.c \
    restbasicauth.c \
    restnegauth.c \
    restutils.c

librestutils_la_LDFLAGS =  \
    -static \
    @top_builddir@/jsonutils/libjsonutils.la \
    @JANSSON_LIBS@ \
    @COPENAPI_LIBS@
