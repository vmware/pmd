noinst_LTLIBRARIES = libcommon.la

AM_CFLAGS += $(LIBCURL_CFLAGS)

libcommon_la_SOURCES = \
    configreader.c \
    dcerpcerror.c \
    fwmgmt.c \
    memory.c \
    rolemgmt.c \
    rpcsrvutils.c \
    strings.c \
    usermgmt.c \
    utils.c

libcommon_la_CPPFLAGS = \
    -I$(top_srcdir)/include

libcommon_la_LDFLAGS = \
    @DCERPC_LIBS@ \
    @LIBCURL_LIBS@ \
    -lpthread \
    -static
