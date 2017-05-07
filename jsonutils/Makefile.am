noinst_LTLIBRARIES = libjsonutils.la

AM_CFLAGS += $(JANSSON_CFLAGS)

libjsonutils_la_SOURCES = \
    jsonutils.c

libjsonutils_la_CPPFLAGS = \
    -I$(top_srcdir)/include

libjsonutils_la_LDFLAGS = \
    -static \
    @JANSSON_LIBS@
