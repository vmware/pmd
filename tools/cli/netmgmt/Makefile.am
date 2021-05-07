noinst_LTLIBRARIES = libnetmgmtcli.la

libnetmgmtcli_la_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/idl -I/usr/include -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/usr/include/json-c
libnetmgmtcli_la_SOURCES = \
    net_help.c \
    net_main.c

libnetmgmtcli_la_LDFLAGS =  \
    -lnetwork_config_manager \
    -lglib-2.0 \
    -ljson-c \
    -static
