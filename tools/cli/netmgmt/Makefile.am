noinst_LTLIBRARIES = libnetmgmtcli.la

libnetmgmtcli_la_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/idl -I/opt/likewise/include -I/usr/include/netmgmt
libnetmgmtcli_la_SOURCES = \
    net_help.c \
    net_main.c

libnetmgmtcli_la_LDFLAGS =  \
    -lnetmgrcli \
    -static
