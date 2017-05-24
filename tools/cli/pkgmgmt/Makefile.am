noinst_LTLIBRARIES = libpkgmgmtcli.la

AM_CFLAGS += $(TDNF_CLI_LIBS_CFLAGS)

libpkgmgmtcli_la_CPPFLAGS = -I$(top_srcdir)/include
libpkgmgmtcli_la_SOURCES = \
    pkg_help.c \
    pkg_main.c \
    pkg_parseargs.c

libpkgmgmtcli_la_LDFLAGS =  \
    -static \
    @TDNF_CLI_LIBS_LIBS@
