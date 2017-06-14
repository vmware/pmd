bin_PROGRAMS = pmd-cli

pmd_cli_CPPFLAGS = -I$(top_srcdir)/include
pmd_cli_SOURCES = \
    help.c \
    parseargs.c \
    options.c \
    main.c \
    utils.c

SUBDIRS = \
    fwmgmt \
    pkgmgmt \
    netmgmt \
    rolemgmt \
    usermgmt

if ENABLE_DEMO
    SUBDIRS += demo
endif

pmd_cli_LDADD =  \
    @DCERPC_LIBS@ \
    $(top_builddir)/client/libpmdclient.la \
    $(top_builddir)/tools/cli/fwmgmt/libfwmgmtcli.la \
    $(top_builddir)/tools/cli/pkgmgmt/libpkgmgmtcli.la \
    $(top_builddir)/tools/cli/netmgmt/libnetmgmtcli.la \
    $(top_builddir)/tools/cli/rolemgmt/librolemgmtcli.la \
    $(top_builddir)/tools/cli/usermgmt/libusermgmtcli.la
if ENABLE_DEMO
    pmd_cli_LDADD += $(top_builddir)/tools/cli/demo/libdemocli.la
endif

pmd_cli_LDFLAGS = \
    @DCERPC_LDFLAGS@ \
    @LW_LDFLAGS@
