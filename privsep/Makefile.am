bin_PROGRAMS = pmdprivsepd

pmdprivsepd_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/idl

pmdprivsepd_SOURCES = \
    global.c \
    pkgmgmtapi.c \
    pkgmgmtrpcapi.c \
    pkghandlelist.c \
    netmgmtrpcapi.c \
    fwmgmt_api.c \
    fwmgmt_rpcapi.c \
    fwmgmt_utils.c \
    iptables_rule_parser.c \
    iptables_script_reader.c \
    usermgmt_api.c \
    usermgmt_rpcapi.c \
    rpcapi.c \
    security.c \
    server.c \
    privsepd_sstub.c \
    pkgmgmt_privsep_sstub.c \
    netmgmt_privsep_sstub.c \
    fwmgmt_privsep_sstub.c \
    usermgmt_privsep_sstub.c \
    utils.c

SUBDIRS = demo

privsepd_sstub.c:
	cp $(top_srcdir)/idl/privsepd_sstub.c .
pkgmgmt_privsep_sstub.c:
	cp $(top_srcdir)/idl/pkgmgmt_privsep_sstub.c .
netmgmt_privsep_sstub.c:
	cp $(top_srcdir)/idl/netmgmt_privsep_sstub.c .
fwmgmt_privsep_sstub.c:
	cp $(top_srcdir)/idl/fwmgmt_privsep_sstub.c .
usermgmt_privsep_sstub.c:
	cp $(top_srcdir)/idl/usermgmt_privsep_sstub.c .

CLEANFILES = \
    privsepd_sstub.c \
    pkgmgmt_privsep_sstub.c \
    netmgmt_privsep_sstub.c \
    fwmgmt_privsep_sstub.c \
    usermgmt_privsep_sstub.c

pmdprivsepd_LDADD =  \
    @top_builddir@/common/libcommon.la \
    @top_builddir@/server/security/libpmdsecurity.la \
    @top_builddir@/server/common/libsrvcommon.la \
    @top_builddir@/privsep/demo/libdemosrv.la \
    @DCERPC_LIBS@ \
    -ltdnf \
    -lnetmgr \
    -lpthread \
    -lcrypt \
    -lcrypto \
    -ldl

pmdprivsepd_LDFLAGS = \
    @DCERPC_LDFLAGS@
