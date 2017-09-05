bin_PROGRAMS = pmdprivsepd

pmdprivsepd_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/idl \
    @LW_INCLUDES@ \
    @VMDIRCLI_INCLUDES@ \
    @VMAFD_INCLUDES@

pmdprivsepd_SOURCES = \
    global.c \
    pkgmgmtapi.c \
    pkgmgmtrpcapi.c \
    rpcapi.c \
    security.c \
    server.c \
    privsepd_sstub.c \
    pkgmgmt_privsep_sstub.c \
    utils.c

SUBDIRS = demo

privsepd_sstub.c:
	cp $(top_srcdir)/idl/privsepd_sstub.c .
pkgmgmt_privsep_sstub.c:
	cp $(top_srcdir)/idl/pkgmgmt_privsep_sstub.c .

CLEANFILES = \
    privsepd_sstub.c \
    pkgmgmt_privsep_sstub.c

pmdprivsepd_LDADD =  \
    @top_builddir@/common/libcommon.la \
    @top_builddir@/server/security/libpmdsecurity.la \
    @top_builddir@/server/common/libsrvcommon.la \
    @top_builddir@/privsep/demo/libdemosrv.la \
    @DCERPC_LIBS@ \
    @VMDIRCLI_LIBS@ \
    @VMAFD_LIBS@ \
    @LWBASE_LIBS@ \
    -lvmdirclient \
    -ltdnf \
    -lnetmgr \
    -lpthread \
    -lcrypt \
    -lcrypto

pmdprivsepd_LDFLAGS = \
    @VMAFD_LDFLAGS@ \
    @VMDIRCLI_LDFLAGS@ \
    @DCERPC_LDFLAGS@ \
    @LW_LDFLAGS@
