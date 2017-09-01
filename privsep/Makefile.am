bin_PROGRAMS = pmdprivsepd

pmdprivsepd_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/idl \
    @LW_INCLUDES@ \
    @VMDIRCLI_INCLUDES@ \
    @VMAFD_INCLUDES@

pmdprivsepd_SOURCES = \
    rpcapi.c \
    security.c \
    server.c \
    privsepd_sstub.c

SUBDIRS = demo

privsepd_sstub.c:
	cp $(top_srcdir)/idl/privsepd_sstub.c .

CLEANFILES = \
    privsepd_sstub.c

pmdprivsepd_LDADD =  \
    @top_builddir@/common/libcommon.la \
    @top_builddir@/server/security/libpmdsecurity.la \
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
