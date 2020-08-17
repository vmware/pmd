bin_PROGRAMS = pmd
AM_CFLAGS += $(JANSSON_CFLAGS)
AM_CFLAGS += $(COPENAPI_CFLAGS)

pmd_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/idl \
    @LW_INCLUDES@ \
    @CREST_INCLUDES@ \
    @VMDIRCLI_INCLUDES@ \
    @VMAFD_INCLUDES@

pmd_SOURCES = \
    api.c \
    config.c \
    global.c \
    fwmgmt_rpcapi.c \
    fwmgmt_restapi.c \
    fwmgmt_sstub.c \
    netmgmtrpcapi.c \
    netmgmtrestapi.c \
    pkgmgmtrpcapi.c \
    pkgmgmtrestapi.c \
    usermgmt_restapi.c \
    usermgmt_rpcapi.c \
    usermgmt_sstub.c \
    pmdrestapi.c \
    restserver.c \
    rpc.c \
    server.c \
    pkgmgmt_sstub.c \
    pmd_sstub.c \
    netmgmt_sstub.c \
    privsephandlelist.c \
    rolemgmt_sstub.c \
    rpmostree_sstub.c \
    rpmostreeapi.c \
    utils.c

fwmgmt_sstub.c:
	cp ../idl/fwmgmt_sstub.c .

pkgmgmt_sstub.c:
	cp ../idl/pkgmgmt_sstub.c .

pmd_sstub.c:
	cp ../idl/pmd_sstub.c .

netmgmt_sstub.c:
	cp ../idl/netmgmt_sstub.c .

usermgmt_sstub.c:
	cp ../idl/usermgmt_sstub.c .
rolemgmt_sstub.c:
	cp ../idl/rolemgmt_sstub.c .

rpmostree_sstub.c:
	cp ../idl/rpmostree_sstub.c .

CLEANFILES = \
    fwmgmt_sstub.c \
    pkgmgmt_sstub.c \
    pmd_sstub.c \
    netmgmt_sstub.c \
    usermgmt_sstub.c \
    rolemgmt_sstub.c \
    rpmostree_sstub.c

SUBDIRS = common \
    rolemgmt \
    security \
    restutils \
    extras

if ENABLE_DEMO
    SUBDIRS += demo
endif

pmd_LDADD =  \
    @top_builddir@/common/libcommon.la \
    @top_builddir@/jsonutils/libjsonutils.la \
    @top_builddir@/server/restutils/librestutils.la \
    @top_builddir@/server/extras/libpmdextras.la \
    @top_builddir@/server/security/libpmdsecurity.la \
    @top_builddir@/server/common/libsrvcommon.la \
    @top_builddir@/client/libpmdclient.la \
    @top_builddir@/server/rolemgmt/librolemgmt.la \
    @DCERPC_LIBS@ \
    @JANSSON_LIBS@ \
    @CREST_LIBS@ \
    @VMDIRCLI_LIBS@ \
    @VMAFD_LIBS@ \
    @COPENAPI_LIBS@ \
    @LWBASE_LIBS@ \
    -lvmdirclient \
    -lnetmgr \
    -lpthread \
    -lcrypt \
    -lcrypto \
    -lgssapi_krb5

pmd_LDFLAGS = \
    @VMAFD_LDFLAGS@ \
    @VMDIRCLI_LDFLAGS@ \
    @CREST_LDFLAGS@ \
    @DCERPC_LDFLAGS@ \
    @LW_LDFLAGS@

if ENABLE_DEMO
    pmd_LDADD += @top_builddir@/server/demo/libdemosrv.la
endif
