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
    netmgmtapi.c \
    netmgmtrestapi.c \
    pkgmgmtapi.c \
    pkgmgmtrpcapi.c \
    pkgmgmtrestapi.c \
    pmdrestapi.c \
    restserver.c \
    rpc.c \
    rpmostreeapi.c \
    server.c \
    signal.c \
    pkgmgmt_sstub.c \
    pmd_sstub.c \
    netmgmt_sstub.c \
    rpmostree_sstub.c \
    utils.c

pkgmgmt_sstub.c:
	cp ../idl/pkgmgmt_sstub.c .

pmd_sstub.c:
	cp ../idl/pmd_sstub.c .

netmgmt_sstub.c:
	cp ../idl/netmgmt_sstub.c .


rpmostree_sstub.c:
	cp ../idl/rpmostree_sstub.c .

CLEANFILES = \
    pkgmgmt_sstub.c \
    pmd_sstub.c \
    netmgmt_sstub.c \
    rpmostree_sstub.c


SUBDIRS = restutils \
          security \
          extras \
          grouppolicy

if ENABLE_DEMO
    SUBDIRS += demo
endif

pmd_LDADD =  \
    @top_builddir@/common/libcommon.la \
    @top_builddir@/jsonutils/libjsonutils.la \
    @top_builddir@/server/restutils/librestutils.la \
    @top_builddir@/server/extras/libpmdextras.la \
    @top_builddir@/server/security/libpmdsecurity.la \
    @top_builddir@/server/grouppolicy/libpmdgpwrappers.la \
    @DCERPC_LIBS@ \
    @JANSSON_LIBS@ \
    @CREST_LIBS@ \
    @VMDIRCLI_LIBS@ \
    @VMAFD_LIBS@ \
    @COPENAPI_LIBS@ \
    @LWBASE_LIBS@ \
    -lvmdirclient \
    -ltdnf \
    -lnetmgr \
    -lpthread \
    -lcrypt \
    -lcrypto

pmd_LDFLAGS = \
    @VMAFD_LDFLAGS@ \
    @VMDIRCLI_LDFLAGS@ \
    @CREST_LDFLAGS@ \
    @DCERPC_LDFLAGS@ \
    @LW_LDFLAGS@

if ENABLE_DEMO
    pmd_LDADD += @top_builddir@/server/demo/libdemosrv.la
endif
