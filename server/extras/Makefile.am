noinst_LTLIBRARIES = libpmdextras.la

libpmdextras_la_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/idl \
    @LW_INCLUDES@

libpmdextras_la_SOURCES = \
    fwmgmt_api.c \
    fwmgmt_restapi.c \
    fwmgmt_rpcapi.c \
    fwmgmt_sstub.c \
    fwmgmt_utils.c \
    iptables_rule_parser.c \
    iptables_script_reader.c \
    usermgmt_api.c \
    usermgmt_restapi.c \
    usermgmt_rpcapi.c \
    usermgmt_sstub.c

fwmgmt_sstub.c:
	cp ../../idl/fwmgmt_sstub.c .

rolemgmt_sstub.c:
	cp ../../idl/rolemgmt_sstub.c .

usermgmt_sstub.c:
	cp ../../idl/usermgmt_sstub.c .

CLEANFILES = \
    fwmgmt_sstub.c \
    rolemgmt_sstub.c \
    usermgmt_sstub.c

libpmdextras_la_LDFLAGS = \
    -static \
    @top_builddir@/common/libcommon.la \
    @top_builddir@/jsonutils/libjsonutils.la \
    @top_builddir@/server/security/libpmdsecurity.la
