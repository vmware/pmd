noinst_LTLIBRARIES = libpmdsecurity.la

libpmdsecurity_la_CPPFLAGS = \
    -I$(top_srcdir)/include \
    @LW_INCLUDES@ \
    @VMDIRCLI_INCLUDES@ \
    @VMAFD_INCLUDES@

libpmdsecurity_la_SOURCES = \
    apisecurity.c \
    authz.c \
    rsa.c

libpmdsecurity_la_LDFLAGS = \
    -static \
    @top_builddir@/common/libcommon.la
