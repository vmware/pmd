lib_LTLIBRARIES = libpmdgpmgmt.la

AM_CFLAGS += $(TDNF_CLI_LIBS_CFLAGS)

libpmdgpmgmt_la_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/idl \
    @LW_INCLUDES@


libpmdgpmgmt_la_SOURCES = \
    gpmgmtapi.c \
    gpupdatepolicy.c

libpmdgpmgmt_la_LDFLAGS = \
    -shared

libpmdgpmgmt_la_LIBADD = \
    -lpthread \
    @TDNF_CLI_LIBS_LIBS@
