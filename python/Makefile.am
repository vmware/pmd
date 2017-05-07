pkgpyexec_LTLIBRARIES = _pmd.la
pkgpyexec_DATA = pmd/__init__.py

CLEANFILES =

_pmd_la_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I@WITH_PYTHON_INCLUDE@ \
    @LW_INCLUDES@

_pmd_la_SOURCES = \
    fwmgmt_py.c \
    netmgmt_py.c \
    netmgmt_link_py.c \
    netmgmt_route_py.c \
    netmgmt_system_py.c \
    pkgmgmt_py.c \
    pkgmgmt_repodata_py.c \
    pkgmgmt_package_py.c \
    pkgmgmt_solvedinfo_py.c \
    pkgmgmt_utils.c \
    pmdmodule.c \
    server_py.c \
    utils.c

_pmd_la_LDFLAGS= -module -avoid-version -shared @DCERPC_LDFLAGS@

_pmd_la_LIBADD = \
    $(top_builddir)/common/libcommon.la \
    $(top_builddir)/client/libpmdclient.la \
    @DCERPC_LIBS@ \
    @WITH_PYTHON_LIB@

CLEANFILES += pmd/__pycache__
CLEANFILES += build
