AC_INIT(pmd, 0.0.6)
AC_MSG_NOTICE([pmd configuration])

AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AM_PROG_AR

AC_PROG_CC
LT_INIT
AC_PROG_LIBTOOL

CPPFLAGS="$CPPFLAGS -D_REENTRANT -D_GNU_SOURCE -fPIC"

AM_CPPFLAGS="$AM_CPPFLAGS -I${top_srcdir}/include"
AM_CFLAGS="$AM_CFLAGS -Wall -Werror -Wno-unused-variable -fno-strict-aliasing"

AC_SUBST(AM_CPPFLAGS)
AC_SUBST(AM_CFLAGS)

saved_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS"

DCERPC_PATH="/usr/bin"
DCERPC_INCLUDES="-I/usr/include"
DCERPC_LDFLAGS="-L/usr/lib"

AC_SUBST(DCERPC_PATH)
AC_SUBST(DCERPC_INCLUDES)
AC_SUBST(DCERPC_LDFLAGS)

#dcerpc lib
echo "Looking for dcerpc headers"
AC_CHECK_HEADERS(dce/rpc.h)

CPPFLAGS="$saved_CPPFLAGS"

AC_CHECK_LIB(
    [dcerpc],
    [rpc__init],
    [DCERPC_LIBS="-ldcerpc"],
    [],
    [$DCERPC_LDFLAGS])

AC_SUBST(DCERPC_LIBS)

AC_ARG_WITH([c-rest-engine],
    [AC_HELP_STRING([--with-c-rest-engine=<dir>], [use rest binaries rooted at prefix <dir> ])],
    [
        CREST_BASE_PATH="$withval"
        CREST_INCLUDES="-I$withval/include"
        CREST_LDFLAGS="-L$withval/lib64"
    ],
    [
        CREST_BASE_PATH="/usr/lib/"
        CREST_INCLUDES="-I/usr/include/c-rest-engine/"
        CREST_LDFLAGS="-L/usr/lib/"
    ])

AC_SUBST(CREST_BASE_PATH)
AC_SUBST(CREST_INCLUDES)
AC_SUBST(CREST_LDFLAGS)

saved_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $CREST_INCLUDES"

#c-rest-engine lib
echo "Looking for rest headers"
AC_CHECK_HEADERS(vmrest.h)

AC_CHECK_LIB(
    [restengine],
    [VmRESTInit],
    [CREST_LIBS="-lrestengine"],
    [],
    [$CREST_LDFLAGS])

AC_SUBST(CREST_LIBS)

saved_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS"
AC_CHECK_HEADERS(uuid/uuid.h dce/rpc.h)
CPPFLAGS="$saved_CPPFLAGS"

AC_ARG_ENABLE([python],
    [AS_HELP_STRING([--enable-python], [build pmd python bindings (default: disabled)])],
    [
      if test x"$enableval" = x"yes"
      then
        AM_PATH_PYTHON([2.7],
        [WITH_PYTHON_INCLUDE=`${PYTHON} -c 'from distutils.sysconfig import *; import sys; sys.stdout.write(get_python_inc())'`
        CPPFLAGS="$CPPFLAGS -I$WITH_PYTHON_INCLUDE"
        AC_CHECK_HEADER([Python.h],[],[AC_MSG_ERROR([missing Python.h])])
        AC_SEARCH_LIBS([Py_Main],[python${PYTHON_VERSION} python],
                       [WITH_PYTHON_LIB="$ac_res"],
                       [AC_MSG_ERROR([missing python library])])
        ])
      fi
    ])

CPPFLAGS="$saved_CPPFLAGS"
LIBS="$saved_LIBS"

AC_SUBST(WITH_PYTHON_INCLUDE)
AC_SUBST(WITH_PYTHON_LIB)
AM_CONDITIONAL(ENABLE_PYTHON,[test "$WITH_PYTHON_INCLUDE"])

AC_ARG_ENABLE([demo],
    [AS_HELP_STRING([--enable-demo], [build demo modules(default: disabled)])],
    [
      if test x"$enableval" = x"yes"
      then
        [WITH_DEMO=1]
        AC_DEFINE(DEMO_ENABLED)
      else
        [WITH_DEMO=0]
      fi
    ])
AM_CONDITIONAL(ENABLE_DEMO, [test "$WITH_DEMO" = 1])


#tdnf
PKG_CHECK_MODULES([TDNF], [tdnf], [have_libtdnf=yes], [have_libtdnf=no])
AM_CONDITIONAL([TDNF],  [test "$have_libtdnf" = "yes"])

#tdnf-cli-libs
PKG_CHECK_MODULES([TDNF_CLI_LIBS], [tdnf-cli-libs], [have_libtdnfcli=yes], [have_libtdnfcli=no])
AM_CONDITIONAL([TDNF_CLI_LIBS],  [test "$have_libtdnfcli" = "yes"])

#jansson
PKG_CHECK_MODULES([JANSSON], [jansson], [have_libjansson=yes], [have_libjansson=no])
AM_CONDITIONAL([JANSSON],  [test "$have_libjansson" = "yes"])

#libcurl
PKG_CHECK_MODULES([LIBCURL], [libcurl], [have_libcurl=yes], [have_libcurl=no])
AM_CONDITIONAL([LIBCURL],  [test "$have_libcurl" = "yes"])

#copenapi
PKG_CHECK_MODULES([COPENAPI], [copenapi], [have_libcopenapi=yes], [have_libcopenapi=no])
AM_CONDITIONAL([COPENAPI],  [test "$have_libcopenapi" = "yes"])

#uuid
PKG_CHECK_MODULES([UUID], [uuid], [have_libuuid=yes], [have_libuuid=no])
AM_CONDITIONAL([UUID],  [test "$have_libuuid" = "yes"])

#network-config-manager
PKG_CHECK_MODULES([NETWORK_CONFIG_MANAGER], [network-config-manager], [have_libnetwork_config_manager=yes], [have_libnetwork_config_manager=no])
AM_CONDITIONAL([NETWORK_CONFIG_MANAGER],  [test "$have_libnetwork_config_manager" = "yes"])

#makefiles
AC_CONFIG_FILES([Makefile
                 common/Makefile
                 idl/Makefile
                 jsonutils/Makefile
                 server/Makefile
                 server/common/Makefile
                 server/demo/Makefile
                 server/extras/Makefile
                 server/restutils/Makefile
                 server/rolemgmt/Makefile
                 server/security/Makefile
                 privsep/Makefile
                 privsep/demo/Makefile
                 client/Makefile
                 python/Makefile
                 python/setup.py
                 tools/Makefile
                 tools/cli/Makefile
                 tools/cli/demo/Makefile
                 tools/cli/fwmgmt/Makefile
                 tools/cli/pkgmgmt/Makefile
                 tools/cli/netmgmt/Makefile
                 tools/cli/usermgmt/Makefile
                 tools/cli/rolemgmt/Makefile
                 pmd.spec
                ])

#pmd conf dir
confdir=$sysconfdir/pmd
AC_SUBST(confdir)

#
AC_OUTPUT
