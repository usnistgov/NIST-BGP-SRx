#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([SRxCryptoAPI], [0.3.0.3], [itrg-contact@list.nist.gov])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_MSG_CHECKING([Linux distribution checking])
cat /proc/version | grep -i ubuntu >/dev/null 2>&1
if [[ $? -eq 0 ]]; then
  OS_DIST=ubuntu
else
  OS_DIST=other
fi
AC_MSG_RESULT([$OS_DIST])

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([srxcryptoapi.c])
AC_CONFIG_HEADERS([config.h])

# Using for Libtool
LT_PREREQ([2.2])
LT_INIT([dlopen])
LT_INIT([lt_dlopen])

# library information versioning
# Extract Version numbers from AC_INIT above
PKG_VER=`echo AC_PACKAGE_VERSION | cut -d . -f 1`
MAJOR_VER=`echo AC_PACKAGE_VERSION | cut -d . -f 2`
MINOR_VER=`echo AC_PACKAGE_VERSION | cut -d . -f 3`
UPD_VER=`echo AC_PACKAGE_VERSION | cut -d . -f 4`
PACKAGE_VERSION=AC_PACKAGE_VERSION

current=$MAJOR_VER
revision=$MINOR_VER
# The age CAN NOT be derived from the package version specified above.
# The age MUST be specified manually!!!
age=0

dnl echo "PKG_VER=$PKG_VER" 
dnl echo "MAJOR_VER=$MAJOR_VER" 
dnl echo "MINOR_VER=$MINOR_VER" 
dnl echo "UPD_VER=$UPD_VER" 
dnl echo "PACKAGE_VERSION=$PACKAGE_VERSION"
dnl echo "current=$current"

dnl echo "revision=$revision" 
dnl echo "age=$age" 

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_MAKE_SET
AC_PROG_INSTALL

#
# Check for CPU architecture
#
CPU_ARCH_FLAG=
SRX_M4_CHECK_ARCH([CPU_ARCH], [CPU_ARCH_FLAG], [CPU_])
if test "${libdir}" = "\${exec_prefix}/lib" ; then
  libdir="${libdir}$CPU_ARCH"
fi

#
# Checks for libraries.
#
AS_BOX([Process libraries])
AC_SEARCH_LIBS([dlopen], [dl])

##
## CHECK FOR config library
##
SRX_M4_CHECK_LIBCONFIG()

#
# Check for OPENSSL Parameter
#
AS_BOX([Process OPENSSL Setup])
SRX_M4_CHECK_OPENSSL($CPU_ARCH, OPENSSL_LIBS, [OPENSSL_CFLAGS], [OPENSSL_LDFLAGS])

# General checks for header files.
AS_BOX([Process header files])
echo "Checking generel required header files..."
AC_CHECK_HEADERS([                 \
                  assert.h         \
                  dlfcn.h          \
                  libconfig.h      \
                  malloc.h         \
                  stdarg.h         \
                  stdbool.h        \
                  stddef.h         \
                  stdio.h          \
                  stdlib.h         \
                  string.h         \
                  syslog.h         \
                  sys/param.h      \
                  sys/stat.h       \
                  sys/types.h      \
                 ], [have_required_headers=yes], [have_required_headers=no])
if test "${have_required_headers}" = no; then
    AC_MSG_ERROR([
          --------------------------------------------------
          Not all required header files are found. See list
          above and make sure to install the header required
          header files.
          --------------------------------------------------])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])


# Add Debugging Memory checking.
AC_MSG_CHECKING([whether MEM_CHECK will be activated])
AC_ARG_ENABLE(mcheck,
              [  --enable-mcheck         enable memory check M_CHECK_ACTION 3],
              MCHECK="-DMEM_CHECK", MCHECK="")
if test "$MCHECK" = "" ; then
  AC_MSG_RESULT([no])
else
  AC_MSG_RESULT([yes])
  have_gcc_s=no
  AC_SEARCH_LIBS([free], [gcc_s], [have_gcc_s=yes])
  if test "x${have_gcc_s}" = "xno" ; then
    AC_MSG_ERROR([Libraty libgcc_s is required for --enable-mcheck.])
  fi
fi
AC_SUBST(MCHECK)

# Check if .la and .a libraries should be added to RPM distribution
AC_MSG_CHECKING([whether .a and .la libraries will be added to rpm distribution])
AC_ARG_WITH(la-lib,
            [  --with-la-lib           add installation/distribution of .la/.a libraries in RPM generation],
            [incl_la_lib=${withval}], [incl_la_lib="no"])
AC_MSG_RESULT([${incl_la_lib}])
AC_SUBST(incl_la_lib)

#
# Add Modules
#
AS_BOX([Process which components to be added])

#
# Add Module BGPSEC-OPENSSL
#
CONFIG_MODULES=""
AC_MSG_CHECKING([whether module bgpsec-openssl will be added])
AC_ARG_WITH(bgpsec-openssl,
              [  --without-bgpsec-openssl do not include bgpsec openssl crypto implementationl],
              [bgpsec_openssl=${withval}], [bgpsec_openssl=yes])
AC_MSG_RESULT([${bgpsec_openssl}])
if  test "${bgpsec_openssl}" = "yes" ; then  
  BGPSEC_OPENSSL="bgpsec_openssl"
  # it requires uthash
  AC_CHECK_HEADERS([uthash.h], [have_headers=yes], [have_headers=no])
  if test "${have_headers}" = no; then
    AC_MSG_ERROR([
	--------------------------------------------------
	uthash.h is missing, install uthash.h header. For 
	fedora/CentOS install uthash-devel.
	--------------------------------------------------])
  fi  
else
  BGPSEC_OPENSSL=""
fi

#
# Add Module TESTLIB
#
AC_MSG_CHECKING([whether module testlib will be added])
AC_ARG_WITH(testlib,
              [  --without-testlib        do not include crypto test implementationl],
              [with_testlib=${withval}], [with_testlib=yes])
AC_MSG_RESULT([${with_testlib}])
if test "${with_testlib}" = "yes"; then  
  CRYPTO_TESTLIB="crypto_testlib"
else
  CRYPTO_TESTLIB=""
fi

LIB_VER_INFO=$current:$revision:$age
VER_INFO=$current.$age.$revision

#
# Check the CFLAGS
#
AS_BOX([Processing CFLAGS setting])
srx_cflags=
for srx_cflag in $CFLAGS; do

  if test "x$srx_cflag" = "x-O2"; then
    AC_MSG_NOTICE([Found CFLAGS -O2 setting, change it to -O0])
    srx_cflag="-O0"
  fi

  if test "x$srx_cflags" = "x"; then
    srx_cflags="$srx_cflag"
  else
    srx_cflags="$srx_cflags $srx_cflag"
  fi

done
CFLAGS="$srx_cflags $CPU_ARCH_FLAG"

dnl ----------
dnl Some automake conditions
dnl ----------
AM_CONDITIONAL([LIB_VER_INFO_COND], [test $LIB_VER_INFO])
AM_CONDITIONAL([OS_UBUNTU_COND], [test "x$OS_DIST" = xubuntu])

dnl ----------
dnl Linux IPv6
dnl ----------
AC_MSG_CHECKING([whether system supports IPv6])
if test x`ls /proc/net/ipv6_route 2>/dev/null` = x"/proc/net/ipv6_route" ; then
   srxcryptoapi_ipv6=yes
   AC_MSG_RESULT([Linux IPv6])
else
   srxcryptoapi_ipv6=no
   AC_MSG_RESULT([none])
fi

if test "$srxcryptoapi_ipv6" = "yes"; then
  AC_MSG_CHECKING(whether libc has IPv6 support)
  AC_TRY_LINK([#include <netinet/in.h>
               ],[ int a; a = (int) in6addr_any.s6_addr[0]; if (a != 12345) return a; ],
               [srxcryptoapi_ipv6=yes], [srxcryptoapi_ipv6=no])
  AC_MSG_RESULT(${srxcryptoapi_ipv6})
fi
  
if test "$srxcryptoapi_ipv6" = "yes";then
  AC_DEFINE(HAVE_IPV6,1,Linux IPv6)
fi



dnl
dnl If this compilation test pass through, that means ltdl.h will be included in config.h
dnl
AC_MSG_CHECKING([compiling test for ltdl])
header_ltdl=no
AC_COMPILE_IFELSE(
                  [AC_LANG_PROGRAM( [[
                   #include<ltdl.h>
                   ]],
                   [[ ]])],
                  [header_ltdl=yes],[]
                 )
AC_MSG_RESULT(ltdl header: $header_ltdl)


save_libs="$LIBS"
LIBS="$LIBS -lltdl"
need_preload_symbol=no
if test "x$OS_DIST" = xubuntu; then
  AC_MSG_CHECKING([libtool dynamic loader link availability])
  AC_LINK_IFELSE( [AC_LANG_PROGRAM([[
                   #include<ltdl.h>
                   ]],
                   [[
                    int ltdl;
                    LTDL_SET_PRELOADED_SYMBOLS();
                    ltdl = lt_dlinit();
                    ]])],
                  [AC_MSG_RESULT(availability: yes)],
                  [AC_MSG_RESULT(availability: no)
                  need_preload_symbol=yes]
                )
fi
LIBS="$save_libs"

dnl
dnl In case of success, USE_PRELOAD_SYMBOL enables the patch code to be able to link
dnl
available_preload_symbol=no
AC_MSG_CHECKING([ltdl patch capability])
if test "x$need_preload_symbol" = xyes; then
  if test "x$header_ltdl" = xyes; then
    save_libs="$LIBS"
    LIBS="$LIBS -lltdl"
    AC_LINK_IFELSE(
                   [AC_LANG_PROGRAM( [[
                    #include<ltdl.h>
                    ]],
                    [[
                     #ifndef lt__PROGRAM__LTX_preloaded_symbols
                     #define lt_preloaded_symbols    lt_libltdl_LTX_preloaded_symbols
                     extern lt_dlsymlist lt_libltdl_LTX_preloaded_symbols[];
                     #endif
                     int ltdl;
                     LTDL_SET_PRELOADED_SYMBOLS();
                     ltdl = lt_dlinit();
                    ]])
                   ],
                   [AC_MSG_RESULT(capability: yes)
                   LIBS="$save_libs"
                   available_preload_symbol=yes
                   AC_DEFINE([USE_PRELOAD_SYMBOL], [], [enable ltdl preload symbol])
                   AC_CHECK_HEADERS([ltdl.h])
                   AC_SEARCH_LIBS([lt_dlopen], [ltdl])
                   ],
                   [LIBS="$save_libs"
                    AC_MSG_WARN([ warning -- need to use dl library instead of ltdl ])
                   ]
                  )
  fi
fi
AC_MSG_CHECKING([preload symbol status])
AC_MSG_RESULT([need: $need_preload_symbol  avaliable: $available_preload_symbol])

AC_SUBST(BGPSEC_OPENSSL)
AC_SUBST(CRYPTO_TESTLIB)
AC_SUBST(LIB_VER_INFO)
AC_SUBST(PKG_VER)
AC_SUBST(MAJOR_VER)
AC_SUBST(MINOR_VER)
AC_SUBST(UPD_VER)
AC_SUBST(PACKAGE_VERSION)
AC_SUBST(VER_INFO)
AC_SUBST(OPENSSL_LIBS)
AC_SUBST(OPENSSL_LDFLAGS)
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(CPU_ARCH)
AC_SUBST(LCONFIG_INT)

AS_BOX(Processing additional configuration settings)
AC_SUBST([CFG_PREFIX], [${prefix}])
AC_SUBST([SRX_DIR], [srx])

AC_SUBST([DOLLAR_SIGN],[$])

# Use this if one of the 'Makefile.am ' files are modified prior autoreconf -i
AC_CONFIG_FILES([Makefile bgpsec_openssl/Makefile crypto_testlib/Makefile \
                 srxcryptoapi.conf \
                 srxcryptoapi-$PACKAGE_VERSION.spec:srxcryptoapi.spec.in \
                 srxcryptoapi-devel-$PACKAGE_VERSION.spec:srxcryptoapi-devel.spec.in \
                 srxcryptoapi_lib$CPU_ARCH.conf:srxcryptoapi_lib.conf.in])

#
# Force all libraries to be installed in lib/srx or lib64/srx
#
my_libdir=${libdir}/srx
libdir=${my_libdir}

AC_OUTPUT

echo "Summary:"
echo "----------------------------------------------------------"
echo "Version......: $PACKAGE_VERSION"
echo "Configured...: AC_PACKAGE_NAME V AC_PACKAGE_VERSION"
echo "Library......: $VER_INFO ($LIB_VER_INFO)"
echo "CPU Arch.....: $CPU_ARCH"
echo "CFLAGS.......: $CFLAGS"
echo "LIBS.........: $LIBS"
echo "LDFLAGS......: $LDFLAGS"
echo "LIBDIR.......: ${libdir}"
echo "LCONFIG_INT..: $LCONFIG_INT"
echo "RPM Incl. la.: ${incl_la_lib}"
echo ""
echo "OpenSSL Configuration:"
if test "x${openssl_dir}" = "x"; then
  echo "  - Type.............: Use default install"
else
  echo "  - Type.............: Use custom install at '${openssl_dir}'"
fi
echo "  - OPENSSL_LIBS.....: $OPENSSL_LIBS"
echo "  - OPENSSL_LDFLAGS..: $OPENSSL_LDFLAGS"
echo "  - OPENSSL_CFLAGS...: $OPENSSL_CFLAGS"

echo ""
echo "Installed PlugIns: "
if  test "x${BGPSEC_OPENSSL}" = x; then
  echo "  - SRxBGPSecOpenSSL...no"
else
  echo "  - SRxBGPSecOpenSSL...yes"
fi
if  test "x${CRYPTO_TESTLIB}" = x; then
  echo "  - SRxCryptoTestlib...no"
else
  echo "  - SRxCryptoTestlib...yes"
fi
