#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([SRxCryptoAPI], [0.2.0.1], [bgpsrx-dev@nist.gov])

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

#
# Check for OPENSSL Parameter
#
AS_BOX([Process OPENSSL Setup])
AC_ARG_VAR(openssl_dir, Provide a different openssl directory as the default one)

if test "x${openssl_dir}" = "x"; then
  echo "Use default OPENSSL Installation"
  OPENSSL_CFLAGS=""
  OPENSSL_LDFLAGS=""
  OPENSSL_CURVE_TEST=$(openssl ecparam -list_curves | grep prime256v1 | sed -e "s/\(prime256v1\):.*/-\1-/g" | sed -e "s/ //g")

  AC_CHECK_HEADERS([ \
		openssl/bio.h    \
		openssl/ec.h     \
		openssl/ecdsa.h  \
		openssl/err.h    \
		openssl/pem.h    \
		openssl/sha.h    \
		openssl/x509.h], \
		[have_openssl_headers=yes], [have_openssl_headers=no])
else
  echo "Use custom OPENSSL Installation at '${openssl_dir}'"
  OPENSSL_CFLAGS="-I${openssl_dir}/include"
  OPENSSL_LDFLAGS="-L${openssl_dir}/lib"
  OPENSSL_CURVE_TEST=$(${openssl_dir}/bin/openssl ecparam -list_curves | grep prime256v1 | sed -e "s/\(prime256v1\):.*/-\1-/g" | sed -e "s/ //g")
  AC_CHECK_HEADERS([ \
		${openssl_dir}/include/openssl/bio.h    \
		${openssl_dir}/include/openssl/ec.h     \
		${openssl_dir}/include/openssl/ecdsa.h  \
		${openssl_dir}/include/openssl/err.h    \
		${openssl_dir}/include/openssl/pem.h    \
		${openssl_dir}/include/openssl/sha.h    \
		${openssl_dir}/include/openssl/x509.h], \
		[have_openssl_headers=yes], [have_openssl_headers=no])
fi

if test "${have_openssl_headers}" = no; then
    AC_MSG_ERROR([
	--------------------------------------------------
	OpenSSL header files are missing - install 
	openssl-devel
	--------------------------------------------------])
fi

# Test for OPENSSL Curve availability
if test "${OPENSSL_CURVE_TEST}" = "-prime256v1-"; then
  echo "checking for openssl curve prime256v1... yes"
else
  echo "checking for openssl curve prime256v1... no"
  AC_MSG_ERROR([
	--------------------------------------------------
	ECDSA curve prime256v1 not found with selected 
	OpenSSL implementation.
	--------------------------------------------------])
fi

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_MAKE_SET
AC_PROG_INSTALL

#
# Checks for libraries.
#
AS_BOX([Process libraries])
AC_SEARCH_LIBS([dlopen], [dl])

##
## CHECK FOR config library
##
have_config=no
AC_SEARCH_LIBS([config_init], [config], [have_config=yes])
if test "${have_config}" = no; then
  AC_MSG_ERROR([
	--------------------------------------------------
	The config library required to build srx_server.
	For Fedora/CentOS please install "libconfig"
	--------------------------------------------------])
else  
  AC_CHECK_HEADERS([libconfig.h], [have_headers=yes], [have_headers=no])
  if test "${have_headers}" = no; then
    AC_MSG_ERROR([
	--------------------------------------------------
	libconfig.h is missing, install the libconfig 
	header. For fedora/CentOS install libconfig-devel.
	--------------------------------------------------])
  fi
fi

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
# BGPSEC-OPENSSL
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
# TESTLIB
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

# Determine if it is 64 or 32 bit architecture
AS_BOX([Processing system and compiler setup])
AC_MSG_CHECKING([host architecture information])
case "$HOSTTYPE" in
  x86_64) 
     CPU_ARCH_FLAG="-DCPU_64"
     CPU_ARCH="64"
     if test "${libdir}" = "\${exec_prefix}/lib" ; then
       libdir="${libdir}64"
     fi
     ;;
  *) 
     CPU_ARCH_FLAG=""
     CPU_ARCH=""
     ;;
esac
AC_MSG_RESULT([$CPU_ARCH bit])

LIB_VER_INFO=$current:$revision:$age
VER_INFO=$current.$age.$revision

# Check the CFLAGS 
if test "$CFLAGS" = "-g -O2"; then
 CFLAGS="-g -O0 -Wall $CPU_ARCH_FLAG"
else
 CFLAGS="$CFLAGS $CPU_ARCH_FLAG"
fi

# Check if crypto libraries will be dynamically or statically linked
AC_MSG_CHECKING([whether to link openssl libraries static or dynamic])
AC_ARG_ENABLE(static-openssl,
              [  --enable-static-openssl enable openssl being linked statically])
if test "${enableval}" = "yes" ; then
  AC_MSG_RESULT([static])
  OPENSSL_LIBS="-Wl,-Bstatic -lssl -Wl,-Bstatic -lcrypto"
else
  AC_MSG_RESULT([dynamic])
  OPENSSL_LIBS="-lssl -lcrypto"
fi

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

AS_BOX(Processing additional configuration settings)
AC_SUBST([CFG_PREFIX], [${prefix}])
AC_SUBST([SRX_DIR], [srx])

AC_SUBST([DOLLAR_SIGN],[$])

# Use this if one of the 'Makefile.am ' files are modified prior autoreconf -i
AC_CONFIG_FILES([Makefile bgpsec_openssl/Makefile crypto_testlib/Makefile \
                 srxcryptoapi-$PACKAGE_VERSION.spec:srxcryptoapi.spec.in \
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
echo "LDFLAGS......: $LDFLAGS"
echo "LIBDIR.......: ${libdir}"
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
