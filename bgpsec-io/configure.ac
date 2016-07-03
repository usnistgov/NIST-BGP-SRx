#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([bgpsecio], [0.2.0.4], [bgpsrx-dev@antd.nist.gov])
AM_INIT_AUTOMAKE([-Wall -Werror -Wno-portability])

# AC_CONFIG_SRCDIR specifies a file that the configuration checks for existence.
AC_CONFIG_SRCDIR([ASList.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

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

# Determine if it is 64 Bit. This is needed for the ld.conf.d. file.
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

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Add Debugging Memory checking.
AC_ARG_ENABLE(mcheck,
              [--enable-mcheck  enable memory check M_CHECK_ACTION 3],
              MCHECK="-DMEM_CHECK", MCHECK="")
AC_SUBST(MCHECK)

# Checks for libraries.

##
## CHECK FOR pthread library
##
AC_SEARCH_LIBS([pthread_create], [pthread], [have_pthreads=yes])
if test "${have_pthreads}" = no; then
  AC_MSG_ERROR([
  ------------------------------------------------------
  The pthread library is required to build bgpsec-io
  ------------------------------------------------------
  ])
else  
  AC_CHECK_HEADERS([pthread.h], [have_headers=yes], [have_headers=no])
  if test "${have_headers}" = no; then
    AC_MSG_ERROR([
    --------------------------------------------------
    pthread.h is missing, install the pthread headers.
    --------------------------------------------------])
  fi
fi

#
# Checks for libraries.
#
AS_BOX([Process libraries])

have_libraries="no"
AC_SEARCH_LIBS([clock_gettime], [rt], [have_libraries="yes"])

if test "${have_libraries}" = no; then
    AC_MSG_ERROR([
	--------------------------------------------------
	One of the required libraries is missing.
	--------------------------------------------------])
fi

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

##
## CHECK FOR SRxCrytpoAPI
##
have_srxcryptoapi=no
AC_ARG_VAR(sca_dir, Provide a different directory where SRxCryptoAPI is installed in)
if test "x${sca_dir}" = "x"; then
  SCA_CFLAGS=
  SCA_LDFLAGS="-L/usr/lib${CPU_ARCH}/srx"
  AC_SEARCH_LIBS([_init], [SRxCryptoAPI], [have_srxcryptoapi=yes])
else
  SCA_CFLAGS="-I${sca_dir}/include"
  SCA_LDFLAGS="-L${sca_dir}/lib${CPU_ARCH}/srx"
  AC_MSG_CHECKING([for ${sca_dir}/lib${CPU_ARCH}/srx/libSRxCryptoAPI.so])
  if test -e ${sca_dir}/lib${CPU_ARCH}/srx/libSRxCryptoAPI.so ; then
    have_srxcryptoapi=yes
  fi
  AC_MSG_RESULT([${have_srxcryptoapi}])
fi

if test "${have_srxcryptoapi}" = no; then
  AC_MSG_ERROR([
	--------------------------------------------------
	The SRxCryptoAPI library is required for bgpsec-io
	--------------------------------------------------])
else
  if test "x${sca_dir}" = "x"; then
    AC_CHECK_HEADERS([srx/srxcryptoapi.h], [have_headers=yes], [have_headers=no])
  else
    AC_CHECK_HEADERS([${sca_dir}/include/srx/srxcryptoapi.h], [have_headers=yes], [have_headers=no])
  fi
  if test "${have_headers}" = no; then
    AC_MSG_ERROR([
    --------------------------------------------------
    srxcryptoapi.h not found, install SRxCryptoAPI
    --------------------------------------------------])
  fi
fi
SCA_LDFLAGS="${SCA_LDFLAGS} -lSRxCryptoAPI"

## 
## Check for OPENSSL Parameter`
##
AC_ARG_VAR(openssl_dir, Provide a different openssl directory as the default one)

if test "x${openssl_dir}" = "x"; then
  echo "Use default OPENSSL Installation"
  OPENSSL_CFLAGS=""
  OPENSSL_LDFLAGS=""
  OPENSSL_CURVE_TEST=$(openssl ecparam -list_curves | grep prime256v1 | sed -e "s/\(prime256v1\):.*/-\1-/g" | sed -e "s/ //g")
  AC_CHECK_HEADERS([openssl/crypto.h \
                    openssl/bio.h \
                    openssl/sha.h \
                    openssl/ec.h \
                    openssl/ecdsa.h \
                    openssl/err.h \
                   ], [have_openssl_headers=yes], [have_openssl_headers=no])
else
  echo "Use custom OPENSSL Installation at '${openssl_dir}'"
  OPENSSL_CFLAGS="-I${openssl_dir}/include"
  OPENSSL_LDFLAGS="-L${openssl_dir}/lib${CPU_ARCH}"
  OPENSSL_CURVE_TEST=$(${openssl_dir}/bin/openssl ecparam -list_curves | grep prime256v1 | sed -e "s/\(prime256v1\):.*/-\1-/g" | sed -e "s/ //g")

  AC_CHECK_HEADERS([${openssl_dir}/include/openssl/crypto.h \
                    ${openssl_dir}/include/openssl/bio.h \
                    ${openssl_dir}/include/openssl/sha.h \
                    ${openssl_dir}/include/openssl/ec.h \
                    ${openssl_dir}/include/openssl/ecdsa.h \
                    ${openssl_dir}/include/openssl/err.h \
                   ], [have_openssl_headers=yes], [have_openssl_headers=no])
fi
if test "${have_openssl_headers}" = no; then
  AC_MSG_ERROR([
	--------------------------------------------------
	Some or all required OpenSSL header files could 
	not be located.
	--------------------------------------------------])
fi

# Test for OPENSSL Curve availability
AC_MSG_CHECKING([for openssl curve prime256v1])
if test "${OPENSSL_CURVE_TEST}" = "-prime256v1-"; then
  AC_MSG_RESULT([yes])
else
  AC_MSG_RESULT([NO])
  AC_MSG_ERROR([
	--------------------------------------------------
	ECDSA curve prime256v1 not found with selected 
  OpenSSL implementation.
	--------------------------------------------------])
fi

# General checks for header files.
echo "Processing generel required header files..."
AC_CHECK_HEADERS([malloc.h \
                  netdb.h \
                  stddef.h \
                  stdint.h \
                  stdlib.h \
                  string.h \
                  stdio.h \
                  pthread.h \
                  time.h \
                  math.h \
                  syslog.h \
                  unistd.h \
                  errno.h \
                  netinet/in.h \
                  arpa/inet.h \
                  sys/socket.h \
                  sys/types.h \
                  readline/chardefs.h \
                 ], [have_required_headers=yes], [have_required_headers=no])
if test "${have_required_headers}" = no; then
    AC_MSG_ERROR([
          --------------------------------------------------
          Not all required header files are found. See list
          above and make sure to install the header required
          header files. Some might be part of dev / devel 
          packages
          --------------------------------------------------])
fi



# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([localtime_r memset socket strchr strerror])

LIB_VER_INFO=$current:$revision:$age
VER_INFO=$current.$age.$revision

# Check the CFLAGS 
if test "$CFLAGS" = "-g -O2"; then
  CFLAGS="-g -O0 -Wall $CPU_ARCH_FLAG"
else
  CFLAGS="$CFLAGS $CPU_ARCH_FLAG"
fi

## 
## Check if unit tests have to be compiled in as well
##
AC_ARG_ENABLE(cunit-tests,
              [--enable-cunit-tests  add CUnit tests to be included],
              CUNIT_TESTS="tests", CUNIT_TESTS="")
if test "$CUNIT_TESTS" = "tests" ; then
  AC_MSG_NOTICE("Check if CUnit framework is installed!")
  AC_CHECK_HEADERS([CUnit/Basic.h], 
                   [], [
    AC_MSG_ERROR([
    ------------------------------------------------------------
    The CUnit library is required to build bgpsec-io with tests
    ------------------------------------------------------------
    ])
  ])
fi

# Check if crypto libraries will be dynamically or statically linked
AC_ARG_ENABLE(static-openssl,
              [--enable-static-openssl  enable openssl being linked statically],
              [OPENSSL_LIBS="-W1,-Bstatic -lssl -W1,-Bstatic -lcrypto"], 
              OPENSSL_LIBS="-lssl -lcrypto")


AM_CONDITIONAL([LIB_VER_INFO_COND], [test $LIB_VER_INFO])

dnl ----------
dnl Linux IPv6
dnl ----------
if test x`ls /proc/net/ipv6_route 2>/dev/null` = x"/proc/net/ipv6_route" ; then
  bgpsecio_ipv6=yes
  AC_MSG_RESULT(Linux IPv6)
fi

if test "$bgpsecio_ipv6" = "yes"; then
  AC_MSG_CHECKING(whether libc has IPv6 support)
  AC_TRY_LINK([#include <netinet/in.h>],[ int a; a = (int) in6addr_any.s6_addr[0]; if (a != 12345) return a; ],
              [AC_MSG_RESULT(yes)
               bgpsecio_ipv6=yes],
              [AC_MSG_RESULT(no)
               bgpsecio_ipv6=no])
fi

if test "$bgpsecio_ipv6" = "yes"; then
  AC_MSG_CHECKING(for GNU libc >= 2.1)
  AC_DEFINE(HAVE_IPV6,1,Linux IPv6)
fi
                                                                                                                                                                        
if test "$CUNIT_TESTS" = ""; then
  TESTMAKE=""
else
  TESTMAKE="$CUNIT_TESTS/Makefile"
fi

#Currenlty leave this out, the libraries are linked in the makefile.
# 
#LDFLAGS="${SCA_LDFLAGS} ${SCA_OPENSSL_LDFLAGS} ${OPENSSL_LIBS} ${LDFLAGS}"
#CFLAGS="${SCA_CFLAGS} ${OPENSSL_CFLAGS} ${CFLAGS}"

AC_SUBST(LIB_VER_INFO)
AC_SUBST(PKG_VER)
AC_SUBST(MAJOR_VER)
AC_SUBST(MINOR_VER)
AC_SUBST(UPD_VER)
AC_SUBST(PACKAGE_VERSION)
AC_SUBST(VER_INFO)
AC_SUBST(SCA_CFLAGS)
AC_SUBST(SCA_LDFLAGS)
AC_SUBST(OPENSSL_LIBS)
AC_SUBST(OPENSSL_LDFLAGS)
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(TESTMAKE)

AC_CONFIG_FILES([Makefile
                 antd-util/Makefile
                 $TESTMAKE
                 bgpsecio-$PACKAGE_VERSION.spec:bgpsecio.spec.in
                 ])

AC_OUTPUT

echo "Summary:"
echo "----------------------------------------------------------"
echo "Version......: $PACKAGE_VERSION"
echo "Configured...: AC_PACKAGE_NAME V AC_PACKAGE_VERSION"
echo "Library......: $VER_INFO ($LIB_VER_INFO)"
echo "CPU Arch.....: $CPU_ARCH"
echo "CFLAGS.......: $CFLAGS"
echo "LDFLAGS......: $LDFLAGS"
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
echo "SRxCryptoAPI Configuration:"
if test "x${sca_dir}" = "x"; then
  echo "  - Type.............: Use default install"
else
  echo "  - Type.............: Use custom install at '${sca_dir}'"
fi
echo "  - SCA_LDFLAGS......: $SCA_LDFLAGS"
echo "  - SCA_CFLAGS.......: $SCA_CFLAGS"
