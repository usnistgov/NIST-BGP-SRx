#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([bgpsecio], [0.2.1.3], [bgpsrx-dev@nist.gov])
AM_INIT_AUTOMAKE([-Wall -Werror -Wno-portability subdir-objects])

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

# IMPORTANT = This variable if, set requires a particular SCA version for 
#             compilation. If a rance is expeced 2..3 then the value needs to 
#             be valid regular expression code [2|3] for example.
#             This does not have any affect on the sca_dir installed library
REQ_SCA_VER=3

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
AC_PROG_LIBTOOL

#
# Check for CPU
#
#CPU_ARCH=
SRX_M4_CHECK_ARCH([CPU_ARCH], [CPU_ARCH_FLAG], [CPU_])
if test "x$CPU_ARCH" != "x"; then
    AC_MSG_NOTICE([Configure libdir parameter for $CPU_ARCH bit architecture])
    if test "${libdir}" = "\${exec_prefix}/lib" ; then
      libdir="${libdir}$CPU_ARCH"
    fi
fi

# Add Debugging Memory checking.
AC_MSG_CHECKING(weather to enable mcheck)
AC_ARG_ENABLE(mcheck,
              [  --enable-mcheck  enable memory check M_CHECK_ACTION 3],
              MCHECK="-DMEM_CHECK", MCHECK="")
if test "$MCHECK" == "" ; then
  AC_MSG_RESULT([no])
else
  AC_MSG_RESULT([yes])
  CFLAGS="$CFLAGS $MCHECK"
  AC_SUBST(MCHECK)
fi

# Add Test Vector output
AC_MSG_CHECKING(weather to enable testvector)
AC_ARG_ENABLE(testvector,
              [  --enable-testvector     enable test vector output CREATE_TESTVECTOR],
              CREATE_TESTVECTOR="-DCREATE_TESTVECTOR", CREATE_TESTVECTOR="")
if test "$CREATE_TESTVECTOR" == "" ; then
  AC_MSG_RESULT([no])
else
  AC_MSG_RESULT([yes])
  CFLAGS="$CFLAGS $CREATE_TESTVECTOR"
  AC_SUBST(CREATE_TESTVECTOR)
fi

# Add Test Vector output
AC_MSG_CHECKING(weather to enable printcrypto)
AC_ARG_ENABLE(printcrypto,
              [  --enable-printcrypto    enable crypto debug],
              PRINT_CRYPTO="-DPRINT_CRYPTO", PRINT_CRYPTO="")
if test "$PRINT_CRYPTO" == "" ; then
  AC_MSG_RESULT([no])
else
  AC_MSG_RESULT([yes])
  CFLAGS="$CFLAGS $PRINT_CRYPTO"
  AC_SUBST(PRINT_CRYPTO)
fi

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
SRX_M4_CHECK_LIBCONFIG()

##
## CHECK FOR SRxCrytpoAPI
##
SCA_LIBS=
SCA_CFLAGS=
SCA_LDFLAGS=
AC_ARG_VAR(sca_dir, Provide a different directory where SRxCryptoAPI is installed in)
SRX_M4_CHECK_SRXLIB([SRxCryptoAPI], [$REQ_SCA_VER], [srx/srxcryptoapi.h], 
                    $CPU_ARCH, $sca_dir, SCA_LIBS, SCA_CFLAGS, SCA_LDFLAGS)

## 
## Check for OPENSSL Parameter
##
SRX_M4_CHECK_OPENSSL($CPU_ARCH, OPENSSL_LIBS, OPENSSL_CFLAGS, OPENSSL_LDFLAGS)

#
# General checks for header files.
#
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
              [  --enable-cunit-tests    add CUnit tests to be included],
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
AC_SUBST(OPENSSL_LIBS)
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LDFLAGS)
AC_SUBST(SCA_LIBS)
AC_SUBST(SCA_CFLAGS)
AC_SUBST(SCA_LDFLAGS)
AC_SUBST(CPU_ARCH)
AC_SUBST(CPU_ARCH_FLAG)
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
echo "LIBS.........: $LIBS"
echo "LDFLAGS......: $LDFLAGS"
echo "CFLAGS.......: $CFLAGS"
echo "LCONFIG_INT..: $LCONFIG_INT"
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
echo "  - SCA_LIBS.........: $SCA_LIBS"
echo "  - SCA_LDFLAGS......: $SCA_LDFLAGS"
echo "  - SCA_CFLAGS.......: $SCA_CFLAGS"
