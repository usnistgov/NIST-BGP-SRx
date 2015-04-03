#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([SRxCryptoAPI], [0.1.1.1], [bgpsrx-dev@nist.gov])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])

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

# library information versioning
# Extract Version numbers from AC_INIT above
PKG_VER=`echo AC_PACKAGE_VERSION | cut -d . -f 1`
MAJOR_VER=`echo AC_PACKAGE_VERSION | cut -d . -f 2`
MINOR_VER=`echo AC_PACKAGE_VERSION | cut -d . -f 3`
UPD_VER=`echo AC_PACKAGE_VERSION | cut -d . -f 4`
PACKAGE_VERSION=AC_PACKAGE_VERSION

current=$MAJOR_VER
revision=$MINOR_VER
age=0

dnl echo "PKG_VER=$PKG_VER" 
dnl echo "MAJOR_VER=$MAJOR_VER" 
dnl echo "MINOR_VER=$MINOR_VER" 
dnl echo "UPD_VER=$UPD_VER" 
dnl echo "PACKAGE_VERSION=$PACKAGE_VERSION"
dnl echo "current=$current"

dnl echo "revision=$revision" 
dnl echo "age=$age" 

# Check for OPENSSL Parameter
AC_ARG_VAR(openssl_dir, Provide a different openssl directory as the default one)

if test "x${openssl_dir}" = "x"; then
  echo "Use default OPENSSL Installation"
  OPENSSL_CFLAGS=""
  OPENSSL_BIO_H="openssl/bio.h"
  OPENSSL_LDFLAGS=""
  OPENSSL_CURVE_TEST=$(openssl ecparam -list_curves | grep prime256v1 | sed -e "s/\(prime256v1\):.*/-\1-/g" | sed -e "s/ //g")
else
  echo "Use custom OPENSSL Installation at '${openssl_dir}'"
  OPENSSL_BIO_H="${openssl_dir}/include/openssl/bio.h"
  OPENSSL_CFLAGS="-I${openssl_dir}/include"
  OPENSSL_LDFLAGS="-L${openssl_dir}/lib"
  OPENSSL_CURVE_TEST=$(${openssl_dir}/bin/openssl ecparam -list_curves | grep prime256v1 | sed -e "s/\(prime256v1\):.*/-\1-/g" | sed -e "s/ //g")
fi

# Test for OPENSSL Curve availability
if test "${OPENSSL_CURVE_TEST}" = "-prime256v1-"; then
  echo "checking for openssl curve prime256v1... yes"
else
  echo "checking for openssl curve prime256v1... no"
  AC_ERROR([ECDSA curve prime256v1 not found with selected OpenSSL implementation.])
fi

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_INSTALL

# Checks for libraries.
have_config=no
AC_SEARCH_LIBS([lt_dlopen], [ltdl])
AC_SEARCH_LIBS([config_init], [config], [have_config=yes])
if test "x${have_config}" = xno; then
  AC_MSG_ERROR([
    -----------------------------------------------------------
    The config library is required to build AC_PACKAGE_NAME.
    Stopping...
    Check 'config.log' for more information.

      Please install first the libraries:
          - libconfig
          - libconfig-devel
    -----------------------------------------------------------])
fi

# ADD check openssl library here as long as we use BIO_snprintf


# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h sys/param.h ltdl.h])
AC_CHECK_HEADER([$OPENSSL_BIO_H], [], 
  [AC_MSG_ERROR([
    -----------------------------------------------------------
    OpenSSL header files are required to build AC_PACKAGE_NAME.
    Stopping...

      Please install first the libraries :
          - openssl-devel
      or 
        configure using openssl_dir="path to openssl"
    -----------------------------------------------------------])
  ])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])


# Add Debugging Memory checking.
AC_ARG_ENABLE(mcheck,
              [--enable-mcheck  enable memory check M_CHECK_ACTION 3],
              MCHECK="-DMEM_CHECK", MCHECK="")
AC_SUBST(MCHECK)



# Add Modules
AC_ARG_ENABLE(bgpsec-openssl,
              [--enable-bgpsec-openssl  enable bgpsec openssl crypto implementationl],
              BGPSEC_OPENSSL="bgpsec_openssl", BGPSEC_OPENSSL="")

AC_ARG_ENABLE(testlib,
              [--enable-testlib  enable crypto test implementationl],
              CRYPTO_TESTLIB="crypto_testlib", CRYPTO_TESTLIB="")

# Determine if it is 64 or 32 bit architecture
case "$HOSTTYPE" in
  x86_64) 
     CPU_ARCH_FLAG="-DCPU_64"
     CPU_ARCH="64"
     ;;
  *) 
     CPU_ARCH_FLAG=""
     CPU_ARCH="32"
     ;;
esac

LIB_VER_INFO=$current:$revision:$age
VER_INFO=$current.$age.$revision

# Check the CFLAGS 
if test "$CFLAGS" = "-g -O2"; then
 CFLAGS="-g -O0 -Wall $CPU_ARCH_FLAG"
else
 CFLAGS="$CFLAGS $CPU_ARCH_FLAG"
fi

# Check if crypto libraries will be dynamically or statically linked
AC_ARG_ENABLE(static-openssl,
              [--enable-static-openssl  enable openssl being linked statically],
              CRYPTO_STATIC="yes", CRYPTO_STATIC="")

if test "x$CRYPTO_STATIC" = "xyes" ; then
  OPENSSL_LIBS="-W1,-Bstatic -lssl -W1,-Bstatic -lcrypto"
else
  OPENSSL_LIBS="-lssl -lcrypto"
fi

AM_CONDITIONAL([LIB_VER_INFO_COND], [test $LIB_VER_INFO])
AM_CONDITIONAL([BGPSEC_OPENSSL_COND], [test "x$BGPSEC_OPENSSL" = xbgpsec_openssl])


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

AC_CONFIG_FILES([Makefile 
                 srxcryptoapi-$PACKAGE_VERSION.spec:srxcryptoapi.spec.in
                 bgpsec_openssl/Makefile crypto_testlib/Makefile])
AC_OUTPUT

echo "Summary:"
echo "----------------------------------------------------------"
echo "Version......: $PACKAGE_VERSION"
echo "Configured...: AC_PACKAGE_NAME V AC_PACKAGE_VERSION"
echo "Library......: $VER_INFO ($LIB_VER_INFO)"
echo "CPU Arch.....: $CPU_ARCH"
echo "CFLAGS.......: $CFLAGS"
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
