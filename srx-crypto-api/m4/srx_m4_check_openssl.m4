# Version 0.2.2
#  0.2.2 - 2020/05/21 - kyehwanl
#          * Fixed compilation issue with openssl include directory.
#  0.2.1 - 2018/04/14 - oborchert
#          * Added instructions if openssl could not be found.
#            ( Important for CentOS 7 )
#  0.2   - 2017/10/27 - oborchert
#          * Added .a library to OpenSSL check.
#  0.1   - 2017/09/22 - oborchert
#          * Moved location processing inside this macro
#        - 2017/09/20 - oborchert
#          * Created macro.
#
#
# Check the OpenSSL installation if it provides the required CURVES
# This macro adds the parameter --enable-static-openssl
#
# Syntax: SRX_M4_CHECK_OPENSSL([architecture], 
#                              [OPENSSL_LIBS], [OPENSSL_CFLAGS], [OPENSSL_LDFLAGS])
#
AC_DEFUN([SRX_M4_CHECK_OPENSSL], [
  AS_BOX([Process OPENSSL Setup])
  AC_ARG_VAR(openssl_dir, Provide a different openssl directory as the default one)

  # initialize the helper variables
  srx_m4_libs=
  srx_m4_cflags=
  srx_m4_ldflags=

  # Check if crypto libraries will be dynamically or statically linked
  AC_ARG_ENABLE(static-openssl,
              [  --enable-static-openssl enable openssl being linked statically],
              [srx_m4_libs_type="-W,-Bstatic "], [srx_m4_libs_type=])

  AC_MSG_CHECKING([type of openssl installation to be used])
  if test "x$openssl_dir" = "x"; then
    AC_MSG_RESULT([default])    
    srx_m4_openssl_dir=$(which openssl 2>/dev/null | sed -e "s/\(.*\)\/bin\/openssl/\1/g")
    if test "x$srx_m4_openssl_dir" = "x"; then
      srx_m4_openssl_dir="/usr/"
      AC_MSG_RESULT([ using default directory /usr ])
    fi

  else
    AC_MSG_RESULT([custom])
    srx_m4_openssl_dir=$openssl_dir
  fi

  # Check the architecture
  srx_m4_arch=
  if test "x$1" != "x"; then
    if test "x$openssl_dir" = "x"; then
      srx_m4_arch=$1
    else
      AC_MSG_NOTICE([Ignore the system architecture in library path for customized OpenSSL install])
    fi
  fi

  # Set the OpenSSL libraries to be searched for
  srx_m4_check_libs="crypto ssl"
  srx_m4_libPath=$srx_m4_openssl_dir/lib$srx_m4_arch/

  # Search for each required OpenSSL library
  for srx_m4_libName in $srx_m4_check_libs; do

    AC_MSG_CHECKING([for library $srx_m4_libName])

    if test "x$openssl_dir" = "x"; then
      #
      # Default installation
      #
      srx_m4_libPath=$(/sbin/ldconfig -p | grep lib$srx_m4_libName.so$ | sed -e "s/.* => \(.*\)lib\(.*\)/\1/g")
      if test "x$srx_m4_libPath" = "x"; then  
        AC_MSG_RESULT([not found])
        AC_MSG_ERROR([
    --------------------------------------------------
    No OpenSSL installation found or incomplete!
    - install openssl, openssl-devel, openssl-libs
    - or/and call /sbin/ldconfig as root and try again
    --------------------------------------------------])
      fi
      AC_MSG_RESULT([-l$srx_m4_libName])
    else
      #
      # Custom installation
      #
      if test -e $srx_m4_libPath/lib$srx_m4_libName.so; then    
        AC_MSG_RESULT([-l$srx_m4_libName])
        srx_m4_cflags="-I${srx_m4_openssl_dir}/include"
        srx_m4_ldflags="-L${srx_m4_libPath}"
        # libs will be set below in general section
      else
          AC_MSG_RESULT([not found])          
        if test -e $srx_m4_libPath/lib$srx_m4_libName.a; then
          AC_MSG_ERROR([
    ---------------------------------------------------
    Custom OpenSSL must be configured as shared library
    (config shared ....) to generate lib$srx_m4_libName.so!
    ---------------------------------------------------])
        fi
          AC_MSG_ERROR([
    --------------------------------------------------
    Library $srx_m4_libName required!
    --------------------------------------------------])
        fi
    fi

    # Add the library - cflags and ldflags are set in custom section
    srx_m4_libs="$srx_m4_libs$srx_m4_libs_type-l$srx_m4_libName "
  done
  
  # Test for OPENSSL Curve availability
  AC_MSG_CHECKING([for openssl curve prime256v1])
  srx_m4_curve_test=$($srx_m4_openssl_dir/bin/openssl ecparam -list_curves 2>/dev/null | grep prime256v1 | sed -e "s/\(prime256v1\):.*/-\1-/g" | sed -e "s/ //g")
  if test "${srx_m4_curve_test}" = "-prime256v1-"; then
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([
    --------------------------------------------------
    ECDSA curve prime256v1 not supported by selected 
    OpenSSL implementation.
    --------------------------------------------------])
  fi

  echo Test for header files

  AC_CHECK_HEADERS([$srx_m4_openssl_dir/include/openssl/crypto.h \
                    $srx_m4_openssl_dir/include/openssl/bio.h \
                    $srx_m4_openssl_dir/include/openssl/sha.h \
                    $srx_m4_openssl_dir/include/openssl/ec.h \
                    $srx_m4_openssl_dir/include/openssl/ecdsa.h \
                    $srx_m4_openssl_dir/include/openssl/err.h], 
                   [], [ AC_MSG_ERROR([
    --------------------------------------------------
    One or more required OpenSSL header file(s) could 
    not be located.
    --------------------------------------------------]) ])

  # Check for libs var
  if test "x$2" = "x"; then
    LIBS="$srx_m4_libs ${LIBS}"
  else
    $2="$srx_m4_libs"
  fi

  # test for cflags var
  if test "x$3" = "x"; then
    CFLAGS="$srx_m4_cflags ${CFLAGS}"
  else
    $3="$srx_m4_cflags"
  fi

  # test for ldflags var
  if test "x$4" = "x"; then
    LDFLAGS="$srx_m4_ldflags ${LDFLAGS}"
  else
    $4="$srx_m4_ldflags"
  fi

  # initialize the helper variables
  srx_m4_libs=
  srx_m4_cflags=
  srx_m4_ldflags=
])
