# SRX_M4_CHECK_LIB replaces the AC_CHECK_LIB which seems to have issues 
# detecting SRx generated libraries.
#
# SRX_M4_CHECK_LIB([library name], [version], [result_val], [4], [5])
#
# The macro uses ldconfig -p to search for the library <library name>. 
# If the library is installed properly, the variable <result_val> will be set to
# "yes", otherwise to "no".
#
# Valiables 2, 4, and 5 are optional and if not set the default variables are
# used.
#
# 2: The version. If not set it will not be used.
# 4: The LDFLAGS variable are a specified replacement
# 5: The LIBS variable or a specified replacement
#
# Example 1:
#
# SRX_M4_CHECK_LIB([SRxCryptoAPI], , [have_sca], [SCA_LIB], [SCA_LDCONFIG])
#
# Result if installed using yum on a 64 bit machine:
#   have_sca="yes"
#   SCA_LIB="-lSRxCryptoAPI ${SCA_LIB}"
#   SCA_LDCONFIG="-L/usr/lib64/srx ${SCA_LDCONFIG}"
#
# Example 2:
#
# SRX_M4_CHECK_LIB([SRxCryptoAPI], , [have_sca])
#
# Result if installed using yum on a 64 bit machine:
#   have_sca="yes"
#   LIBS="-lSRxCryptoAPI ${LIBS}"
#   LD_CONFIG="-L/usr/lib64/srx ${LD_CONFIG}"
#
# If not found:
#   have_sca="no"
# 
# Version 0.1
#  0.1 - 2017/09/18 - oborchert
#        * Changed the finding procedure from only finding to finding and 
#          retrieving the library path.
#        * Added documentation.
#      - 2017/09/14 - oborchert
#        * Created macro.
#
AC_DEFUN([SRX_M4_CHECK_LIB], [

  # check if a particular version is requested.
  if test "x$2" = "x"; then
    libExt=.so
    lib_version=
  else
    libExt=.so.$2
    lib_version=" V$2"
  fi

  AC_MSG_CHECKING([for library lib$1${lib_version}])

  srx_m4_lib_$1="no"
  if test "x$1" = "x"; then
    AC_MSG_ERROR([library name not missing])
  fi

  libpath=$(/sbin/ldconfig -p | grep lib$1${libExt}$ | sed -e "s/.* => \(.*\)lib\(.*\)/\1/g")

  # Check if the path was found
  if test "x$libpath" != "x"; then  
    HAVE_LIB$1=1
    AC_SUBST(HAVE_LIB$1)
    srx_m4_lib_$1="yes"

    if test "x$4" = "x"; then
      LDFLAGS="-L${libpath} ${LDFLAGS}"
    else
      $4="-L${srx_libpath}"
    fi

    if test "x$5" = "x"; then
      LIBS="-l$1 ${LIBS}"
    else
      $5="-l$1"
    fi
  fi

  AC_MSG_RESULT([${srx_m4_lib_$1}])

  if test "x$3" != "x"; then
    $3=${srx_m4_lib_$1}
  fi
]) # SRX_M4_CHECK_LIB


#
# Syntax: SRX_M4_CHECK_SRXLIB([<libname>], [version], [header-file(s)], 
#                             [architecture], [location],
#                             [libs-var], [cflags-var], [ldflags-var])
#
# 
AC_DEFUN([SRX_M4_CHECK_SRXLIB], [
  # initialize the helper variables
  srx_m4_libs=
  srx_m4_cflags=
  srx_m4_ldflags=

  # test library name
  if test "x$1" = "x"; then
    AC_MSG_ERROR([library name missing])
  else
    srx_m4_libName=$1
  fi 
  AS_BOX([Process library $srx_m4_libName])
   
  # test for version install
  if test "x$2" = "x"; then
    srx_m4_version=
    srx_m4_libExt=".so"
  else
    srx_m4_version=" V$2"
    srx_m4_libExt=".so.$2"
  fi

  # test for header file
  if test "x$3" = "x"; then
    srx_m4_headerFiles=
  else
    srx_m4_headerFiles="$3"
  fi 

  # test for architecture
  if test "x$4" = "x"; then
    srx_m4_arc=
  else
    srx_m4_arc=$4
  fi

  # test for specified location
  if test "x$5" = "x"; then
    srx_m4_location=
  else
    srx_m4_location=$5
    AC_MSG_CHECKING([for custom $srx_m4_libName location])
    if test ! -e $srx_m4_location; then
      AC_MSG_RESULT([not available])
      AC_MSG_ERROR([Location $srx_m4_location not found!]) 
    fi     
    AC_MSG_RESULT([available])
  fi

  #  Now start looking for the library
  srx_m4_cflags=
  srx_m4_ldflags=
  srx_m4_libs=

  AC_MSG_CHECKING([for library $srx_m4_libName$srx_m4_version])
               
  # test for specified location
  if test "x$srx_m4_location" != "x"; then
    # 
    # Check for local custom installed library
    # 
    if test -e $srx_m4_location/lib$srx_m4_arc/srx/lib$srx_m4_libName$srx_m4_libExt ; then
      AC_MSG_RESULT([-l$srx_m4_libName])
      srx_m4_libs="-l$srx_m4_libName"
      srx_m4_ldflags="-L$srx_m4_location/lib$srx_m4_arc/srx"
    else
      AC_MSG_RESULT([not found])
      AC_MSG_ERROR([
     --------------------------------------------------
     Custom library $srx_m4_libName not found.
     --------------------------------------------------])    
    fi
  else
    # 
    #  Check for rpm installed library
    # 
    srx_m4_libPath=$(/sbin/ldconfig -p | grep lib$srx_m4_libName$srx_m4_libExt$ | sed -e "s/.* => \(.*\)\\/lib\(.*\)/\1/g")

    # Check if the path was found
    if test "x$srx_m4_libPath" != "x"; then  
      srx_m4_ldflags="-L$srx_m4_libPath"
      srx_m4_libs="-l$srx_m4_libName"
    else
      AC_MSG_RESULT([not found])
      AC_MSG_ERROR([
     ------------------------------------------------------------
     Library $srx_m4_libName$srx_m4_version (lib$srx_m4_libName$srx_m4_libExt) not found.
     ------------------------------------------------------------])
    fi
    AC_MSG_RESULT([-l$srx_m4_libName])
  fi

  # now checking for header files
  if test "x$srx_m4_headerFiles" != "x"; then
    if test "x$srx_m4_location" = "x"; then
      hdr_file_loc=
    else
      srx_m4_cflags="-I$srx_m4_location/include"
      hdr_file_loc="$srx_m4_location/include/"
    fi

    for headerFile in $srx_m4_headerFiles; do
      AC_CHECK_HEADERS([$hdr_file_loc$headerFile], [], [ AC_MSG_ERROR([
     --------------------------------------------------
     Required header file "$hdr_file_loc$headerFile" not found.
     --------------------------------------------------])
      ])
    done
  fi

  # test for libs var
  srx_m4_do_add="yes"
  if test "x$6" = "x"; then
    for srx_m4_lib in $LIBS; do
      if test "x$srx_m4_lib" = "x$srx_m4_libs" ; then
        srx_m4_do_add=no
      fi
    done
    if test "$srx_m4_do_add" = "yes"; then
      LIBS="${srx_m4_libs} ${LIBS}"
    fi
  else
    $6="${srx_m4_libs}"
  fi

  # test for cflags var
  srx_m4_do_add="yes"
  if test "x$7" = "x"; then
    for srx_m4_flag in $CFLAGS; do
      if test "x$srx_m4_flag" = "x$srx_m4_cflags" ; then
        srx_m4_do_add=no
      fi
    done
    if test "$srx_m4_do_add" = "yes"; then
      CFLAGS="${srx_m4_cflags} ${CFLAGS}"
    fi
  else
    $7="${srx_m4_cflags}"
  fi

  # test for ldflags var
  srx_m4_do_add="yes"
  if test "x$8" = "x"; then
    for srx_m4_ldflag in $LDFLAGS; do
      if test "x$srx_m4_ldflag" = "x$srx_m4_ldflags" ; then
        srx_m4_do_add=no
      fi
    done
    if test "$srx_m4_do_add" = "yes"; then
      LDFLAGS="${srx_m4_ldflags} ${LDFLAGS}"
    fi
  else
    $8="${srx_m4_ldflags}"
  fi

  # initialize the helper variables
  srx_m4_libs=
  srx_m4_cflags=
  srx_m4_ldflags=
  srx_m4_do_add=

  AC_SUBST([HAVE_LIB$1], [1])
])
