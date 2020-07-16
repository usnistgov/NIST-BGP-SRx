# Version 0.1
#  0.1 - 2017/09/21 - oborchert
#        * Created macro.
#
#
# This macro determines the CPU architecture and sets the appropriate variables
#
# Syntax: SRX_M4_CHECK_ARCH([CPU_ARCH], [CPU_ARCH_FLAG], [FLAG_PREFIX])
#
AC_DEFUN([SRX_M4_CHECK_ARCH], [
  AS_BOX([Determine CPU])

  AC_MSG_CHECKING([host architecture information])
  if test "$HOSTTYPE" = "x86_64-linux"; then
    AC_MSG_RESULT([64 bit])
    srx_m4_arch="64"
  else 
    if test "$HOSTTYPE" = "x86_64"; then
      AC_MSG_RESULT([64 bit])
      srx_m4_arch="64"
    else
      AC_MSG_RESULT([default])
      srx_m4_arch=""
    fi
  fi

  if test "x$1" = "x"; then
    CPU_ARCH=$srx_m4_arch
  else
    $1=$srx_m4_arch
  fi

  # Set a default prefix for the CPU flag
  if test "x$3" = "x"; then
    srx_m4_cpu_arch_prefix="CPU_#3"
  else
    srx_m4_cpu_arch_prefix=$3
  fi

  # Create a flag value -D....
  if test "x$2" = "x"; then
    CPU_ARCH_FLAG="-D$srx_m4_cpu_arch_prefix$srx_m4_arch"
  else
    $2="-D$srx_m4_cpu_arch_prefix$srx_m4_arch"
  fi
])