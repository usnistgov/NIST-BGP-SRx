# SRX_M4_CHECK_LIBCONFIG does perfomr a library libconfig library check and 
# sets the variable LCONFIG_INT to the appropriate data type depending on the
# library installed.
#
# This function exports LCONFIG and HAVE_LIBCONFIG and modifies CFLAGS by adding
# the necesary LCONFIG type (-DLCONFIG=int or -DLCONFIG=long)
#
# SRX_M4_CHECK_LIBCONFIG()
#
AC_DEFUN([SRX_M4_CHECK_LIBCONFIG], [
  AC_SEARCH_LIBS([config_init], [config], [HAVE_LIBCONFIG=1], [HAVE_LIBCONFIG=0])

  if test "${HAVE_LIBCONFIG}" = "0"; then
    AC_MSG_ERROR([
    --------------------------------------------------
    The library 'libconfig' is required to build 
    srx_server.
    --------------------------------------------------])
  fi

  # Now specify which int type to use which depends on the library type.
  AC_MSG_CHECKING(for libconfig int type)
  /sbin/ldconfig -v 2>/dev/null | grep libconfig.so.8 > /dev/null
  if test "$?" = "0"; then      
    LCONFIG_INT=long
  else
    LCONFIG_INT=int
  fi
  CFLAGS="$CFLAGS -DLCONFIG_INT=$LCONFIG_INT"

  AC_MSG_RESULT($LCONFIG_INT)

  AC_SUBST(LCONFIG_INT)
  AC_SUBST(HAVE_LIBCONFIG)

]) # SRX_M4_CHECK_LIBCONFIG
