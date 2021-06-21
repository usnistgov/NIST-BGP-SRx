# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([SRx], [0.5.1.2], [bgpsrx-dev@nist.gov], [srx], [https://bgpsrx.antd.nist.gov])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_MAKE_SET
AC_CHECK_PROG([PATCH], [patch], [yes], [no])
if ( test "x${PATCH}" == "xno" ) ; then
  AC_MSG_ERROR([
    --------------------------------------------------
       The 'patch' tool is required for compilation 
       of the source in the the extras folder
       on CENTOS 'yum insall patch'
    --------------------------------------------------])
fi
LT_PREREQ([2.2])
LT_INIT([dlopen])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SUBDIRS([src])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
