# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([SRx], [0.3.0.1], [bgpsrx-dev@nist.gov])
# The -Wno=portability is needed for the $(shell...) GNU extension.
# If this is a problem remove the $(shell...) extension in Makefile_Common. 
AM_INIT_AUTOMAKE([-Wall -Werror -Wno-portability])
LT_PREREQ([2.2])
LT_INIT([dlopen])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([server/command_queue.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_MAKE_SET
AM_PROG_CC_C_O

# Platform specific setup
AC_CANONICAL_HOST
case $host_os in
    darwin*)
	# Do something specific for mac
	;;
    linux*)
	# Do something specific for linux
	;;
    *BSD*)
	# Do something specific for BSD
	;;
    *)
	# Default case
	AC_MSG_ERROR([Your platform is not currently supported])
	;;
esac

# Checks for command-line options
AC_ARG_ENABLE([libpatricia-inst], 
	      [AS_HELP_STRING([--disable-libpatricia-inst],
		      [disable libpatricia install feature @<:@default: no@:>@])],
	      [libpatricia_inst=${enableval}], [libpatricia_inst=yes])

AC_ARG_WITH([libpatr],
	    [AS_HELP_STRING([--with-libpatr],
			    [use the internal patricia library package])], 
	    [var_libpatr=yes], [var_libpatr=no])


AC_ARG_WITH([libconf],
	    [AS_HELP_STRING([--with-libconf],
			    [use the internal libconfig library package])],
	    [var_libconf=yes], [var_libconf=no])


AC_ARG_WITH([libncur],
	    [AS_HELP_STRING([--with-libncur],
			    [use the internal ncurses library package])],
	    [var_libncur=yes], [var_libncur=no])

AC_ARG_WITH([libread],
	    [AS_HELP_STRING([--with-libread],
			    [use the internal readline library package])],
	    [var_libread=yes], [var_libread=no])



# Checks for libraries.
have_config=no
AC_SEARCH_LIBS([config_read_file], [config], [have_config=yes])
if test "x${have_config}" = xno; then
    if test "x${var_libconf}" = xno; then
      AC_MSG_WARN([
	--------------------------------------------------
	The config library required to build srx_server.
	Stopping...
	Check 'config.log' for more information.

	Use '--with--libconf' to be enable to install.
	--------------------------------------------------])
    fi

    if test "x${var_libconf}" = xyes; then
	AC_MSG_CHECKING([--srx-- using the extra library dir libconfig])
	AC_MSG_RESULT([$var_libconf])
	SRX_M4_CHECK_INTERNAL_LIB_CONFIG
    fi
fi

# FIXME: Replace `main' with a function in `-ldl':
AC_CHECK_LIB([dl], [main])


have_ncurses=no
# FIXME: Replace `main' with a function in `-lncurses':
AC_CHECK_LIB([ncurses], [main], [have_ncurses=yes])
if test "x${have_ncurses}" = xno; then
    if test "x${var_libncur}" = xno; then
	AC_MSG_WARN([
	--------------------------------------------------
	The ncurses library required to build srx_server.
	Check 'config.log' for more information.

	use '--with-libncur' to be enable to install
	--------------------------------------------------])
    fi

    if test "x${var_libncur}" = xyes; then
	AC_MSG_CHECKING([--srx-- using the extra library dir and installing libncurses ])
	AC_MSG_RESULT([$var_libncur])
	SRX_M4_CHECK_INTERNAL_LIB_NCURSES
    fi
fi

have_patricia=no
# FIXME: Replace `main' with a function in `-lpatricia':
AC_CHECK_LIB([patricia], [main], [have_patricia=yes])
if test "x${have_patricia}" = xno; then
    #if test "x${libpatricia_inst}" = xyes; then
    if test "x${var_libpatr}" = xno; then
	AC_MSG_ERROR([
        --------------------------------------------------
	The patricia library required to build srx_server.
	Stopping...
	Check 'config.log' for more information.

	Use '--with-libpatr' to be enable to install.
	--------------------------------------------------])
    fi

    if test "x${var_libpatr}" = xyes; then
	AC_MSG_CHECKING([--srx-- using the extra library dir and installing libpatricia])
	AC_MSG_RESULT([$libpatricia_inst $var_libpatr])
	SRX_M4_CHECK_INTERNAL_LIB_PATRICIA
    else
	AC_MSG_RESULT([nothing else])
    fi
    libpatricia_inst=no
fi

have_pthreads=no
AC_SEARCH_LIBS([pthread_create], [pthread], [have_pthreads=yes])
if test "x${have_pthreads}" = xyes; then
    AC_CHECK_HEADERS([pthread.h], [], [have_pthreads=no])
    if test "x${have_pthreads}" = xyes; then
	AC_DEFINE([_REENTRANT],, pthread reentrant nature)
    fi
fi

if test "x${have_pthreads}" = xno; then
    AC_MSG_ERROR([
    --------------------------------------------------
    The pthread library and header file required to 
    build srx.  Stopping...
    Check 'config.log' for more information.
    --------------------------------------------------])
fi


have_readline=no
# FIXME: Replace `main' with a function in `-lreadline':
AC_CHECK_LIB([readline], [main], [have_readline=yes])
if test "x${have_readline}" = xno; then
    if test "x${var_libread}" = xno; then
    AC_MSG_WARN([
    --------------------------------------------------
    The readline library required to build srx_server.
    Check 'config.log' for more information.

	use '--with-libread' to be enable to install
    --------------------------------------------------])
fi

    if test "x${var_libread}" = xyes; then
	AC_MSG_CHECKING([--srx-- using the extra library dir and installing libreadline ])
	AC_MSG_RESULT([$var_libread])
	SRX_M4_CHECK_INTERNAL_LIB_READLINE
    fi
#    AC_MSG_FAILURE([readline failure test] )
fi


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Create automake conditional variables
#AM_CONDITIONAL([OS_TYPE], [`uname -s`])

AC_SUBST([SRX_REVISION_FILE],[srx-server-rev.txt])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([bzero gethostbyname memset socket strchr strrchr strdup strerror strtol strtoul])

AC_CONFIG_FILES([Makefile
		 shared/Makefile
		 util/Makefile
     client/Makefile
     server/Makefile
		 tools/Makefile])
AC_OUTPUT

echo "
  SRx Server and Proxy Library ($PACKAGE_NAME) version $PACKAGE_VERSION
  Prefix/Install.: $prefix
  Debug Build....: $debug
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  C++ Compiler...: $CXX $CXXFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
  SRx Library....: ${SRXLIB:-INSTALLED}
  SRx Include....: ${SRXINC:-INSTALLED}
  Doxygen........: ${DOXYGEN:-NONE}
"
