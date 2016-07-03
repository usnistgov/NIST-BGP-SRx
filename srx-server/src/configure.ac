# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([SRx], [0.4.0.1], [bgpsrx-dev@nist.gov])
# The -Wno=portability is needed for the $(shell...) GNU extension.
# If this is a problem remove the $(shell...) extension in Makefile_Common. 
AM_INIT_AUTOMAKE([-Wall -Werror -Wno-portability])
LT_PREREQ([2.2])
LT_INIT([dlopen])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([server/command_queue.h])
AC_CONFIG_HEADERS([config.h])

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

LIB_VER_INFO=$current:$revision:$age
VER_INFO=$current.$age.$revision


# Determine if it is 64 Bit. This is needed for the ld.conf.d. file.
case "$HOSTTYPE" in
  x86_64) 
    AC_SUBST([CPU_ARCH],[-x86_64])
    AC_SUBST([LD_ARCH_LOC],[64])
    ;;
  *) 
    AC_SUBST([CPU_ARCH],[]) 
    AC_SUBST([LD_ARCH_LOC],[])
    ;;
esac
if test "${libdir}" = "\${exec_prefix}/lib" ; then
  libdir="${libdir}$LD_ARCH_LOC"
fi

# Checks for programs.
AS_BOX(Verifying required programs)
AC_PROG_CC
AC_PROG_CXX
AC_PROG_MAKE_SET
AM_PROG_CC_C_O
AC_MSG_CHECKING(for cat installation)
which cat >/dev/null 2>&1
if test $? -eq 0 ; then
  AC_MSG_RESULT([yes])
else
  AC_MSG_RESULT([no])
  AC_MSG_ERROR([
	--------------------------------------------------
	No 'cat' installation found!
	--------------------------------------------------])
fi
AC_MSG_CHECKING(for sed installation)
which sed >/dev/null 2>&1
if test $? -eq 0 ; then
  AC_MSG_RESULT([yes])
else
  AC_MSG_RESULT([no])
  AC_MSG_ERROR([
	--------------------------------------------------
	No 'sed' installation found!
	--------------------------------------------------])
fi

# Platform specific setup
AS_BOX(Checking platform specific setup)
AC_CANONICAL_HOST
case $host_os in
    darwin*)
	# Do something specific for mac
	;;
    linux*)
	# Do something specific for linux
    #CFLAGS="-O0 -g -Wall"
	;;
    *BSD*)
	# Do something specific for BSD
	;;
    *)
	# Default case
	AC_MSG_ERROR([Your platform is not currently supported])
	;;
esac

AC_MSG_CHECKING([whether SRxCryptoAPI is already required for this version of ${PACKAGE_NAME}])
CMPV="0.4.0"
AS_VERSION_COMPARE(${PACKAGE_VERSION}, ${CMPV}, [include_sca=no], 
                   [include_sca=yes], [include_sca=yes])
AC_MSG_RESULT([${include_sca}])

#
# Check if .la and .a libraries should be added to RPM distribution
#
AC_MSG_CHECKING([whether .a and .la libraries will be added to rpm distribution])
AC_ARG_WITH(la-lib,
            [  --with-la-lib           add installation/distribution of .la/.a libraries in RPM generation],
            [incl_la_lib=${withval}], [incl_la_lib="no"])
AC_MSG_RESULT([${incl_la_lib}])
AC_SUBST(incl_la_lib)

#
# Checks for variables
#
AS_BOX(Processing customized variables)

#
# argument 'sca_dir=<path>' - Depending on the version >= 0.4.0 
#
if test "${include_sca}" = "yes" ; then
  AC_SUBST([LIB_SCA], ["-lSRxCryptoAPI"], [""])

  AC_MSG_CHECKING([whether argument 'sca_dir' is provided])
  AC_ARG_VAR(sca_dir, Use library libSRxCryptoAPI from a customized location)
  if test "x${sca_dir}" = "x" ; then
    AC_MSG_RESULT([no])
  else
    AC_MSG_RESULT([yes])
    if test -d ${sca_dir} ; then
      AC_MSG_NOTICE(Using customized SRxCryptoAPI installation in '${sca_dir}')
      AC_SUBST([LIB_SCA_LDFLAGS], ["-L${sca_dir}/lib$LD_ARCH_LOC"], [""])
      CFLAGS="-I${sca_dir} $CFLAGS"
    else
      AC_MSG_ERROR([
	--------------------------------------------------
	Directory 'sca_dir=${sca_dir}' not found!
	--------------------------------------------------])
    fi
  fi
fi
AC_SUBST([SCA_DIR], [${sca_dir}])

#
# argument 'patricia_dir=<path>'
#
AC_MSG_CHECKING([whether argument 'patricia_dir' is provided])
AC_ARG_VAR(patricia_dir, Use library libpatricia from a customized location) 
if test "x${patricia_dir}" = "x" ; then
  AC_MSG_RESULT([no])
else
  AC_MSG_RESULT([yes])
  if test -d ${patricia_dir} ; then
    AC_MSG_NOTICE(Using customized patricia trie installation in '${patricia_dir}'!)
  else
    AC_MSG_ERROR([
	--------------------------------------------------
	Directory 'patricia_dir=${patricia_dir}' not found!
	--------------------------------------------------])
  fi
fi
AC_SUBST([PATRICIA_DIR], [${patricia_dir}])

#
# Checks for libraries.
#
AS_BOX(Processing required libraries!)


##
## Library: libconfig
##
AC_SEARCH_LIBS([config_init], [config], [], 
  [AC_MSG_ERROR([
	--------------------------------------------------
	The library 'libconfig' is required to build 
	srx_server.
	--------------------------------------------------])])

##
## Library: dl
##
AC_SEARCH_LIBS([dlerror], [dl], [], 
  [AC_MSG_ERROR([
	--------------------------------------------------
	The library 'libdl' is required to use srxcryptoapi
	with srx_server.
	--------------------------------------------------])])

##
## Library: rt
##
AC_SEARCH_LIBS([clock_gettime], [rt], [], 
  [AC_MSG_ERROR([
	--------------------------------------------------
	The library 'librt' is required to build srx_server.
	--------------------------------------------------])])

##
## Library: readline for rpkirtr_svr
##
AC_SEARCH_LIBS([write_history], [readline], [], 
  [AC_MSG_ERROR([
	--------------------------------------------------
	The library 'libreadline' is required to build 
	srx_server client and rpkirtr_svr tool.
	--------------------------------------------------])])

##
## Library: pthread
##
AC_SEARCH_LIBS([pthread_create], [pthread], 
               [AC_DEFINE([_REENTRANT],, pthread reentrant nature)], 
  [AC_MSG_ERROR([
	--------------------------------------------------
	The library 'pthread' is required to build srx_server.
	--------------------------------------------------])])

##
## Library: SRxCryptoAPI - Starting with version >= 0.4.0
##
if test ${include_sca} = yes ; then
  AS_BOX(SRxCryptoAPI!)
  if test "x${sca_dir}" = "x" ; then
    # Check for regular installed library
    AC_SEARCH_LIBS([srxCryptoInit], [SRxCryptoAPI], 
                   [HAVE_LIBSRXCRYPTOAPI=yes], [HAVE_LIBSRXCRYPTOAPI=no])
    AC_CHECK_HEADERS([ srx/srxcryptoapi.h ], [], [AC_MSG_ERROR([
    --------------------------------------------------
    Headers for SRxCryptoAPI not found.
    --------------------------------------------------])])

  else
    # Search local install
    AC_MSG_CHECKING(for local installed SRxCryptoAPI)

    if test -e ${sca_dir}/lib$LD_ARCH_LOC/libSRxCryptoAPI.so ; then
      AC_MSG_RESULT([not found])
      AC_MSG_ERROR([
    --------------------------------------------------
    SRxCryptoAPI library not found.
    --------------------------------------------------])
    else
      AC_MSG_RESULT([found])
      CFLAGS="-I${sca_dir}/include $CFLAGS"
      LDFLAGS="-L${sca_dir}/lib$LD_ARCH_LOC/srx $LDFLAGS"
      LIBS="-lSRxCryptoAPI $LIBS"
      HAVE_LIBSRXCRYPTOAPI="yes"
    fi
  fi

  if test "$HAVE_LIBSRXCRYPTOAPI" = "no" ; then
    AC_MSG_ERROR([
	--------------------------------------------------
	The library 'SRxCryptoAPI' is required to build 
	srx_server. Install it using:
	  'yum install srxcryptoapi'
	or specify: 
    'sca_dir=<location>'
	--------------------------------------------------])
  fi
fi # end of ${include_sca}

##
## Library: libpatricia
##
# First test if it is located in a customized location
if test "x$patricia_dir" != "x" ; then

  # Search for custom install
  compile_libpatricia=no
  AC_MSG_CHECKING([whether custom installed library libpatricia exists])

  if test -f ${patricia_dir}/lib$LD_ARCH_LOC/libpatricia.a ; then
    if test -f ${patricia_dir}/include/patricia.h ; then
      CFLAGS="-I${patricia_dir}/include/ $CFLAGS"
      LIB_PATRICIA=${patricia_dir}/lib$LD_ARCH_LOC/libpatricia.a 
    else # patricia.h
      patr_err_msg="Custom file ${patricia_dir}/include/patricia.h not found!"    
    fi
  else # patricia.a
    patr_err_msg="Custom library ${patricia_dir}/lib$LD_ARCH_LOC/libpatricia.a not found!"    
  fi
  if test "x${error_msg}" = "x" ; then
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([
	--------------------------------------------------
	Error finding custom specified patricia library.
	"${patr_err_msg}"  
	--------------------------------------------------])
  fi
else # in case no custom library is specified, do compile the provided version

  AS_BOX(attempt to compile libpatricia from extra folder)
  home_dir=$(pwd)
  extras_dir=${home_dir}/../extras
  src_tarfile=${extras_dir}/files/Net-Patricia-1.15.tar.gz
  src_patchfile=${extras_dir}/files/Net-Patricia-1.15-fixes-20100513.patch
  src_makefile=${extras_dir}/make-lp.sh

  AC_MSG_CHECKING([whether file '${src_tarfile}' exists])
  if test -f ${src_tarfile} ; then
    AC_MSG_RESULT([yes])

    AC_MSG_CHECKING([whether file '${src_patchfile}' exists])
    if test -f ${src_patchfile} ; then
      AC_MSG_RESULT([yes])

      AC_MSG_CHECKING([whether file '${src_makefile}' exists])
      if test -f ${src_makefile} ; then
        AC_MSG_RESULT([yes])
        cd $extras_dir
        chmod +x ./make-lp.sh
        AC_MSG_NOTICE([building libpatricia])
        ./make-lp.sh > /dev/null 2>&1 
        if test $? -eq 0 ; then
          AC_MSG_CHECKING([whether library 'libpatricia.a' is created]) 
          if test -f ${extras_dir}/local/include/patricia.h ; then
            CFLAGS="-I${extras_dir}/local/include $CFLAGS"
            LIB_PATRICIA=${extras_dir}/local/lib$LD_ARCH_LOC/libpatricia.a
            if test -f ${LIB_PATRICIA} ; then
              AC_MSG_RESULT([yes])
            else # static library not generated
              AC_MSG_RESULT([no])
              patr_err_msg="Static library ${LIB_PATRICIA} not generated!"
            fi
            cd ${home_dir}
          else # NO HEADER FILE
            AC_MSG_RESULT([no])
            patr_err_msg="Header files for libpatricia not installed!"
          fi   # NO HEADER FILE

        else # Compiling patricia trie 
          patr_err_msg="Compiler returned with an error!"    
        fi

      else # Makefile search
        AC_MSG_RESULT([no])
        patr_err_msg="Patricia trie make file 'make-pl.sh' not found!"    
      fi   # Makefile search

    else # Patchfile search
      AC_MSG_RESULT([no])
      patr_err_msg="Patricia trie patch file not found!"    
    fi   # Patchfile search

  else    # Tarfile search
    AC_MSG_RESULT([no])
    patr_err_msg="Patricia trie source not found!"    
  fi      # Tarfile search

  if test "x${patr_err_msg}" != "x" ; then
    AC_MSG_ERROR([
	--------------------------------------------------
	Error building patricia library.
	- "${patr_err_msg}"  
	--------------------------------------------------])
  fi
fi
AC_SUBST(LIB_PATRICIA)
AS_BOX([LIB_PATRICIA: '$LIB_PATRICIA'])

AS_BOX(Processing required headers)
# Checks for header files.
#                  winsock.h \
AC_CHECK_HEADERS([ \
                  assert.h \
                  ctype.h \
                  dlfcn.h \
                  errno.h \
                  fcntl.h \
                  getopt.h \
                  libconfig.h \
                  malloc.h \
                  netdb.h \
                  patricia.h \
                  pthread.h \
                  semaphore.h \
                  signal.h \
                  stdarg.h \
                  stdbool.h \
                  stdint.h \
                  stdio.h \
                  stdlib.h \
                  string.h \
                  syslog.h \
                  time.h \
                  unistd.h \
                  uthash.h \
                  arpa/inet.h \
                  netinet/in.h \
                  netinet/tcp.h \
                  readline/history.h \
                  readline/readline.h \
                  sys/socket.h \
                  sys/time.h \
                  sys/types.h \
                  sys/un.h \
            ], [], [AC_MSG_ERROR([
    --------------------------------------------------
    Not all required headers found.
    --------------------------------------------------])])
 
# Checks for typedefs, structures, and compiler characteristics.
AS_BOX(processing for typedefs - structures - and compiler characteristics)
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

AM_CONDITIONAL([LIB_VER_INFO_COND], [test $LIB_VER_INFO])
AC_SUBST(LIB_VER_INFO)
AC_SUBST(VER_INFO)
AC_SUBST(PKG_VER)
AC_SUBST(MAJOR_VER)
AC_SUBST(MINOR_VER)
AC_SUBST(UPD_VER)
AC_SUBST(PACKAGE_VERSION)

# Checks for library functions.
AS_BOX(Processing library functions)
#AC_FUNC_MALLOC
#AC_FUNC_REALLOC
AC_CHECK_FUNCS([bzero gethostbyname memset socket strchr strrchr strdup strerror strtol strtoul], 
               [], [AC_MSG_ERROR([
	--------------------------------------------------
	Not all required system functions are available.
	--------------------------------------------------])])

AS_BOX(Processing additional configuration settings)
AC_SUBST([CFG_PREFIX], [${prefix}])
AC_SUBST([CFG_SYSCONFIG], [${prefix}/etc])

# Used as sub directory location for include and lib directory
AC_SUBST([SRX_DIR], [srx])

AC_CONFIG_FILES([Makefile \
     client/srxproxy$CPU_ARCH.conf:client/srxproxy.conf.in \
     srx-$PACKAGE_VERSION.spec:srx.spec.in \
     srx-proxy-$PACKAGE_VERSION.spec:srx-proxy.spec.in \
     server/srx_serverd:server/srx_serverd.in])

AC_OUTPUT

echo "Summary:"
echo "----------------------------------------------------------"
echo "SRx Server and Proxy Library ($PACKAGE_NAME) version $PACKAGE_VERSION"
echo "Prefix/Install.: $prefix"
echo "Debug Build....: $debug"
echo "C Compiler.....: $CC $CFLAGS $CPPFLAGS"
echo "C++ Compiler...: $CXX $CXXFLAGS $CPPFLAGS"
echo "Linker.........: $LD $LDFLAGS $LIBS"
echo "Patricia Trie..: $LIB_PATRICIA"
echo "Doxygen........: ${DOXYGEN:-NONE}"
echo "CPU Type.......: $CPU_ARCH"
echo "Library........: $VER_INFO ($LIB_VER_INFO)"
echo "RPM Incl. la...: ${incl_la_lib}"

