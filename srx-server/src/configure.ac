# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([SRx], [0.6.2.1], [itrg-contact@list.nist.gov], [srx], [https://www.nist.gov/services-resources/software/bgp-secure-routing-extension-bgp-srx-prototype])
# The -Wno=portability is needed for the $(shell...) GNU extension.
# If this is a problem remove the $(shell...) extension in Makefile_Common. 
AM_INIT_AUTOMAKE([-Wall -Werror -Wno-portability])
LT_PREREQ([2.2])
LT_INIT([dlopen])
LICENSE=https://www.nist.gov/director/copyright-fair-use-and-licensing-statements-srd-data-and-software


# IMPORTANT = This variable if, set requires a particular SCA version for 
#             compilation. 
REQ_SCA_VER=3

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
URL=AC_PACKAGE_URL

current=$MAJOR_VER
revision=$MINOR_VER
# The age CAN NOT be derived from the package version specified above.
# The age MUST be specified manually!!!
age=0

LIB_VER_INFO=$current:$revision:$age
VER_INFO=$current.$age.$revision


# Checks for programs.
AS_BOX(Verifying required programs)
# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET

#
# Determine if it is 64 Bit. This is needed for the ld.conf.d. file.
#
SRX_M4_CHECK_ARCH([CPU_ARCH], [CPU_ARCH_FLAGS], [CPU_])
if test "${libdir}" = "\${exec_prefix}/lib" ; then
  libdir="${libdir}$CPU_ARCH"
fi

#
# Check if .la and .a libraries should be added to RPM distribution
#
AS_BOX([Configure RPM settings])
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
# argument 'sca_dir=<path>'
#
AC_MSG_CHECKING([whether argument 'sca_dir' is provided])
AC_ARG_VAR([sca_dir], [Use library libSRxCryptoAPI from a customized location])
if test "x${sca_dir}" = "x"; then
  AC_MSG_RESULT([no])
else
  AC_MSG_RESULT([yes])
fi

SRX_M4_CHECK_SRXLIB([SRxCryptoAPI], [$REQ_SCA_VER], [srx/srxcryptoapi.h], 
                    [$CPU_ARCH], [$sca_dir], 
                    [SCA_LIBS], [SCA_CFLAGS], [SCA_LDFLAGS])

#
# Checks for libraries.
#
AS_BOX(Processing additional required libraries!)

##
## Library: libconfig
##
SRX_M4_CHECK_LIBCONFIG()

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
## Library: libpatricia
##
# First test if it is located in a customized location
if test "x$patricia_dir" != "x" ; then

  # Search for custom install
  compile_libpatricia=no
  AC_MSG_CHECKING([whether custom installed library libpatricia exists])

  if test -f ${patricia_dir}/lib$CPU_ARCH/libpatricia.a ; then
    if test -f ${patricia_dir}/include/patricia.h ; then
      CFLAGS="-I${patricia_dir}/include/ $CFLAGS"
      LIB_PATRICIA=${patricia_dir}/lib$CPU_ARCH/libpatricia.a 
    else # patricia.h
      patr_err_msg="Custom file ${patricia_dir}/include/patricia.h not found!"    
    fi
  else # patricia.a
    patr_err_msg="Custom library ${patricia_dir}/lib$CPU_ARCH/libpatricia.a not found!"    
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
            LIB_PATRICIA=${extras_dir}/local/lib$CPU_ARCH/libpatricia.a
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

AC_MSG_CHECKING([whether test tools have to be generated])
AC_ARG_WITH([buildtest], 
            [  --with-builtest         build test tools],
              [case "${withval}" in
                yes) buildtest=true ;;
                no) buildtest=false ;;
                *) AC_MSG_ERROR([bad value ${withval} for --width-buildtest]) 
                   ;;
              esac], [buildtest=false])
AC_MSG_RESULT([${withval}])
AM_CONDITIONAL([BUILD_TEST], [test x$buildtest = xtrue])

# check gRPC support variables
AC_ARG_ENABLE(grpc,
              [ --enable-grpc       enable grpc features],
              [enable_grpc="yes"],[])

AM_CONDITIONAL([ENABLE_GRPC_COND], [test x$enable_grpc = xyes])

AC_MSG_CHECKING(checking to see if grpc is enabled)
if test "x${enable_grpc}" = "xyes"; then
    AC_MSG_RESULT(yes)
    AC_DEFINE([USE_GRPC],[], SRX GRPC)
    AC_ARG_VAR(grpc_dir, provide grpc driver directory in which grpc server and client installed)
else
    AC_MSG_RESULT(no) 
fi





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

AM_CONDITIONAL([LIB_VER_INFO_COND], [test $LIB_VER_INFO])
AC_SUBST(LIB_VER_INFO)
AC_SUBST(VER_INFO)
AC_SUBST(PKG_VER)
AC_SUBST(MAJOR_VER)
AC_SUBST(MINOR_VER)
AC_SUBST(UPD_VER)
AC_SUBST(PACKAGE_VERSION)
AC_SUBST(SCA_LIBS)
AC_SUBST(SCA_CFLAGS)
AC_SUBST(SCA_LDFLAGS)
AC_SUBST(SCA_DIR, [$sca_dir])
AC_SUBST(CPU_ARCH)
AC_SUBST(CPU_ARCH_FLAGS)
AC_SUBST(LCONFIG_INT)
AC_SUBST(LICENSE)
AC_SUBST(URL)

# Checks for library functions.
#AS_BOX(Processing library functions)
#AC_FUNC_MALLOC
#AC_FUNC_REALLOC
#AC_CHECK_FUNCS([gethostbyname memset socket strchr strrchr strdup strerror strtol strtoul], 
#               [], [AC_MSG_ERROR([
#	--------------------------------------------------
#	Not all required system functions are available.
#	--------------------------------------------------])])

AS_BOX(Processing additional configuration settings)
AC_SUBST([CFG_PREFIX], [${prefix}])
AC_SUBST([CFG_SYSCONFIG], [${prefix}/etc])

# Used as sub directory location for include and lib directory
AC_SUBST([SRX_DIR], [srx])

AC_CONFIG_FILES([Makefile \
     client/srxproxy$CPU_ARCH.conf:client/srxproxy.conf.in \
     srx-$PACKAGE_VERSION.spec:srx.spec.in \
     srx-proxy-$PACKAGE_VERSION.spec:srx-proxy.spec.in \
     srx-proxy-devel-$PACKAGE_VERSION.spec:srx-proxy-devel.spec.in \
     server/srx_serverd:server/srx_serverd.in])

if test "x${enable_grpc}" = "xyes"; then
    AC_CONFIG_FILES([$grpc_dir/Makefile]) 
    AC_SUBST([HOME_DIR], [${home_dir}])
fi

AC_OUTPUT

echo
echo "Summary:"
echo "----------------------------------------------------------"
echo "SRx Server and Proxy Library ($PACKAGE_NAME) version $PACKAGE_VERSION"
echo "Prefix/Install.: $prefix"
echo "Debug Build....: $debug"
echo "CPU Type.......: $CPU_ARCH"
echo "LIBS...........: $LIBS"
echo "LDFLAGS........: $LDFLAGS"
echo "CFLAGS.........: $CFLAGS"
echo "Patricia Trie..: $LIB_PATRICIA"
echo "Library........: $VER_INFO ($LIB_VER_INFO)"
echo "LCONFIG_INT....: $LCONFIG_INT"
echo "RPM Incl. la...: ${incl_la_lib}"
echo "Build Test.....: ${buildtest}"
echo
echo "SRxCryptoAPI V$REQ_SCA_VER:"
echo "----------------------------------"
echo "SCA_LIBS.......: $SCA_LIBS"
echo "SCA_LDFLAGS....: $SCA_LDFLAGS"
echo "SCA_CFLAGS.....: $SCA_CFLAGS"
if test "x${enable_grpc}" = "xyes"; then
echo
echo "----------------------------------"
echo "Enable gRPC....: ${enable_grpc}"
echo "gRPC DIR  .....: $grpc_dir"
fi
