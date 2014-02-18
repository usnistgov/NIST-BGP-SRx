# SRX_M4_CHECK_INTERNAL_LIB_PATRICIA & LIB_CONFIG
# -------------------------------------------------
#
# Define this macro for chekcing extra files
#  and installing libpatricia tree.
#
AC_DEFUN([SRX_M4_CHECK_INTERNAL_LIB_PATRICIA], [
AC_MSG_CHECKING([for using internal libpatricia])
if test "x$var_libpatr" = xyes; then
    AC_MSG_RESULT([enabled: ${var_libpatr}])
    if test -f ../extras/files/Net-Patricia-1.15.tar.gz; then
        if test -f ../extras/files/Net-Patricia-1.15-fixes-20100513.patch; then
            if test -f ../extras/make-lp.sh; then
                AC_MSG_RESULT([ Net-Patricia-1.15.tar.gz and others exists ])
                orig_path=$PWD
                cd ../extras/files/ && pwd
                tar xvfz Net-Patricia-1.15.tar.gz > /dev/null 2>&1 && cd Net-Patricia-1.15/libpatricia
                patch -p0 -i ../../Net-Patricia-1.15-fixes-20100513.patch
                cp ../../../make-lp.sh ./
                chmod +x ./make-lp.sh
                ./make-lp.sh > /dev/null 2>&1 
                cd $orig_path && pwd
                rm -rf ../extras/files/Net-Patricia-1.15/
            fi

        fi
    fi
else
    AC_MSG_RESULT([null: ${var_libpatr}])
fi
])#SRX_M4_CHECK_INTERNAL_LIB_PATRICIA



AC_DEFUN([SRX_M4_CHECK_INTERNAL_LIB_CONFIG], [
AC_MSG_CHECKING([for using internal libconfig])
if test "x$var_libconf" = xyes; then
    AC_MSG_RESULT([enabled: ${var_libconf}])
    if test -f ../extras/files/libconfig-1.4.1.tar.gz; then
	    AC_MSG_RESULT([ libconfig-1.4.1.tar.gz exists ])
	    orig_path=$PWD
	    cd ../extras/files/ && pwd
	    tar xvfz libconfig-1.4.1.tar.gz > /dev/null 2>&1 && cd libconfig-1.4.1
	    ./configure --prefix=${PWD}/../../local --disable-cxx
	    make all install > /dev/null 2>&1 
	    cd $orig_path && pwd
        rm -rf ../extras/files/libconfig-1.4.1/
    fi
else
    AC_MSG_RESULT([null: ${var_libconf}])
fi
])#SRX_M4_CHECK_INTERNAL_LIB_CONFIG


