# SRX_M4_CHECK_INTERNAL_lib_ncurses & libreadline 
# -------------------------------------------------
#
# Define this macro for chekcing extra files
#  and installing libncurses and libreadline.
#
AC_DEFUN([SRX_M4_CHECK_INTERNAL_LIB_NCURSES], [
AC_MSG_CHECKING([for using internal libncurses])
if test "x$var_libncur" = xyes; then
    AC_MSG_RESULT([enabled: ${var_libncur}])
    if test -f ../extras/files/ncurses-5.9.tar.gz; then
        AC_MSG_RESULT([ file ncurses-5.9.tar.gz exists ])
        orig_path=$PWD
        cd ../extras/files/ && pwd
        tar xvfz ncurses-5.9.tar.gz > /dev/null 2>&1 && cd ncurses-5.9
	./configure --prefix=${PWD}/../../local 
	make all install > /dev/null 2>&1 
        cd $orig_path && pwd
    fi
else
    AC_MSG_RESULT([null: ${var_libncur}])
fi
])#SRX_M4_CHECK_INTERNAL_LIB_NCURSES



AC_DEFUN([SRX_M4_CHECK_INTERNAL_LIB_READLINE], [
AC_MSG_CHECKING([for using internal libreadline])
if test "x$var_libread" = xyes; then
    AC_MSG_RESULT([enabled: ${var_libread}])
    if test -f ../extras/files/readline-6.2.tar.gz; then
	AC_MSG_RESULT([ readline-6.2.tar.gz exists ])
	orig_path=$PWD
	cd ../extras/files/ && pwd
	tar xvfz readline-6.2.tar.gz > /dev/null 2>&1 && cd readline-6.2
	./configure --prefix=${PWD}/../../local 
	make all install > /dev/null 2>&1 
	cd $orig_path && pwd
    fi
else
    AC_MSG_RESULT([null: ${var_libread}])
fi
])#SRX_M4_CHECK_INTERNAL_LIB_READLINE


