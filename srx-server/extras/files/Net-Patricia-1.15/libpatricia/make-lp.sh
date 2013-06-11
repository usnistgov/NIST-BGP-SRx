#!/bin/bash
# Make for both the lib and the demo

OS=$(uname)
if [ "$OS" == "Darwin" ]; then
  LIBTOOL="glibtool --tag=CC"
else
  LIBTOOL="libtool --tag=CC"
fi

$LIBTOOL --version > /dev/null
res=`echo $?`
if [ $res != 0 ]; then
    echo "use SRx-built-in libtool"
    LIBTOOL="../../../../libtool --tag=CC"
    $LIBTOOL --version > /dev/null 2>&1
else
    echo "use internal libtool"
fi


OPTS=-DHAVE_IPV6 $@
if [ -e demo.c ]; then
  gcc -I../libpatricia/ $OPTS -c demo.c
  gcc $OPTS -o demo demo.o ../libpatricia/libpatricia.a
else
  TDIR=$PWD/../../../local/lib
  mkdir $TDIR
  $LIBTOOL --mode=compile gcc $OPTS -c patricia.c
  $LIBTOOL --mode=link gcc -o libpatricia.la patricia.lo -rpath $TDIR
  $LIBTOOL --mode=install cp libpatricia.la $TDIR
  $LIBTOOL --finish $TDIR
  cp patricia.h ../../../local/include/
fi
