#!/bin/bash
# Make for both the lib and the demo

EXTRA_ROOT=$(pwd)
SRX_ROOT=$EXTRA_ROOT/..
FILES_ROOT=$EXTRA_ROOT/files
INSTALL_DIR=$EXTRA_ROOT/local

case "$HOSTTYPE" in
  x86_64) 
    LD_ARCH_LOC="64"
    ;;
  *) 
    LD_ARCH_LOC=""
    ;;
esac


cd $FILES_ROOT
  tar -xzf Net-Patricia-1.15.tar.gz
  cd Net-Patricia-1.15/libpatricia
    patch -p0 -i $FILES_ROOT/Net-Patricia-1.15-fixes-20100513.patch  

    mkdir -p $INSTALL_DIR/include $INSTALL_DIR/lib$LD_ARCH_LOC

    LIBTOOL="../../../../libtool --tag=CC"   

    OPTS=-DHAVE_IPV6 $@
    $LIBTOOL --mode=compile gcc $OPTS -c patricia.c
    $LIBTOOL --mode=link gcc -o libpatricia.la patricia.lo -rpath $INSTALL_DIR/lib$LD_ARCH_LOC
    $LIBTOOL --mode=install cp libpatricia.la $INSTALL_DIR/lib$LD_ARCH_LOC
    $LIBTOOL --finish $INSTALL_DIR/lib$LD_ARCH_LOC

    cp -f patricia.h $INSTALL_DIR/include
cd $EXTRA_ROOT
rm -rf $FILES_ROOT/Net-Patricia-1.15
