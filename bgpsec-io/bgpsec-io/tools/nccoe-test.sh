#!/bin/sh

TESTNUM=""
TESTFILE=""
TESTHOST=""

while [ "$1" != "" ] ; do
  case "$1" in
    "?" | "-?" | "h" | "-h")
      echo "$0 <test number> <host>"
      ;;
    "--list")
      ls | grep "NCCOE-"
      ;;
    *)
      if [ "$TESTNUM" != "" ] ; then
        if [ "$TESTHOST" != "" ] ; then
          echo "Test number & host are already assigned!"
          exit 1
        else
          TESTHOST="$1"
        fi
      else
        TESTNUM="$1"
      fi
      ;;
  esac
  shift
done

TESTFILE="NCCOE-$TESTNUM-$TESTHOST.test"
TESTRESULT="NCCOE-$TESTNUM-$TESTHOST.result"

if [ "$TESTNUM" == "" ] ; then
  echo "Test number missing!"
  exit 1
fi

if [ "$TESTHOST" == "" ] ; then
  echo "Test host missing!"
  exit 1
fi

if [ ! -e $TESTFILE ] ; then
  echo "Test script '$TESTFILE' not found!"
  exit 1
fi

echo "Starting test $TESTNUM on $TESTHOST..."

bgpsecio -f $TESTFILE > $TESTRESULT
