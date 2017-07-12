#!/bin/sh
#echo "Generate large amounts of updates"

IP1=10
IP2=0
IP3=0
IP4=0
PFX=24

IP2STEP=1
IP3STEP=1

COUNT=0
MAXCT=2000

COMMA=""
PREFIX=""
LIST=0

AS_PATH=""

function syntax()
{
  echo "$0 [-b <#> <val> ] [-p <pfxlen>] [-s2 <step>] [s3 <step>] [-P <path>] [-c ] [-l] "
  echo
  echo "  Parameters:"
  echo "    -b <#> <val>: Specify the byte portion of the start prefix"
  echo "    -p <pfx-len>: Specify the prefix length (default: 24)"
  echo "    -s2 <step>  : Specify the increment of byte 2"
  echo "    -s3 <step>  : Specify the increment of byte 3"
  echo "    -P <path>   : Path = <as#> <as1> <as2> ... path to be added"
  echo "    -c          : Max number of updates"
  echo "    -l          : List mode, one update per line."
  echo "    -?, ?, -h   : This screen."
  echo
  echo " 2017 ANTD/NIST (bgpsrx-dev@nist.gov)"
  echo
  exit $1
}

function processParam()
{
  local ELEMENTS=0
  local NUM=0

  while [ "$1" != "" ] ; do
    case "$1" in
     "?" | "-?" | "-h")
       syntax 0
       ;;
     "-s2")
        shift
        if [ "$1" == "" ] ; then
          syntax 1
        fi
        if [ $1 -gt 0 ] && [ $1 -lt 257 ] ; then
          IP2STEP=$1          
        fi
        ;;
     "-s3")
        shift
        if [ "$1" == "" ] ; then
          syntax 1
        fi
        if [ $1 -gt 0 ] && [ $1 -lt 257 ] ; then
          IP3STEP=$1          
        fi
        ;;
     "-c")
        shift
        MAXCT=$1
        ;;
     "-P")
        shift
        ELEMENTS=$1
        while [ $ELEMENTS -gt 0 ] ; do
          shift
          AS_PATH="$AS_PATH $1"
          ELEMENTS=$(($ELEMENTS - 1))
        done
        AS_PATH=",$AS_PATH"
        ;;
     "-l")
        LIST=1
        ;;
     "-b")
        shift
        NUM=$1
        shift
        if [ "$1" != "" ] ; then
          case "$NUM" in 
            "1") IP1=$1 ;;
            "2") IP2=$1 ;;
            "3") IP3=$1 ;;
            "4") IP4=$1 ;;
            *) echo "Invalid IP number '$NUM=$1'"
               exit 1
               ;;
          esac
        else
          echo "No IP position provided!"
          exit 1
        fi
        ;;
     "-p")
        shift
        if [ $1 -ge -1 ] && [ $1 -le 32 ] ; then
          PFX-$1
        else
          echo "Invalid prefix length '$1'"
          exit 1
        fi
        ;;
     *) echo "Unknown Parameter '$1'"
        exit 1
        ;;
    esac
    shift
  done
}


processParam $@

if [ $LIST -eq 0 ] ; then
  echo "update = ("
  PREFIX="  "
  COMMA=","
fi

while [ $PFX -lt 32 ] && [ $COUNT -lt $MAXCT ] ; do
  while [ $IP2 -lt 256 ] && [ $COUNT -lt $MAXCT ] ; do
    while [ $IP3 -lt 256 ] && [ $COUNT -lt $MAXCT ] ; do
      if [ $COUNT -gt 0 ] ; then
        echo "$PREFIX$COMMA\"$IP1.$IP2.$IP3.$IP4/$PFX$AS_PATH\""
      else
        echo "$PREFIX\"$IP1.$IP2.$IP3.$IP4/$PFX$AS_PATH\""
      fi
      IP3=$(($IP3 + $IP3STEP))
      COUNT=$(($COUNT + 1))
    done
    IP3=0
    IP2=$(($IP2 + $IP2STEP))
  done
  IP2=0
  IP3=0
  PFX=$(($PFX + 1))
done

if [ $LIST -eq 0 ] ; then
  echo ");"
  echo "# $COUNT Updates generated"
fi
