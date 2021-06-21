#!/bin/bash
# 
# Make sure we start in the demo folder
#
DEMO_FLDR=$(readlink -f $0 | xargs dirname)
DEMO_CURR_FLDR=$(pwd)
DEMO_PREFIX_FLDR=$(echo $DEMO_FLDR | sed -e "s/\(.*\)\/opt\/.*/\1/g")
DEMO_SBIN_FLDR=$DEMO_PREFIX_FLDR/sbin/
DEMO_LIB_FLDR=$DEMO_PREFIX_FLDR/opt/bgp-srx-examples/lib
DEMO_KEYS_FLDR=$DEMO_PREFIX_FLDR/opt/bgp-srx-examples/bgpsec-keys

PRG_SCA=srx_crypto_tester

# set to 1 if --report is used.
__REPORT=0
_ERROR_REGEX="ERROR"

##############################################################################
##  LOAD THE LIBRARY
##
if [ ! -e $DEMO_LIB_FLDR/functions.sh ] ; then
  echo "WARNING: Could not find library script [$DEMO_LIB_FLDR/functions.sh]!"
  echo "         Install framework properly prior usage."
else
  . $DEMO_LIB_FLDR/functions.sh
fi
if [ "$FUNCTION_LIB_VER" == "" ] ; then
  echo "ERROR loading the functions library - Abort operation!"
  exit 1
fi
##############################################################################


#
# Display the programs syntax
#
syntax()
{
  echo "$0 <module> [--report]"
  echo
  echo "  --report   This setting filters the output for ERROR and"
  echo "             reduces the output to \"TEST OK\" or \"TEST FAILED\""
  echo "             with a return level of 0:OK and 1:FAILED"
  echo
  echo "Modules:"
  echo "  sca-1  Start SCA tester trying to load the SCA library"
  echo "  sca-2  Load a single public key"
  echo "  sca-3  Load a single private key"
  echo

  endPrg $1
}

#
# Make sure to return to the folder this script was called from
# Similar to popd.
#
# @param $1 the exit code/
# 
endPrg()
{
  retVal=0
  if [ "$1" != "" ] ; then
    retVal=$1
  fi
  if [ $__REPORT -eq 1 ] ; then
    ## Here a return value of 0 means the error was found
    if [ $retVal -eq 1 ] ; then
      echo "TEST OK"
      retVal=0
    else
      echo "TEST FAILED"
      retVal=1
    fi
  fi

  cd $DEMO_CURR_FLDR
  exit $retVal
}

# Switch into the demo folder
cd $DEMO_FLDR

if [ "$1" == "" ] ; then
  syntax 0
fi 

# Check that all files are configured
CFG_FILES=("$DEMO_FLDR/srxcryptoapi-sca-1.conf"
           "$DEMO_FLDR/srxcryptoapi-sca-2-3.conf"
           "$DEMO_KEYS_FLDR/ski-list.txt" 
           "$DEMO_KEYS_FLDR/priv-ski-list.txt")
for cfg_file in "${CFG_FILES[@]}" ; do 
  if [ ! -e "$cfg_file" ] ; then
    echo "Configuration file '$cfg_file' not found!"
    echo "Please configure example first!"
    endPrg 1
  fi
done

if [ "$1" == "--report" ] ; then
  __REPORT=1
  shift
fi

_module="$1"
shift

# Check if any other parameter is --report
while [ "$1" != "" ] ; do
  case $1 in
    "--report") __REPORT=1 ;;
    *) echo "ERROR: Unknown parameter '$1'"; endPrg 1 ;;
  esac
  shift
done

_retVal=0
cd $DEMO_SBIN_FLDR

case "$_module" in
  "sca-1")
    if [ $__REPORT -eq 0 ] ; then
      startPrg 0 "./$PRG_SCA" "-f" "$DEMO_FLDR/srxcryptoapi-sca-1.conf" 
      retVal=$?
    else
      startPrg 0 "./$PRG_SCA" "-f" "$DEMO_FLDR/srxcryptoapi-sca-1.conf" \
                 | grep -e "$_ERROR_REGEX" >> /dev/null
      retVal=$?
    fi
    ;;
  "sca-2")
    if [ $__REPORT -eq 0 ] ; then
      startPrg 0 "./$PRG_SCA" "-f" "$DEMO_FLDR/srxcryptoapi-sca-2-3.conf" \
                 -k pub 65000 8E232FCCAB9905C3D4802E27CC0576E6BFFDED64
      retVal=$?
    else
      startPrg 0 "./$PRG_SCA" "-f" "$DEMO_FLDR/srxcryptoapi-sca-2-3.conf" \
                 -k pub 65000 8E232FCCAB9905C3D4802E27CC0576E6BFFDED64 \
                 | grep -e "$_ERROR_REGEX" >> /dev/null
      retVal=$?
    fi
    ;;
  "sca-3")
    if [ $__REPORT -eq 0 ] ; then
      startPrg 0 "./$PRG_SCA" "-f" "$DEMO_FLDR/srxcryptoapi-sca-2-3.conf" \
                 -k priv 65000 8E232FCCAB9905C3D4802E27CC0576E6BFFDED64
      retVal=$?
    else
      startPrg 0 "./$PRG_SCA" "-f" "$DEMO_FLDR/srxcryptoapi-sca-2-3.conf" \
                 -k priv 65000 8E232FCCAB9905C3D4802E27CC0576E6BFFDED64 \
                 | grep -e "$_ERROR_REGEX" >> /dev/null
#      echo $_ERROR_REPORT
      retVal=$?
    fi
    ;;
  *)    
    echo "Unknown Module '$1'"
    retVal=1
    ;;
esac

endPrg $retVal