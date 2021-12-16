#!/bin/bash
# 
# Make sure we start in the demo folder
#
DEMO_FLDR=$(readlink -f $0 | xargs dirname)
DEMO_CURR_FLDR=$(pwd)
DEMO_PREFIX_FLDR=$(echo $DEMO_FLDR | sed -e "s/\(.*\)\/opt\/.*/\1/g")
DEMO_BIN_FLDR=$DEMO_PREFIX_FLDR/bin/
DEMO_LIB_FLDR=$DEMO_PREFIX_FLDR/opt/bgp-srx-examples/lib
DEMO_KEYS_FLDR=$DEMO_PREFIX_FLDR/opt/bgp-srx-examples/bgpsec-keys

PRG_BIO=bgpsecio

# set to 1 if --report is used.
__REPORT=0
_ERROR_REGEX=" 1 updates (4 segments) \| 3 updates (9 segments) \| Invalid updates due to missing key: 1"
_KEEP_DATAFILE=0

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
  echo "The srxcryptoapi does not contain any keys. All keys are provided"
  echo "  by the bgpsec-io"
  echo
  echo "$0 <module> [--report] [--keep-datafile]"
  echo
  echo "  --report   This setting filters the output for ERROR and"
  echo "             reduces the output to \"TEST OK\" or \"TEST FAILED\""
  echo "             with a return level of 0:OK and 1:FAILED"
  echo 
  echo "  --keep-datafile   This setting allows to keep the datafile generated"
  echo "                    in bio-sca-2 and bio-sca-3"
  echo
  echo "Modules:"
  echo "  bio-sca-1  Test srxcryptoapi using bgpsecio by dynamically"
  echo "             generating signatures and have srxcryptoapi validate them"
  echo "  bio-sca-2  Generate binary data file containing BGPsec_PATH attribute using"
  echo "             bgpsecio. Then replay the data file and have srxcryptoapi "
  echo "             validate the signatures."
  echo "             This test displays correctly a key registration error because"
  echo "             an invalid key was used to generate one signature."
  echo

  endPrg $1
}

#
# Make sure to return to the folder this script was called from,
# similar to popd.
#
# cd @param $1 the exit code/
# 
endPrg()
{
  local _retVal=0
  if [ "$1" != "" ] ; then
    _retVal=$1
  fi
  if [ $_retVal -eq 0 ] ; then
    echo "TEST OK"
  else
    echo "TEST FAILED"
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
CFG_FILES=("$DEMO_FLDR/srxcryptoapi.conf"
           "$DEMO_FLDR/bgpsecio-sca-replay.conf"
           "$DEMO_FLDR/bgpsecio-sca-gen.conf"
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
    "--keep-datafile") _KEEP_DATAFILE=1;;
    *) echo "ERROR: Unknown parameter '$1'"; endPrg 1 ;;
  esac
  shift
done

retVal=0
cd $DEMO_BIN_FLDR

case "$_module" in
  "bio-sca-1")
      _CONF_FILE_1="$DEMO_FLDR/bgpsecio-sca-gen.conf"
      _DATA_FILE=""
      ;;
  "bio-sca-2")
      _CONF_FILE_1="$DEMO_FLDR/bgpsecio-sca-gen.conf"
      _CONF_FILE_2="$DEMO_FLDR/bgpsecio-sca-replay.conf"
      _DATA_FILE="/tmp/srxcryptoapi-sca-replay-$(date +%s).dat"
      ;;
  *)    
    echo "Unknown Module '$1'"
    retVal=1
    ;;
esac

if [ $retVal -eq 0 ] ; then
  if [ $__REPORT -eq 0 ] ; then
    if [ "$_DATA_FILE" == "" ] ; then
      # run bio-sca-1 without report
      startPrg 0 "./$PRG_BIO" "-f" $_CONF_FILE_1 -m CAPI 2>/dev/null
      retVal=$?
      echo "It is expected to have 1 invalid and 3 valid routes!"
    else
      # run bio-sca-2 or bio-sca-3 without report
      startPrg 0 "./$PRG_BIO" "-f" $_CONF_FILE_1 -m GEN-C --out $_DATA_FILE 2>/dev/null
      retVal=$?
      if [ $retVal -eq 0 ] ; then
        startPrg 0 "./$PRG_BIO" "-f" $_CONF_FILE_2 -m CAPI --bin $_DATA_FILE 2>/dev/null
        retVal=$?
      fi
    fi
  else
    if [ "$_DATA_FILE" == "" ] ; then
      # run bio-sca-1 with report
      _RESULT=$(startPrg 0 "./$PRG_BIO" "-f" $_CONF_FILE_1 -m CAPI 2>/dev/null \
                | grep -e "$_ERROR_REGEX" | wc -l)
    else
      # run bio-sca-2 with report
      startPrg 0 "./$PRG_BIO" "-f" $_CONF_FILE_1 -m GEN-C --out $_DATA_FILE >/dev/null 2>&1
      retVal=$?
      if [ $retVal -eq 0 ] ; then
        _RESULT=$(startPrg 0 "./$PRG_BIO" "-f" $_CONF_FILE_2 -m CAPI --bin $_DATA_FILE 2>/dev/null \
                  | grep -e "$_ERROR_REGEX" | wc -l)
      else
        _RESULT=0
      fi
    fi
    if [ $_RESULT -eq 3 ] ; then
      retVal=0
    else
      retVal=1
    fi
  fi
  if [ "$_DATA_FILE" != "" ] ; then
    if [ -e $_DATA_FILE ] ; then
      if [ $_KEEP_DATAFILE -eq 0 ] ; then
        # Clean up
        rm -f $_DATA_FILE
      else
        echo "Data is stored in '$_DATA_FILE'"
      fi
    fi
  fi
fi

endPrg $retVal