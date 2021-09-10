#!/bin/bash
#
# This file contains functions used in multiple shell script files.
#
#

# Array used to specify IP addresses
SYS_IP=()
SYS_IP_LABEL=()

# The following variables are used for formating purpose.
# Allow a tab prior printed text
SYS_IP_TAB=""
# Prefix used when printing IP label
SYS_IP_LBL_PFX="<"
# Suffix used when printing IP label
SYS_IP_LBL_SFX=">"

## Used by the function fill_SYS_IP to indicate how many
## IP addresses are missing, if any.
SYS_MISSING_IPS=0

READ_TAB=""
GLOBAL_YN=""

FUNCTION_LIB_VER=0.5.1.9

## 
## This function resets the arrays associated with IP selection
## 
function reset_SYS_IP()
{
  SYS_IP=()
  SYS_IP_LABEL=()
}

## 
## This function retrieves the systems IPv4 addresses which should be
## used and writes it into the SYS_IP array. 
## If more are available, user input is required.
## 
 # if less addresses are pre-chosen than required then the pre-chosen 
 # will be selected first and then user input is required.
 #
 # For pre-chosen addresses it is important to considder the renumbering
 # selection. 
 # Once an IP address is selected, the following list type decides what 
 # happens: 
 #      0: remove selected and renumber list
 #      1: remove selected without renumbering
 #      2: kepp list entry for multiple selections
 #
 # Example: 
 #   list_type=0 - remove selected and renumebr
 #     1(a), 2(b), 3(c), 4(d) and 2 selected: new list = 1(a), 2(c), 3(d)
 #   list_type=1 - remove selected no renumbering
 #     1(a), 2(b), 3(c), 4(d) and 2 selected: new list = 1(a),     , 3(c), 4(d)
 #   list_type=2 - don't remove and allow re-selection
 #     1(a), 2(b), 3(c), 4(d) and 2 selected: new list = 1(a), 2(b), 3(c), 4(d)
 # 
## $1 number of IP addresses to be assigned.
## $2 text label prefix (default: 'ip-address-')
## $3 list-type (0|1|2)
## $4... pre-selection
## 
function fill_SYS_IP()
{
  local ip_addr=($(ifconfig | grep -e "inet \(addr:\)\?" | sed -e "s/.*inet [adr:]*\([0-9\.]\+\) .*/\1/g" | sed "/127\.0\.0\.1/d"))
  if [ $? -gt 0 ] ; then
    local ip_addr=($(ip addr show | grep -e "inet \(addr:\)\?" | sed -e "s/.*inet [adr:]*\([0-9\.]\+\)\/[0-9]\+ .*/\1/g" | sed "/127\.0\.0\.1/d"))
  fi
  local arrayHelper
  local _PRESELECT=()
  local addr
  local idx
  local list_type=1
  local selected=0
  local requested=1
  local label="ip-address-"

  if [ "$1" != "" ] ; then
    requested=$1
  fi
  if [ "$2" != "" ] ; then
    label="$2"
  fi
  if [ "$3" != "" ] ; then
    list_type=$3
  fi
  while [ "$4" != "" ] ; do
    if [ "$(($4+0))" == "$4" ] ; then
      _PRESELECT+=($4)
    else
      echo $SYS_IP_TAB"Given preselection '$4' is invalid, skipp this value!"
    fi
    shift
  done

  #echo "arr: ${ip_addr[@]}"
  #echo "req: $requested"

  if [ ${#ip_addr[@]} -gt $requested ] ; then
    _preselect_idx=1
    while [ ${#SYS_IP[@]} -lt $requested ] ; do
      if [ $requested -gt 1 ] ; then
        selected=$((${#SYS_IP[@]}+1))
        echo "$SYS_IP_TAB  Select $SYS_IP_LBL_PFX$label$selected$SYS_IP_LBL_SFX of $requested IP Addresses from the following IP Addresses:"
        if [ $selected -gt 1 ] ;then
          echo "$SYS_IP_TAB  Selected so far: ${SYS_IP[@]}"
        fi
      else
        echo "$SYS_IP_TAB  Select one IP from the following IP Addresses:"
      fi
      idx=1
      for addr in "${ip_addr[@]}" ; do
        echo "$SYS_IP_TAB  - [$idx]: $addr"
        idx=$(($idx + 1))
      done
      if [ $_preselect_idx -gt ${#_PRESELECT[@]} ] ; then
        read -p "$SYS_IP_TAB  Select address: " selected
      else
        # Choose from the preselected first.
        selected=${_PRESELECT[$(($_preselect_idx-1))]}
        _preselect_idx=$(($_preselect_idx+1))
        echo "$SYS_IP_TAB  Select address: $selected"
      fi
      echo
      echo "$selected" | grep -e "^[0-9]\+$" > /dev/null
      if [ ! $? -eq 0 ] || [ $selected -eq 0 ] || [ $selected -gt ${#ip_addr[@]} ] ; then
        echo "$SYS_IP_TAB  Error: Invalid input '$selected' - select between 1 and ${#ip_addr[@]}"
      else
        selected=$(($selected -1))
        chosenIP=${ip_addr[$selected]}
        SYS_IP+=($chosenIP)
        SYS_IP_LABEL+=("$label${#SYS_IP[@]}")
        # Now remove the chosen IP from the IP array
        case $list_type in
          0)
            arrayHelper=()
            for addr in "${ip_addr[@]}" ; do
              if [ "$addr" != "$chosenIP" ] ; then
                arrayHelper+=($addr)
              fi
            done
            ip_addr=(${arrayHelper[@]})
            ;;
          1)
            ip_addr=( "${ip_addr[@]/$chosenIP}" )
            ;;
          *)
            # All staus as it is
            ;;
        esac
      fi
    done
  else
    for idx in ${!ip_addr[@]} ; do
      SYS_IP_LABEL+=("$label$(($idx+1))")
    done
    SYS_IP=(${ip_addr[@]});
  fi

  local retVal=0
  if [ $requested -gt ${#SYS_IP[@]} ] ; then
    local missing=$(($requested-${#SYS_IP[@]}))
    local plural=""
    if [ $missing -gt 1 ] ; then
      plural="es"
    fi
    echo "$SYS_IP_TAB""Not enough IP addresses available!"
    echo "$SYS_IP_TAB$missing IP address$plural are missing!"
    SYS_MISSING_IPS=$missing
    retVal=1
  elif [ $requested -eq 0 ] ; then
    echo "$SYS_IP_TAB""At least one single request must be made!"
    retVal=1
  fi

  return $retVal
}

## 
## Parses the given parameters for Y or N and writes the 
## proper value into GLOBAL_YN.
##
## If no parameter is given the return value will be 1 as well.
## 
## $1 The parameter parsed "-Y" or "-N"
## $2 Optional replacement for "-Y" 
## $3 Optional replacement for "-N"
##
## return 1 if any other parameter than -Y or -N (or its replacement $2 $3) 
##          was parsed.  
## 
function parseYN()
{
  local _retVal=1
  local _Y="-Y"
  local _N="-N"

  if [ "$2" != "" ] ; then
    _Y="$2"
    if [ "$3" != "" ] ; then
      _N="$3"
    fi
  fi

  if [ "$1" != "" ] ; then
    _retVal=0
    case $1 in
      $_Y) GLOBAL_YN="Y" ;;
      $_N) GLOBAL_YN="N" ;;
      *) _retVal=1 ;;
    esac
  fi

  return $_retVal
}

## 
## Read the keyboard and returns 0 on NO and 1 ON yes
## This function uses $GLOBAL_YN to write tha answer in
## in addition to 0 and 1 return levels
## This function also uses $READ_TAB for formating.
## 
## $1 The text to be asked, otherwise "CONTINUE ? [Y/N]"
## $2 if set to 1, disable the usage of GLOBAL_YN
## 
function readYN()
{
  local YN=$GLOBAL_YN
  local TEXT=$READ_TAB"Continue ? [Y/N] "
  local retVal=0

  if [ "$2" != "" ] ; then
    if [ $2 -eq 1 ] ; then
      YN=""
    else
      echo "$READ_TAB""ERROR: Invalid value ($2) to disable use of GLOBAL_YN!"
      exit 1
    fi
  fi

  if [ "$1" != "" ] ; then
    TEXT="$READ_TAB$1 [Y/N] "
  fi

  if [ "$YN" != "" ] ; then
    echo "$TEXT$YN"
    case $YN in
     "y" | "Y") retVal=1 ;;
     "n" | "N") retVal=0 ;;
     *) 
       echo "Invalid automation value, switch to interactive!" 
       $YN=""
       ;;
    esac
  fi

  while [ "$YN" == "" ] ; do
    read -p "$TEXT" YN
    case $YN in
     "y" | "Y") retVal=1 ;;
     "n" | "N") retVal=0 ;;
     *) YN="" ;;
    esac
  done

  return $retVal
}

## 
## Start the program specified in $2 with parameters from $3..$x
## 
## $1   if 0 start normal, if 1 use sudo
## $2   program to start
## $3.. paramters (optional)
## 
function startPrg()
{
  local _retVal=1
  local _sudo=""
  local _cmd_file

  if [ "$2" != "" ] ; then
    _retVal=0

    if [ $1 -eq 1 ] ; then
      _sudo="sudo "
    fi
    shift
    _cmd_file="$1"
    shift

    if [ -e "$_cmd_file" ] ; then
      echo "Current Folder: $(pwd)"
      echo "Starting [$_sudo./$@]..."    
      $_sudo  ./$_cmd_file $@
      _retVal=$?
      if [ ! $_retVal -eq 0 ] ; then
        echo "ERROR '$_retVal' returned!"
      fi
    else
      echo "ERROR: Cannot find '$(pwd)/$_cmd_file'"
      echo "Abort operation"
      _retVal=1
    fi
  else
    echo "Incorrect number of parameters."
  fi

  return $_retVal
}

## 
## Check if something is listening on the given port
## 
## $1 The port to be checked.
## 
## return [1] if port is used, if not then [0]
## 
function isPortUsed()
{
  local _retVal=0
  if [ "$1" != "" ] ; then
    netstat -tulpn 2>/dev/null | grep ":$1 " > /dev/null
    if [ $? -eq 0 ] ; then
      _retVal=1
    fi
  fi
  return $_retVal
}

## 
## This function waits until the given port is found to be
## listened on or timeout occurred.
## 
## If the given port is 0 the check will be skiped and the
## function returns 0 - Minimum timeout is 1 sec
## 
## $1 Port to check
## 
## return 0 if port is found to be listened on, 1 if time out
## 
function _waitUntilLISTEN()
{
  local _retVal=1
  local _port=0
  local _timeout=0
  if [ "$1" != "" ] ; then
    _port=$1
  fi
  if [ "$2" != "" ] ; then
    _timeout=$2
  fi
  
  if [ $_port -gt 0 ] ; then
    while [ $_timeout -gt 0 ] ; do
      isPortUsed $_port
      if [ $? -eq 1 ] ; then
        _timeout=0
      else
        echo -n "."
        sleep 1
        _timeout=$(($_timeout-1))
      fi
    done
    isPortUsed $_port
    if [ $? -eq 1 ] ; then 
      _retVal=0
    else
      _retVal=1
    fi
  fi

  return $_retVal
}

##
## Count the number a specific value occurs in the 
## list of parameters.
##
## $1 The value to search for
 #
## $2..$n the parameters to look in
##
## Return How often the given value was found
##
function countInParameters()
{
  local _search=$1
  local _count=0
  shift
  while [ "$1" != "" ] ; do
    if [ "$1" == "$_search" ] ; then
      _count=$(($_count+1))
    fi
    shift
  done

  return $_count
}

#####################################################################
## Command Line Tester
#####################################################################

## 
## More elaborate test of function fill_SYS_IP
## 
function _test_ip ()
{
  local _retVal=0
  fill_SYS_IP $@
  _retVal=$?
  if [ $_retVal -eq 0 ] ; then
    echo "Selected:"
    for idx in ${!SYS_IP[@]} ; do
      echo "$SYS_IP_LBL_PFX${SYS_IP_LABEL[$idx]}$SYS_IP_LBL_SFX := ${SYS_IP[$idx]}"
    done
  else
    echo "Error: $_retVal"
  fi
  return $_retVal
}

# This allows the functions.sh script to be tested external
echo $0 | grep functions.sh >> /dev/null
FUNCTIONS_EMBEDDED_AS_LIBRARY=$?
if [ $FUNCTIONS_EMBEDDED_AS_LIBRARY -eq 0 ] ; then
  case $1 in
    "F-TEST")
      echo "Start functions.sh test script..."
      shift
      if [ "$1" == "" ] || [ "$1" == "--no-#" ] ; then
        echo "The following functions are available:"
        hash_reg="^## .*\|"
        cr="\n"
        if [ "$1" == "--no-#" ] ; then
          hash_reg=""
          cr=""
        fi
        cat $0 | grep -e "$hash_reg^function .*" | sed -e "s/^\(function .*\)/\1$cr/g"
        if [ "$cr" == "" ] ; then
          echo
        fi
        exit 0
      fi
      # Some test code
      _test=$1
      shift
      echo "Test function $_test $@"
      $_test $@
      retVal=$?
      echo "Return Value: $retVal"
      exit $retVal
      ;;
    *) echo "This library can be tested using"
      echo "  * $0 F-TEST <function> [parameters]"
      echo "    Test the given function with appropriate parameters"
      echo
      echo "  * $0 F-TEST [--no-#]"
      echo "    Return a ist of available functions with or without (--no-#)"
      echo "    documentation."
      ;;
  esac
fi
