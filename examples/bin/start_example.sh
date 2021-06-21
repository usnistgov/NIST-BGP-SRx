#!/bin/bash
# 
# Make sure we start in the demo folder
#
if [ "$_BGP_SRX_CALLER" == "" ] ; then
  echo "This starter script cannot be called directly!"
  exit 1
fi
echo "Start $_BGP_SRX_CALLER..."
_BGP_SRX_CALLER=

DEMO_FLDR=$(readlink -f $0 | xargs dirname)
DEMO_CURR_FLDR=$(pwd)
DEMO_PREFIX_FLDR=$(echo $DEMO_FLDR | sed -e "s/\(.*\)\/opt\/.*/\1/g")
DEMO_BIN_FLDR=$DEMO_PREFIX_FLDR/bin/
DEMO_SBIN_FLDR=$DEMO_PREFIX_FLDR/sbin/
DEMO_LIB_FLDR=$DEMO_PREFIX_FLDR/opt/bgp-srx-examples/lib

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

PRG_BIO=bgpsecio
PRG_CACHE=rpkirtr_svr
PRG_SRX=srx_server
PRG_ROUTER=bgpd

# Indicates if gnome-terminal is available & should be used in lieu of screen
TOOL_TERMINAL=0
USE_TERMINAL=0
which gnome-terminal > /dev/null
if [  $? -eq 0 ] ; then
  TOOL_TERMINAL=1
fi

# Perform the stop all untik $STOP_ALL_LOOP -eq 0
# This allows to tweak the stopping of all. 
# Recommended is 3
if [ "$STOP_ALL_LOOP" == "" ] ; then
  STOP_ALL_LOOP=3
fi

if [ "$SUDO_MODULES" == "" ] ; then
  SUDO_MODULES=()
fi
countInParameters "router" ${SUDO_MODULES[@]}
if [ $? -eq 0 ] ; then
  SUDO_MODULES+=("router")
fi

if [ "$SIT_AND_WAIT_TIME" == "" ] ; then
  SIT_AND_WAIT_TIME=10
fi
if [ "$SIT_AND_WAIT_MOD" == "" ] ; then
  SIT_AND_WAIT_MOD=()
fi
#countInParameters "bio1" ${SIT_AND_WAIT_MOD[@]}
#if [ $? -eq 0 ] ; then
#  SIT_AND_WAIT_MOD+=("bio1" )
#fi
#countInParameters "bio2" ${SIT_AND_WAIT_MOD[@]}
#if [ $? -eq 0 ] ; then
#  SIT_AND_WAIT_MOD+=("bio2" )
#fi
if [ "$SIT_AND_WAIT_MOD" == "" ] ; then
  SIT_AND_WAIT_MOD=()
fi

# Contains the parameters that can be globally used for each module
GLOB_PARAMS=( "-t" "--wait-for-enter" )

# These arrays are used for the automated starting and stopping.
# modules are started and stopped in this order
ALL_MOD_NAME=( "cache" "srx" "router" "bio1" "bio2" )
if [ "$PORT_CACHE" == "" ] ; then
  PORT_CACHE=50000
fi
if [ "$PORT_SRX" == "" ] ; then
  PORT_SRX=17900
fi
if [ "$PORT_ROUTER" == "" ] ; then
  PORT_ROUTER=179
fi
# These are the ports configured for each module in case the screen
# The module order is: cache srx router bio1 bio2
# did not show (happens sometimes) try to kill the app using the port
# port=0 skip
ALL_MOD_PORT=( $PORT_CACHE    $PORT_SRX  $PORT_ROUTER        0             0 )
# These ports are required by the specific module
ALL_MOD_PORT_REQ=( 0         $PORT_CACHE   $PORT_SRX    $PORT_ROUTER  $PORT_ROUTER )

if [ "$LISTEN_TIMEOUT" == "" ] ; then
  LISTEN_TIMEOUT=10
fi

# Configuration files to be used
if [ "$CFG_CACHE_NAME" == "" ] ; then
  CFG_CACHE_NAME="rpki_cache.script"
fi  
if [ "$CFG_SCA_NAME" == "" ] ; then
  CFG_SCA_NAME="srxcryptoapi.conf"
fi  
if [ "$CFG_SRX_NAME" != "" ] ; then
  CFG_SRX_NAME="srx_server.conf"
fi  
if [ "$CFG_ROUTER_NAME" == "" ] ; then
  CFG_ROUTER_NAME="as65000.bgpd.conf"
fi  
if [ "$CFG_BIO1_NAME" == "" ] ; then
  CFG_BIO1_NAME="as65005.bio.conf"
fi  
if [ "$CFG_BIO2_NAME" == "" ] ; then
  CFG_BIO2_NAME="as65010.bio.conf"
fi
CFG_CACHE=$DEMO_FLDR/$CFG_CACHE_NAME;
CFG_SCA=$DEMO_FLDR/$CFG_SCA_NAME
CFG_SRX=$DEMO_FLDR/$CFG_SRX_NAME
CFG_ROUTER=$DEMO_FLDR/$CFG_ROUTER_NAME
CFG_BIO1=$DEMO_FLDR/$CFG_BIO1_NAME
CFG_BIO2=$DEMO_FLDR/$CFG_BIO2_NAME

#
# Display the programs syntax
#
syntax()
{
  echo "$0 <module> [-t] [--wait-for-enter] | <command>"
  echo
  echo " --wait-for-enter Wait for the enter key to be pressed"
  echo "                  before the program ends." 
  echo
  echo " -t               Use the gnome-terminal in lieu of screen"
  echo "                  when using <all> or <select>"
  if [ $TOOL_TERMINAL -eq 0 ] ; then
    echo "                  IMPORTANT: gnome-terminal required to work!!"
  fi
  echo
  echo "Command:"
  echo "  view-table: Display the content of the BGP router's RIB-IN"
  echo "  view-all    Display all 'screens' available"
  echo "  stop-all    Stop all BGP-SRx 'screens'"
  echo 
  echo "Module:"
  echo "  all"
  echo "           Start all modules (root privileges required!)"
  echo "           This uses screen and starts all but the router in the"
  echo "           users environment and router as root."
  echo "  select <module> [ <module>]*"
  echo "           Functions in thesame way as all except it does not use"
  echo "           all modules in the predefined order, it starts modules"
  echo "           in the order as scripted and only the scripted ones."
  echo 
  echo "  cache    Start the RPKI Router Cache Test Harness"
  echo "  srx      Start the SRx Server"
  echo "  router   Start the Quagga router (root privileges required!)"
  echo "  bio1     Start BGPsec-IO traffic generator 1"
  echo "  bio2     Start BGPsec-IO traffic generator 2"
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
  cd $DEMO_CURR_FLDR
  echo
  exit $1
}

#
# Start the program specified in the parameters
#
# $1 The program to be started
# $2..n The programs parameter.
#
# return 0 if all went fine
#
function startPrg()
{
  local _retVal=1
  local _sudo=""
  local _sudo_text=""
  local _program="$1"

  if [ "$(whoami)" == "root" ] ; then
    _sudo="sudo "
    _sudo_text=" as 'root'"
  fi
  shift

  if [ "$_program" != "" ] ; then
    if [ -e $_program ] ; then
      echo "Current Folder: $(pwd)"
      echo "Starting [$_sudo./$2 $3 $4 $5 $6]$_sudo_text..."    
      $_sudo./$_program $@
      _retVal=$?

      if [ ! $_retVal -eq 0 ] ; then 
        echo "ERROR '$_retVal' returned!"
        _retVal=$_retVal
      fi
    else
      echo "ERROR: Cannot find './$_program'"
      echo "Abort operation"
      _retVal=1
    fi
  fi

  return $_retVal
}

#
# Start the given  module in a screen session.
# Return 0 if it was successfull, otherwse 1
#
# $1 "screen" or "terminal"
# $2 The module to be started
# $3 A tabulator for formating (optional)
#
function _startModuleIn()
{
  local _retVal=0
  local _thread=$1
  local _module=$2
  local _sudo_cmd=""
  local _tab="$3"
  local _counter=0
  local _activate=""

  shift
  if [ "$_module" != "" ] ; then
    countInParameters $_module ${SUDO_MODULES[@]}

    if [ $? -gt 0 ] ; then
      if [ "$root" != "root" ] ; then
        _sudo_cmd="sudo"
        echo "$_tab""Module [$_module] requires sudo priviledges!"
        # Allow to enter for terminal
        _activate="--active"
      fi
    fi

    # Check if this module is already active as a screen
    case "$_thread" in
      "screen")
         $_sudo_cmd screen -ls | grep "\.$_module " > /dev/null 2>&1
         _retVal=$?
         ;;
      "terminal")
         _retVal=1
         ;;
      *)
         _retVal=1
         ;; 
    esac
   
    if [ $_retVal -eq 0 ] ; then
      echo "$_tab""A $_thread module with this name is already active!"
    else
      echo "$_tab- Starting module '$_module'..."
      case "$_thread" in
        "screen")
          $_sudo_cmd screen -S "$_module" -d -m $0 $_module --wait-for-enter
          _retVal=$?
          ;;
        "terminal")
          gnome-terminal --title "$_module" --tab $_activate -- /bin/bash -c "$_sudo_cmd $0 $_module --wait-for-enter"
          _retVal=$?
          ;;
        *)
          _retVal=1
          ;;
      esac

      if [ $_retVal -eq 0 ] ; then
        echo "$_tab  Start successful!"
      else
        echo "$_tab  Start failed!"
      fi
      countInParameters $_module ${SIT_AND_WAIT_MOD[@]}
#      if [ $? -gt 0 ] ; then
#        echo -n "$_tab  Add delay after staring of $SIT_AND_WAIT_TIME seconds"
#        _counter=$SIT_AND_WAIT_TIME
#        while [ $_counter -gt 0 ] ; do
#          echo -n "."
#          sleep 1
#          _counter=$(($_counter-1))
#        done
#        echo "done"
#      fi 
    fi
  fi
  return $_retVal
}

#
# This function does start all components needed
#
# $1..$n The modules to be started
#
function runAutomated()
{
  local _retVal=0
  local _loopCounter=20
  local _MODULES=$@
  local _useTimeout=$LISTEN_TIMEOUT
  local _waitCounter=$SIT_AND_WAIT_TIME
#  local _PID=()
#  local _sudo=""

  echo "Perform tool check..."
  for tool in ${REQ_TOOLS[@]} ; do
    echo -n "Check for '$tool'..."
    which $tool > /dev/null 2>&1
    if [ $? -eq 0 ] ; then
      echo "Found!"
    else
      echo "Missing!"
      return 1
    fi
  done

  echo "Verify if any requested module is still running..."
  for _checkModule in ${_MODULES[@]} ; do
    # First check the screen tool
    if [ -e /tmp/$_checkModule.pid ] ; then
      pid=$(cat $_checkModule | sed -e "s/ //g")
      if [ "$pid" != "" ] ; then
        ps aux | awk '{ print $2 }' | grep "^$pid$"
        if [ $? -eq 0 ] ; then
          _retVal=1
          echo "Found other instances of '$_checkModule'"
        fi 
      fi
    fi
    if [ $_retVal -eq 1 ] ; then
      echo "Please stop all running instances!"
    fi
  done

  if [ $_retVal -eq 0 ] ; then
    # cache can be started right away
    # srx should wait 2 seconds to allow caceh to fully start
    # router should wait for 5 seconds to allow srx server to accept connections
    # bio1 should wait 5 seconds for router to be able to accept connections
    # bio2 can start right after bio1

    echo "Starting modules: ${_MODULES[@]}"
    # Check if I need to add some sit and wait modules
    countInParameters "router" ${_MODULES[@]}
    if [ $? -gt 0 ] ; then
      # Just in case, add bio1 and bio2 into the sit and wait
      SIT_AND_WAIT_MOD+=( "bio1" "bio2" )
    fi
    for _mod_idx in ${!ALL_MOD_NAME[@]} ; do
      # Check if this module is part of the requested modules.
      countInParameters ${ALL_MOD_NAME[$_mod_idx]} ${_MODULES[@]}
      if [ $? -gt 0 ] ; then
        if [ $_retVal -eq 0 ] ; then
          echo "  * Start module ${ALL_MOD_NAME[$_mod_idx]}"
          ## 1st Check if the required port is available to accept connections
          if [ ${ALL_MOD_PORT_REQ[$(($_mod_idx))]} -gt 0 ] ; then
            echo -n "    - Wait until port ${ALL_MOD_PORT_REQ[$(($_mod_idx))]} is ready"
            _waitUntilLISTEN ${ALL_MOD_PORT_REQ[$(($_mod_idx))]} $LISTEN_TIMEOUT
            _retVal=$?
            if [ $_retVal -eq 0 ] ; then
              echo "...done!"
            else
              echo "...time out!"
            fi
          fi
          # 2nd sit and wait until time has passed in case module is in sit and wait array
          countInParameters ${ALL_MOD_NAME[$_mod_idx]} ${SIT_AND_WAIT_MOD[@]}
          if [ $? -gt 0 ] ; then
            echo -n "    - Delay start by $SIT_AND_WAIT_TIME seconds"
            _waitCounter=$SIT_AND_WAIT_TIME
            while [ $_waitCounter -gt 0 ] ; do
              _waitCounter=$(($_waitCounter-1))
              echo -n "."
              sleep 1
            done
            echo "done."
          fi

          # 3rd Start the module
          if [ $_retVal -eq 0 ] ; then
            if [ $USE_TERMINAL -eq 0 ] ; then
              _startModuleIn screen ${ALL_MOD_NAME[$_mod_idx]} "    "
              _retVal=$?
            else
              _startModuleIn terminal ${ALL_MOD_NAME[$_mod_idx]} "    "
              _retVal=$?
            fi
          fi
          # 4th Verify that the current module is listening on the required port.
          if [ $_retVal -eq 0 ] ; then
            if [ ${ALL_MOD_PORT[$(($_mod_idx))]} -gt 0 ] ; then
              echo    "    - Timeout: $_useTimeout sec."
              echo -n "    - Wait until ${ALL_MOD_NAME[$(($_mod_idx))]} listens on port ${ALL_MOD_PORT[$(($_mod_idx))]}"
              _waitUntilLISTEN ${ALL_MOD_PORT[$(($_mod_idx))]} $_useTimeout
              _retVal=$?
              if [ $_retVal -eq 0 ] ; then
                echo "...done!"
              else
                echo "...time out!"
              fi
            fi
          fi
          if [ ! $_retVal -eq 0 ] ; then
            echo "      Module ${ALL_MOD_NAME[$_mod_idx]} did not start properly!"
          fi          
        fi
        _useTimeout=$LISTEN_TIMEOUT
      else
        # Skip this module so reduce the timeout for port listening to 0
        _useTimeout=0
      fi
    done
  fi

  viewAll
  return $_retVal;
}

#
# This function displays all screen sessions found
#
function viewAll()
{
  echo "Screen for ($(whoami)):"
  screen -ls | grep "(Detached)"
  echo "Screen for (root):"
  sudo screen -ls | grep "(Detached)"
  echo ${view[@]}
}


#
# This function checks is the experiment is started using screen
# and stops all instances it can find
#
function stopAll()
{
  if [ "$1" != "" ] ; then
    echo $1
  fi
  local _sudo_cmd
  local _user=$(whoami)
  local _mod_user=""
  local _program=()
  local _endLoop=10

  for _mod_idx in ${!ALL_MOD_NAME[@]} ; do
     _running_mod=${ALL_MOD_NAME[$_mod_idx]}
     _running_port=${ALL_MOD_PORT[$_mod_idx]}

    _program=( $(ps aux | grep -e start.sh | grep -e "$_running_mod" | head -n 1 | awk '{ print $1 " " $2 }' ) )
    _mod_user="${_program[0]}"
    _mod_pid="${_program[1]}"
    if [ "$_mod_pid" == "" ] ; then
      # Now try to find the port number
      echo "  * Module [$_running_mod]: No instance found!"
      if [ $_running_port -gt 0 ] ; then
        # try to find the progam using the port number
        countInParameters "$_running_mod" ${SUDO_MODULES[@]}
        if [ $? -eq 0 ] ; then
          _sudo_cmd=""
          _user_mod="$_user"
        else
          _sudo_cmd="sudo "
          _user_mod="root"
        fi
        echo "    - Try to identify a running instance using the port '$_running_port'..."
        _mod_pid=$($_sudo_cmd netstat -tulpn 2>/dev/null | grep -e "[^0-9]$_running_port[^0-9]" | sed -e "s/.*LISTEN[^0-9]*\([0-9]\+\)[^0-9].*/\1/g" | sort -u)
        if [ "$_mod_pid" == "" ] ; then
          echo "      * Not Found!"
        else
          echo "      * Found!"
        fi
      fi
    fi
    ## Now try again, maybe the running mod needed root priv to get
    ## the proper pid.
    if [ "$_mod_pid" != "" ] ; then
      # Help prevent an endless loop
      _endLoop=10
      while [ "$_mod_pid" != "" ] && [ $_endLoop -gt 0 ] ; do
        _endLoop=$(($_endLoop-1))
        if [ "$_mod_user" != "$_user" ] ; then
          _sudo_cmd="sudo "
        else
          _sudo_cmd=""
        fi  
        readYN "  - Stopping module '$_running_mod' [$_mod_pid] ?"
        if [ $? -eq 1 ] ; then
          $_sudo_cmd kill -9 $_mod_pid > /dev/null
          $_sudo_cmd screen -wipe > /dev/null
        else
          echo "    * Abort stopping module '$_running_mod'!"
          _endLoop=0
        fi
        _program=( $(ps aux | grep -e start.sh | grep -e "$_running_mod" | head -n 1 | awk '{ print $1 " " $2 }' ) )
        _user="${_program[0]}"
        _mod_pid="${_program[1]}"
      done
    fi
  done
}

# Switch into the demo folder
cd $DEMO_FLDR

if [ "$1" == "" ] ; then
  syntax 0
fi 

#echo "Current folder...: $DEMO_CURR_FLDR"
#echo "DEMO Folder......: $DEMO_FLDR" 
#echo "DEMO_PREFIX_FLDR.: $DEMO_PREFIX_FLDR"
#echo "DEMO_BIN_FDLR....: $DEMO_BIN_FLDR"
#echo "DEMO_SBIN_FDLR...: $DEMO_SBIN_FLDR"

# Check that all files are configured
CFG_FILES=("$CFG_CACHE" "$CFG_SRX" "$CFG_SCA" 
           "$CFG_ROUTER" "$CFG_BIO1"  "$CFG_BIO2")

# List of tools required for the "all" mode
REQ_TOOLS=("/bin/bash" "screen" "netstat" "awk")

for cfg_file in "${CFG_FILES[@]}" ; do 
  if [ ! -e "$cfg_file" ] ; then
    echo "Configuration file: '$cfg_file' not found!"
    echo "Make sure the project is configured properly!"
    endPrg 1
  fi
done

retVal=0
READ_ENTER=0
_PARAMS=( $(echo $@) )
for param in ${_PARAMS[@]} ; do
  case $param in 
    "--wait-for-enter") 
      READ_ENTER=1 
      ;;
    "-t") 
      if [ $TOOL_TERMINAL -eq 1 ] ; then
        echo "Enable usage of terminal, do not use screen!"
        USE_TERMINAL=1
      else
        echo "WARNING: gnome-terminal is not installed."
        endPrg 1
      fi
      ;;
    *)
      ;;
  esac
done

_modules=()
if [ $retVal -eq 0 ] ; then
  case "$1" in
    "?" | "-?" | "h" | "H" | "-h" | -"H")
      syntax 0
      ;;
    "view-table")
      echo "Display the routing table:"
      echo "=========================="
      { sleep 1; echo "zebra"; sleep 1; echo "enable"; sleep 1; echo "show ip bgp"; sleep 3; } | telnet localhost 2605
      ;;
    "view-all")
      viewAll
      retVal=$?
      ;;
    "stop-all")
      STOP_ALL_LABEL="Stopping all screen modules..."
      if [ $STOP_ALL_LOOP -eq 0 ] ; then
        STOP_ALL_LOOP=1
      fi
      while [ $STOP_ALL_LOOP -gt 0 ] ; do
        stopAll $STOP_ALL_LABEL
        STOP_ALL_LABEL=
        STOP_ALL_LOOP=$(($STOP_ALL_LOOP-1))
        if [ $STOP_ALL_LOOP -gt 0 ] ; then
          sleep 1
        fi
      done
      screen -wipe >> /dev/null 2>&1
      viewAll
      retVal=$?
      READ_ENTER=0
      ;;
    "select")
      shift
      while [ "$1" != "" ] ; do
        countInParameters  $1 ${ALL_MOD_NAME[@]}
        if [ $? -gt 0 ] ; then
          _modules+=( $1 )
        else  
          countInParameters $1 ${GLOB_PARAMS[@]}
          if [ $? -eq 0 ] ; then
            echo "Invalid module!"
            endPrg 1          fi
          fi
        fi
        shift
      done
      runAutomated ${_modules[@]}
      _retVal=$?
      echo
      if [ ! $_retVal -eq 0 ] ; then
        echo "An error occured during starting one of the modules."
      fi
      echo "Use 'screen -r -S <screen-name>' to reattach to any screen."
      echo "Once reattached, press 'Ctrl-a d' to detach again."
      echo "For more information on how to use screen, use 'man screen'."
      echo "Call $0 view-table to see the routers RIB-IN."
      READ_ENTER=0
      ;;
    "all")
      runAutomated ${ALL_MOD_NAME[@]}
      _retVal=$?
      echo
      if [ ! $_retVal -eq 0 ] ; then
        echo "An error occured during starting one of the modules."
      fi
      echo "Use 'screen -r -S <screen-name>' to reattach to any screen."
      echo "Once reattached, press 'Ctrl-a d' to detach again."
      echo "For more information on how to use screen, use 'man screen'."
      echo "Call $0 view-table to see the routers RIB-IN."
      READ_ENTER=0
      ;;
    "cache")
      cd $DEMO_BIN_FLDR
      startPrg "./$PRG_CACHE" "-f" "$CFG_CACHE" $PORT_CACHE
      retVal=$?
      ;;
    "srx")
      cd $DEMO_BIN_FLDR
      startPrg "./$PRG_SRX" "-f" "$CFG_SRX"
      retVal=$?
      ;;
    "router")
      cd $DEMO_SBIN_FLDR
      startPrg "./$PRG_ROUTER" "-f" "$CFG_ROUTER"
      retVal=$?
      ;;
    "bio1")
      cd $DEMO_BIN_FLDR
      startPrg "./$PRG_BIO" "-f" "$CFG_BIO1"
      retVal=$?
      ;;
    "bio2")
      cd $DEMO_BIN_FLDR
      startPrg "./$PRG_BIO" "-f" "$CFG_BIO2"
      retVal=$?
      ;;
    *)
      echo "Unknown Module '$1'"
      retVal=$?
      READ_ENTER=0
      ;;
  esac
fi

if [ $READ_ENTER -eq 1 ] ; then
  read -p "Press Enter "
fi
endPrg $retVal
