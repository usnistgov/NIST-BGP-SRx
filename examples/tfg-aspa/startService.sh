#!/bin/bash
#
# This script performs the experimentation. It is recommended tostart this script
# using the 'run.sh' script, it functions as a wrapper and is much simpler to 
# use. For more information on how to use this script, call it with the parameter '-?'
#
# Version 0.1.0.0
#

_HOME="$(pwd)"
_CONF="$_HOME/config"
_RESULT_FLDR="$_HOME/data-result"
_EXPERIMENT_FLDR="$_HOME/data-experiment"
if [ "$CONFIGURED" == "" ] ; then
  . system_env.sh
  # system_env attempts to configure
  # _LOCAL
  # _BIN
  # _SBIN
fi
if [ $CONFIGURED -eq 0 ] ; then
  echo "System not completely configured! Edit 'system_env.sh'!"
  exit 1
fi

_LOG_DIR="$_HOME/log"
# Use a gnome terminal for each module
_USE_TERMINAL=0
# If set to 1 request keyboard input before the terminal will be closed again
_WAIT_FOR_KEY=0
# Specify the first IP that is not loopback if no system wide IP is specified in _SYSTEM_IP
if [ "$_SYSTEM_IP" == "" ] ; then
  ips=( $( ip addr | grep "inet " | sed "/.* 127\..*/d" | awk '{ print $2 }' | sed -e "s#/[0-9]\+##g") ); 
  _SYSTEM_IP=${ips[0]}
  ips=""
fi
# Wait time in seconds after QuaggaSRx is started
_WAIT_FOR_QUAGGA=10
# Wait time in seconds after SRx-Server is started
_WAIT_FOR_SRX=5

# for show-data
_USE_RESULT_FILE=0
# Final sleep for telnet when retrieving data to prevent session from closing before
# any data is received.
_TELNET_SLEEP=20

if [ "$_SYSTEM_IP" == "" ] ; then
  echo "Unable to determine a system IP Addr"
  echo "Set environment variable _SYSTEM_IP=\"a.b.c.d\" for IP address to be used."
  exitScript 1
else
  ping -c 1 $_SYSTEM_IP > /dev/null 2>&1
  if [ ! $? -eq 0 ] ; then
    echo "Unable to ping my own IP address $_SYSTEM_IP!"
    echo "Edit script and manually add specify working IP address!"
    exitScript 1
  fi
fi

if [ ! -e $_LOG_DIR ] ; then
  mkdir -p $_LOG_DIR
  echo $_LOG_DIR >> $_HOME/.gitignore
fi

_PEERING_AS=""
_PEERING_REL=""
_UPDATE_COUNT=""

_NO_SHOW=0
_SHOW_DOT="/dev/stdout"

_START_TIME=$( date +%s )
_PRINT_RUNTIME=0

#
# Exit the program and prints the runtime to standard error 
# if sepcified by script parameter --runtime
#
# $1 The exit code
#
function exitScript()
{
  if [ $_PRINT_RUNTIME -eq 1 ] ; then
    local _end_time=$( date +%s )
    local _time=$(($_end_time-$_START_TIME))
    local _hours=$(($_time / 3600))
    local _minutes=$((($_time % 3600)/60))
    local _seconds=$(($_time % 60))
    echo "Runtime: $_hours:$_minutes:$_seconds" > /dev/stderr
  fi

  exit $1
}


#
# Print out the script syntax and exit
#
# $1 The exit code (optional)
#
function syntax()
{
   echo
   echo "Syntax: $(basename $0) [-t] [-w] [--no-show] [--show-dot] [--runtime] (-?|-h|list|stop|show-data <peer> [-f]|<peer> <relation> <updates>)"
   echo
   echo "   -t                    Start each module in a gnome terminal"
   echo "   -w                    Wait for key pressed before closing terminal."
   echo "   --no-show             Don't show data during regular run, don't ask for it!"
   echo "   --show_dot            Display dots wile waiting using error output!"
   echo "   --runtime             display the runtime of the script to standard error"  
   echo
   echo "   -?, -h                This screen."
   echo "   list                  Display the possible peer and update selections that can be made"
   echo "   stop                  Stop all running services."
   echo "   show-data <peer> [<update_count>] [-f] Display the RIB-IN in ASPA formated form"
   echo "                         <validation>, <path>"
   echo "                         In case a peer is specified only the AS Path's with this peer"
   echo "                         are displayed!"
   echo "                         If update count is provided it is used for the file name. Though"
   echo "                         a warning is displayed in case the number of stored updats for the"
   echo "                         given peer does not match the number that is provided."
   echo "                         In case '-f' is provided, the output will be stored a result file"
   echo "                         with the name result.<PEER>-<#UPDATES|num>-<RELATION>.txt"
   echo "   <peer>                The AS number of the peer to be used."
   echo "   <relation>"
   echo "      provider, p, P - The peer is a topologically upstream neighbor (transit provider)"
   echo "      customer, c, C - The peer is a topologically downstream (customer AS)"
   echo "      sibling, s, S  - The peer is transit provider and transit customer."
   echo "      lateral, l, L  - The peering only includes prefixes of customers."
   echo "   <updates>    The number of updates generated."
   echo
   exitScript $1
}

#
# Stop the Cache, SRx-Servr and QuaggaSRx
#
function stopService()
{
   echo
   sudo killall -9 bgpd >> /dev/null 2>&1
   killall -9 bgpsecio >> /dev/null 2>&1
   killall -9 rpkirtr_svr >> /dev/null 2>&1
   killall -9 srx_server >> /dev/null 2>&1
}

#
# List all selections that can be made
#
function listSelections()
{
  local selections=( $(ls | grep -e "^[0-9]\+\-[0-9]\+\-data-.*" \
                          | sed -e "s/^\([^\-]\+\)\-\([^\-]\+\)\-.*/\1 \2/g" \
                          | sort -u) )
  local counter=0
  echo
  if [ ${#selections[@]} -gt 0 ] ; then
    echo "The following selections can be made:"
    while [ $counter -lt ${#selections[@]} ] ; do
      echo -n "  ./$(basename $0) ${selections[$counter]} "
      ((counter++))
      echo "[P|C|S|L] ${selections[$counter]}"
      ((counter++))
    done
  else
    echo "Run the data generation script first to get data!"
  fi
  echo
  exitScript
}

#
# This function retrieves the RIB in from QuaggaSRx
#
# $1 The peer AS to be queried or all (optional)
#
function showData()
{
  # First make sure the router is doen receiveing updates from the peer
  # First get the peering IP
  local _peer_ip=$($_HOME/current_config.sh $_PEERING_AS ip)

  if [ "$_peer_ip" == "" ] ; then
    echo "ERROR: AS$_PEERING_AS is not a configured peer!" > /dev/stderr
    exitScript 1
  fi 
  # Now get the number of updates (query twice and see if the number changes)
  local _num_updates_prev=$($_HOME/router_cmd.sh "show ip bgp neighbors $_peer_ip" 2 2>/dev/null \
                 | grep -e "^[[:space:]]\+Updates:" | awk ' { print $3 } ' | sed -e "s/[\r]//g")
  sleep 1
  local _num_updates=$($_HOME/router_cmd.sh "show ip bgp neighbors $_peer_ip" 1 2>/dev/null \
                 | grep -e "^[[:space:]]\+Updates:" | awk ' { print $3 } ' | sed -e "s/[\r]//g")
  
  if [ $_num_updates_prev -lt $_num_updates ] ; then
    echo -n "Router still receiving updates from AS$_PEERING_AS"
    while [ $_num_updates_prev -lt $_num_updates ] ; do
      echo -n "." > $_SHOW_DOT
      _num_updates_prev=$_num_updates
      #                                                             sleep for 1 second
      _num_updates=$($_HOME/router_cmd.sh "show ip bgp neighbors $_peer_ip" 1 2>/dev/null \
                     | grep -e "^[[:space:]]\+Updates:" | awk ' { print $3 } ' | sed -e "s/[\r]//g")
    done 
    echo "done"
  fi

  # Now check if the validation is still ongoing. This the case if still unverified "?" ASPA results
  # are stored in the table. This runs until either the validation did not update for 5 consecutive
  # calls or no "?" is found anymore. 
  local _missing_validation=$($_HOME/router_cmd.sh "show ip bgp" 2>/dev/null | grep -e ".*(.,.,?)" | wc -l)
  local _prev_missing=$_missing_validation
  if [ $_missing_validation -gt 0 ] ; then 
    echo -n "Validation still in progress.-."
  fi
  local _symbol=("-" ".")
  local _position=0
  local _stop=5
  while [ $_missing_validation -gt 0 ] && [ $_stop -gt 0 ] ; do
    echo -n ${_symbol[_position]} > $_SHOW_DOT
    ((_position++))
    if [ $_position -eq 2 ] ; then
      _position=0
    fi
    _prev_missing=$_missing_validation
    _missing_validation=$($_HOME/router_cmd.sh "show ip bgp" 2 2>/dev/null | grep -e ".*(.,.,?)" | wc -l)
    if [ $_prev_missing -eq $_missing_validation ] ; then
      ((_stop--))
    else
      _stop=5
    fi
    # allow the router to process.
    sleep 5
  done
  

  if [ ! $_num_updates_prev -eq $_num_updates ] ; then
    echo "Router not ready to print data, still receiveing data ($_num_updates...), try later again!"
    exitScript 1
  fi

  if [ $_missing_validation -gt 0 ] ; then
    echo "Router did not verify all routes yet, ($_missing_validation routers not validated, try later again!"
    exitScript 1
  fi

  # Now get the data
  _peering_rel=$($_HOME/current_config.sh $_PEERING_AS rel)
  echo -n "Start showing data for $_peering_rel AS '$_PEERING_AS'..."
  local output="/dev/stdout"
  local peerStr=" $_PEERING_AS"
  if [ $_USE_RESULT_FILE -eq 1 ] ; then
    output="$_RESULT_FLDR/result-$_PEERING_AS-$_UPDATE_COUNT-$_peering_rel.txt"
    echo -n "use file '$output'..."
  else
    echo
  fi
  $_HOME/router_cmd.sh "show ip bgp" 2>/dev/null \
                       | grep -e ".*(.,.,.)" \
                       | sed -e "s/^.*(.,.,\(.\)).*\($peerStr [0-9\. ]*\)./\1 \2/g" > $output
  echo "Done"
  if [ $_USE_RESULT_FILE -eq 1 ] ; then
    cat $output
  fi
  exitScript
}

#
# Parse through the handed parameters
#
# $1..$n Parameters to be parsed
#
# return the number of used parameters 
#
function parseParameters()
{
   local used=0
   while [ "$1" != "" ] ; do
     case "$1" in
       "-t") ((used++)); _USE_TERMINAL=1 ;;
       "-w") ((used++)); _WAIT_FOR_KEY=1 ;;
       "--no-show")  ((used++)); _NO_SHOW=1 ;;
       "--show-dot") ((used++)); _SHOW_DOT="/dev/stderr" ;;
       "--runtime")  ((used++)); _PRINT_RUNTIME=1 ;; 
       *)  return $used;;
     esac
     shift
   done
}

parseParameters $@
_retVal=$?
# Remove the used parameters
while [ $_retVal -gt 0 ] ; do
  shift
  ((_retVal--))
done

case "$1" in
  "-?" |"-h") syntax ;;
  "stop") echo -n "Stop Router, SRx-Server, and Cache..."
      stopService
      echo "done!"
      exitScript
      ;;
   "list") listSelections ;;
   "show-data") shift ; 
      _PEERING_AS=$1
      _UPDATE_COUNT="0"
      shift
      while [ "$1" != "" ] ; do
        case "$1" in
          "-f") _USE_RESULT_FILE=1 ;;
          *) _UPDATE_COUNT=$1
        esac
        shift
      done
      showData
      ;;
   *) ;;
esac

_PEERING_AS=$1
shift
case "$1" in
   "customer" | "C" | "c")
      _PEERING_REL="customer"
      ;;
   "provider" | "P" | "p")
      _PEERING_REL="provider"
      ;;
   "lateral" | "L" | "l")
      _PEERING_REL="lateral"
      ;;
   "sibling" | "s" | "S")
      _PEERING_REL="sibling"
      ;;
   "") echo "Specify the peering relation!"
      exitScript 1
      ;;
   *) echo "Invalid parameter '$1'!"
      exitScript 2
      ;;
esac
shift

_UPDATE_COUNT=$1
shift

if [ "$1" != "" ] ; then
  echo "Invalid parameter '$1'!"
  syntax 1
fi


cd $_CONF
echo -n "Prepare router config..."
cat bgpd.conf.tpl | sed -e "s/{PEERING_AS}/$_PEERING_AS/g" \
                  | sed -e "s/{PEER_IP}/$_SYSTEM_IP/g" \
                  | sed -e "s/{PEERING_RELATION}/$_PEERING_REL/g" > bgpd.conf 
echo "done"

echo -n "Prepare bgpsecio config..."
cat bio.conf.tpl | sed -e "s#{LOCAL}#$_LOCAL#g" \
                 | sed -e "s#//#/#g" \
                 | sed -e "s/{PEER_IP}/$_SYSTEM_IP/g" \
                 | sed -e "s/{BIO_ASN}/$_PEERING_AS/g" > bio.conf
echo "done"

echo -n "Check necessary files..."
_CACHE_CONFIG="$_EXPERIMENT_FLDR/$_PEERING_AS-$_UPDATE_COUNT-data-aspa.cache"
if [ ! -e $_CACHE_CONFIG ] ; then
  echo "'$_CACHE_CONFIG' not found!"
  exitScript 1
fi
_BIO_UPDATES="$_EXPERIMENT_FLDR/$_PEERING_AS-$_UPDATE_COUNT-data-updates.bio"
if [ ! -e $_BIO_UPDATES ] ; then
  echo "'$_BIO_UPDATES' not found!"
  exitScript 1
fi
echo "found!"

echo "Stop cache, srx_server, and quagga if running" 
stopService

if [ $_USE_TERMINAL -eq 1 ] ; then
   which gnome-terminal > /dev/null
   if [ ! $? -eq 0 ] ; then
      _USE_TERMINAL=0
      echo "WARNING: Cannot use gnome terminal, 'gnome-terminal' not found!"
   fi
fi 

_LOG_PREFIX="$_PEERING_AS-$_UPDATE_COUNT-$_PEERING_REL"
cd $_BIN

if [ $_WAIT_FOR_KEY -eq 1 ] ; then
  _pressKey="read -p \"Press any key!\""
else
  _pressKey=""
fi

module="RPKI Cache Test Harness"
echo -n "Start $module..."
_cmd="./rpkirtr_svr 50000 -f $_CACHE_CONFIG"
if [ $_USE_TERMINAL -eq 1 ] ; then
  echo -n "using Terminal '$module' with command '$_cmd'..."
  gnome-terminal --title "$module" --tab -- /bin/bash -c "$_cmd; $_pressKey"
  _retVal=$?
else
  $_cmd > $_LOG_DIR/$_LOG_PREFIX-cache.log 2>&1 &
#  ./rpkirtr_svr 50000 -f $_CACHE_CONFIG > $_LOG_DIR/$_LOG_PREFIX-cache.log 2>&1 &
fi
echo "done"

module="SRx Server"
echo -n "Start $module..."
_cmd="./srx_server -f $_CONF/srx_server.conf"
if [ $_USE_TERMINAL -eq 1 ] ; then
  echo -n "using Terminal '$module' with command '$_cmd'..."
  gnome-terminal --title "$module" --tab -- /bin/bash -c "$_cmd; $_pressKey"
  _retVal=$?
else
  $_cmd > $_LOG_DIR/$_LOG_PREFIX-srx_server.log 2>&1 &
#  ./srx_server -f $_CONF/srx_server.conf > $_LOG_DIR/$_LOG_PREFIX-srx_server.log 2>&1 &
fi
echo "done"

echo -n "Wait $_WAIT_FOR_SRX seconds"
sec=0
while [ $sec -lt $_WAIT_FOR_SRX ] ; do
  sleep 1
  ((sec++))
  echo -n "."
done
echo

cd $_SBIN
module="QuaggaSRx"
echo -n "Start $module..."
_cmd="sudo ./bgpd -f $_CONF/bgpd.conf"
if [ $_USE_TERMINAL -eq 1 ] ; then
  echo -n "using Terminal '$module' with command '$_cmd'..."
  gnome-terminal --title "$module" --tab --active -- /bin/bash -c "$_cmd; $_pressKey"
  _retVal=$?
else
  $_cmd -d > $_LOG_DIR/$_LOG_PREFIX-bgpd.log 2>&1
#  sudo ./bgpd -f $_CONF/bgpd.conf -d > $_LOG_DIR/$_LOG_PREFIX-bgpd.log 2>&1
fi
echo "done"

echo -n "Wait $_WAIT_FOR_QUAGGA seconds"
sec=0
while [ $sec -lt $_WAIT_FOR_QUAGGA ] ; do
  sleep 1
  ((sec++))
  echo -n "."
done
echo

cd $_BIN
module="BIO traffic"
echo "Start $module..."
_cmd="cat $_BIO_UPDATES | ./bgpsecio -f $_CONF/bio.conf"
if [ $_USE_TERMINAL -eq 1 ] ; then
  echo -n "using Terminal '$module' with command '$_cmd'..."
  gnome-terminal --title "$module" --tab -- /bin/bash -c "$_cmd; $_pressKey"
  _retVal=$?
else
  $_cmd > $_LOG_DIR/$_LOG_PREFIX-bio.log 2>&1 &
#  cat $_BIO_UPDATES | ./bgpsecio -f $_CONF/bio.conf > $_LOG_DIR/$_LOG_PREFIX-bio.log 2>&1 &
fi
echo "done"

cd $_HOME

if [ $_NO_SHOW -eq 0 ] ; then
  read -p "Press R for results! " _KEY
  _command="./$(basename $0) show-data -f $_PEERING_AS $_UPDATE_COUNT"
  if [ "$_KEY" == "r" ] || [ "$_KEY" == "R" ] ; then
    echo "$_command"
    $_command
  else
    echo "Now retrieve data using '$_command'"
  fi
fi
exitScript
