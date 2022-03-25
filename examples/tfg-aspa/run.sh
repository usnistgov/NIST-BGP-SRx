#!/bin/bash
#
# This script is teh main wrapper for starting experimanes.
#
# Prior to starting an experiment read the README.md file to see what 
# preerequisites are necessary to perform a successfull experimentation.
#
# Version 0.1.0.0
#

if [ "$2" == "" ] ; then
  echo "Syntax: $(basename $0) <peer> <no-updates>"
  exit 1
fi
_HOME="."

# Test for sudo privileges that areneeded for QuaggaSRx
echo "Test sudo privileges that are needed to start bgpd"
echo "Attempt to run 'sudo ls .' ...."
sudo ls > /dev/null 2>&1
if [ $? -eq 0 ] ; then
  echo "success"
else
  echo "failed!"
  echo "Abort, user has insufficient rights to start QuaggaSRx: 'bgpd'."
  exit 1
fi
peer=$1
updates=$2
relations=( "provider" "customer" "sibling" "lateral" )

for  relation in ${relations[@]} ; do
  start_time=$(date +%s)
  echo "Start all services and run the experiment: peer $peer as $relation, IUT receives $updates UPDATES ..."
  $_HOME/startService.sh -t --no-show $peer $relation $updates
  retVal=$?
  if [ $retVal -eq 0 ] ; then
    echo -n "Wait a bit"
    _timer=5
    while [ $_timer -gt 0 ] ; do
      sleep 1
      echo -n "."
      ((_timer--))
    done
    echo
    echo -n "Gather statistics..."
    $_HOME/startService.sh --show-dot show-data $peer $updates -f > /dev/null
  else
    echo
    echo "ERROR: startService returned with error code $retVal"
    echo
  fi
  echo "Cleanup"
  $_HOME/startService.sh stop

  # Calculate timinig
  end_time=$(date +%s)
  total_time=$(($end_time-$start_time))
  hours=$(($total_time / 3600))
  if [ $hours -lt 10 ] ; then
    hours="0$hours"
  fi
  minutes=$((($total_time % 3600) / 60))
  if [ $minutes -lt 10 ] ; then
    minutes="0$minutes"
  fi
  seconds=$(($total_time % 60))
  if [ $seconds -lt 10 ] ; then
    seconds="0$seconds"
  fi
  echo "Runtime for <$peer> <$relation> <$updates>: $hours:$minutes:$seconds - ($total_time sec.)"
  echo
  if [ ! $retVal -eq 0 ] ; then
    echo "Abort script!"
    exit $retVal
  fi
done
