#!/bin/bash
#
# This sctipt is used to get data from the QuaggaSRx usint its CLI.
# Simple script to run a router command.
#
# Version 0.1.0.0
#

_cmd=""
_sleep=""

#
# Print the syntax and exit the script
#
# $1 (optional) An optional parameter
#
function syntax()
{
  echo
  echo "Syntax: $(basename $0) [-?|-h] <router command> [<final sleep time>]"
  echo
  exit $1
}

if [ "$1" == "-?" ] || [ "$1" == "-h" ] ; then
  syntax
fi

_cmd=$1
_sleep=$2

if [ "$_sleep" == "" ] ; then
  _sleep=20
fi

{ sleep 1; echo "zebra"; \
    sleep 1; echo "terminal length 0"; \
    sleep 1; echo "enable"; \
    sleep 1; echo "$1"; \
    sleep $_sleep; } | telnet localhost 2605
