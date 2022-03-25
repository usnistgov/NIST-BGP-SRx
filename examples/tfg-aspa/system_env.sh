#!/bin/bash
#
# This file is used to configure the service scritp 'startService.sh'
#
# Version 0.1.0.0
#

# Configure this file and set the variable to 1
_LOCAL=""
_BIN=""
_SBIN=""
CONFIGURED=0

# This is a good spot to hard configure an IP
_SYSTEM_IP=""

# Check if all variables are configured
if [ "$_LOCAL" != "" ] && [ "$_BIN" != "" ] && [ "$_SBIN" != "" ] ; then
  CONFIGURED=1
fi

# If not, attempt auto configuration
if [ $CONFIGURED -eq  0 ] ; then
  echo "Attempt Auto configuration..."
  directories=( $(pwd) "$(pwd)/.." "$(pwd)/../.." "$(pwd)/../../.." )
  for dir in ${directories[@]} ; do
    if [ $CONFIGURED -eq 0 ] ; then
      find $dir | grep bin/bgpsecio$ > /dev/null 2>&1
      if [ $? -eq 0 ] ; then
        # Found:
        _LOCAL=$(find $dir | grep bin/bgpsecio$ | sed -e "s/bin\/bgpsecio$//g" )
        _BIN=$(echo $_LOCAL/bin | sed -e "s#//#/#g")
        _SBIN=$(echo $_LOCAL/sbin | sed -e "s#//#/#g")
        CONFIGURED=1
      fi
    fi
  done
fi

if [ $CONFIGURED -eq 0 ] ; then
  echo "First perform a system configuration. Configure system_env.sh!"
  echo "Most likely the directories array does not go far enough back (../../..)"
  echo "Abort!"
  exit 1
fi
