#!/bin/bash
#
# This script retrieves requested values for the configured peer. It is used by
# the script generate-data.sh to configure the BGPsec-IO and Quagga-SRx instances.
#
# Note: This sctipt is not intended to be used as stand alone scrtipt.
#
# Version 0.1.0.0
#
_peer=""
_ip=""
_relation=""
_PRINT_IP=0
_PRINT_REL=0

#
# This function prints the syntax and exits
#
# $1 (optional) exit code
#
function syntax()
{
  echo
  echo "Syntax: $(basename $0) [-?|h]  <peer> [<ip> [rel]|<rel> [ip]]"
  echo
  echo "  Option:"
  echo "    ip:    Print the IP address of the peer"
  echo "    rel:   Print the relation of the given peer"
  exit $1
}

while [ "$1" != "" ] ; do
  case "$1" in
    "-?" | "h") syntax ;;
    "ip" | "IP") _PRINT_IP=1 ;;
    "relation" | "rel") _PRINT_REL=1 ;;
    *) _peer="$1" ;;
  esac
  shift
done

if [ "$_peer" != "" ] ; then
  _ip=$(cat config/bgpd.conf | grep "[[:space:]]*remote-as[[:space:]]\+$_peer[[:space:]]*$" | awk ' { print $2 } ')
  if [ "_ip" != "" ] ; then
    _relation=$(cat config/bgpd.conf | grep "^[[:space:]]*neighbor[[:space:]]\+$_ip[[:space:]]\+aspa[[:space:]]\+" | awk ' { print $4} ')
  fi
else
  echo "No AS specified"
  syntax 1
fi
if [ $_PRINT_IP -eq 1 ] ; then
  echo -n "$_ip "
fi
if [ $_PRINT_REL -eq 1 ] ; then
  echo "$_relation"
fi
if [ $(($_PRINT_IP+$_PRINT_REL)) -eq 0 ] ; then
  echo "Nothing specified to print for AS $_peer"
  syntax 1
else
  echo
fi
