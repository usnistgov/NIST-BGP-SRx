#!/bin/bash

# This file retrieves the core web URL(s) for traffic data containing a specific
# AS as peer. 
#
# This tool is used by the get_path_data.sh in this folder
#
# Version 0.1.0.0
#
_status_file="peering-status.html"
_status_file_url="http://www.routeviews.org/peers/$_status_file"
_dl_status=0
_asn=""
_url=()

while [ "$1" != "" ] ; do
  case "$1" in
    "--refresh") _dl_status=1 ;;
    "-?") echo "Syntax $0 [--refresh] <ASN>"
          echo "   --refresh Download the latest peering-status.html"
          ;;
    *) if [ "$_asn" == "" ] ; then
        echo "$1" | grep -e "^[0-9][0-9\.]*$" > /dev/null
        if [ $? -eq 0 ] ; then
          _asn=$1
        else
          echo "Invalid AS parameter '$1'"
          exit 1;
        fi
      else
        echo "Lookup only a single AS!"
        exit 1;
      fi
  esac
  shift
done

if [ "$_asn" == "" ] ; then
   echo "Syntax $0 [--refresh] <ASN>"
   echo "   --refresh Download the latest peering-status.html"
fi

if [ ! -e $_status_file ] ; then
  wget $_status_file_url
else
  if [ $_dl_status -eq 1 ] ; then
    while [ -e $_status_file.$_backup ] ; do ((_backup++)); done
    mv $_status_file $_status_file.$_backup
    wget $_status_file_url
  fi
fi

_url=( $(cat $_status_file | sed "/^[ <R=].*/d" | sed "/^$/d" | sed -e "s/.routeviews.org//g" \
                           | awk -F "|" '{ print $1 }' | awk '{ print $1 " " $2 }' \
                           | grep -e " $_asn$" | awk '{ print $1 }' | sort -u) )

for _source in ${_url[@]} ; do
  if [ "$_source" == "route-views" ] ; then
    # route-views is ommitted
    _source=""
  fi
  if [ "$_source" != "route-views2" ] ; then
    # route-views2 does not exist
    echo "http://archive.routeviews.org/$_source" | sed -e "s/\/$//g"
  fi
done