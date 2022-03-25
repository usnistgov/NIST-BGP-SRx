#!/bin/bash
#
# This script creates the data files for a given ASN. 
# As pre-requisite the following files are needed:
#
# data-peers: 
#    Use get_path_data.sh to generate the AS_Path data of a given
#    ASN. e.g. for 701 the file data-peers/701.txt is required
#
# data-aspa:
#    The ASPA data file generated from CAIDA data is required.
#    e.g.: data-aspa/CAIDA_Data_ASPA.txt
#
# Using this input data, this script will generate the BGP traffic and  ASPA
# data files needed to run an experimentation.
#
# Version 0.1.0.0
#
#

# Interger value of start prefix  1 => 0.0.1.0/24, 257 => 0.1.1.0/24
_IP_NUM=1
# Maximum number of AS paths 0 => all
_MAX=0
# The peer to generate the traffic for
_PEER=""

# Set the home folder
_HOME=$(pwd)
# Update traffic folder
_PEER_FLDR="$_HOME/data-peers"
# The name of the ASPA folder
_ASPA_FLDR="$_HOME/data-aspa"
# The folder in which the final output will be stored in.
_OUT_FLDR="$_HOME/data-experiment"
# The folder in which the final resutl data will be stored in.
# Here used only for preparation purpose.
_RESULT_FLDR="$_HOME/data-result"

# input file
_PEER_FILE=""
# The CAIDA file name containing all CAIDA data
_ASPA_FILE="$_ASPA_FLDR/CAIDA_Data_ASPA.txt"

# Filter the data traffic for IPv4 "\."
_IP_FILTER="\."

# The default filename for the update data
_UPDATE_FILE="$_OUT_FLDR/{PEER}-{NUM}-data-updates.bio"
# The ASN File
_ASN_FILE="$_OUT_FLDR/{PEER}-{NUM}-data-updates.asn"
# Cache file
_CACHE_FILE="$_OUT_FLDR/{PEER}-{NUM}-data-aspa.cache"

#
# This file scans through a BIO update file and extracts unique
# BGP AS_Paths and adds a simple counted prefix to it.
#
# For ASPA experiments, the prefix is irrelevant because the
# algorithm processes the PATH independent to the prefix.
#

#
# makes a /24 prefix and stores it in the variable _IP_PREFIX
#
# $1 the interger value of the prefixes IP base
#
function makePrefix()
{
  local num=$1
  local byte=( 0 )
  local shift=0
  while [ ${#byte[@]} -lt 4 ] ; do
    byte+=( $(($num % 256)) )
    num=$(($num/256))
  done
  _IP_PREFIX="${byte[3]}.${byte[2]}.${byte[1]}.${byte[0]}/24"
}

#
# Use the traffic data found in $_PEER_FILE to create
# a well defined traffic file.
#
function createTraffic()
{
  # Specify the traffic source file
  local as_path=""
  local print_dot=0
  local print_every=0
  local print_num=20
  local dot_count=0
  local asn_temp="$_ASN_FILE~"
  echo "Create traffic from '$_PEER_FILE'"

  if [ $_MAX -lt 1 ] ; then
    _MAX=$(cat $_PEER_FILE | wc -l)
  fi
  print_every=$(($_MAX/100))
  echo -n > $_UPDATE_FILE
  echo -n > $asn_temp
  echo -n "[$dot_count]"
  while IFS='' read -r as_path || [[ -n "${line}" ]] ; do
    ((print_dot++))
    makePrefix $_IP_NUM
    ((_IP_NUM++))
    ((_MAX--))
    echo "$_IP_PREFIX, B4 $as_path" >> $_UPDATE_FILE

    # Now add ASN's to ASN File
    echo $as_path | sed -e "s/ /\n/g" >> $asn_temp

    if [ $(($print_dot % $print_every)) -eq 0 ] ; then
      ((dot_count++))
      if [ $(($dot_count % $print_num)) -eq 0 ] ; then
        echo -n "[$dot_count]"
      else
        echo -n "."
      fi
    fi
    if [ $_MAX -eq 0 ] ; then
      break;
    fi
  done < $_PEER_FILE
  echo
  echo "Created file '$_UPDATE_FILE'!"
  echo "Create ASN file"
  # Sort and delete empty lines
  sort -u $asn_temp | sed -r "/^\s*$/d"> $_ASN_FILE 
  rm $asn_temp
  echo "Created file '$_ASN_FILE'"
}

#
# This function generates the ASPA cache
#
function createASPA()
{
  local aspa_lines
  if [ ! -e $_ASN_FILE ] ; then
    echo "ASN file '$_ASN_FILE' not found!"
    exit 1
  fi
  if [ ! -e $_ASPA_FILE ] ; then
    echo "ASPA data source '$_ASPA_FILE' not found!"
    exit 1
  fi
  echo -n > $_CACHE_FILE
  while IFS='' read -r line || [[ -n "${line}" ]] ; do
    # Find each occurance in the ASPA raw data file 
    # where the given AS is a CUSTOMER registering a provider
    aspa_lines=( $(grep -e "addASPA [0|1] $line .*" $_ASPA_FILE | sed -e "s/ /-/g") )
    for token in ${aspa_lines[@]} ; do
      echo $token | sed -e "s/-/ /g" >> $_CACHE_FILE
    done
  done < $_ASN_FILE
  echo "Created file '$_CACHE_FILE'"
}

#
# Print the script syntax, does exit
#
# $1 exit code if provided
#
function syntax()
{
  echo
  echo "Syntax: $(basename $0) [-p <peer-as> [-i <..>] [-m <..>]]"
  echo
  echo "  Parameters:"
  echo "  -----------"
  echo "    -p <peer-as>      The BIO UPDATE formated traffic file"
  echo "    -i <start ip int> The start prefix IP in integer 1=0.0.1.0/24, 257=0.1.1.0/24, ..."
  echo "    -m <max updates>  The maximum number of updates in the traffic file, 0 = all"
  echo
  exit $1
}

while [ "$1" != "" ] ; do
  case "$1" in
    "-?" | "-h") syntax ;; 
    "-p") shift
          _PEER="$1"
          _PEER_FILE="$_PEER_FLDR/$1.txt"
          if [ ! -e "$_PEER_FILE" ] ; then
            echo "File '$_PEER_FILE' dot found!"
            exit 1
          fi
          ;;
    "-i") shift
          if [ "$1" != "" ] ; then
            if [ $1 -gt 0 ] ; then
              _IP_NUM=$1
            else
              echo "Invalid parameter '$1', must be a number > 0!"
              exit 1
            fi
          else 
            echo "Parameter missing -i <start ip or int>"
            exit 1
          fi
          ;;
    "-m") shift
          if [ "$1" != "" ] ; then
            if [ $1 -gt 0 ] ; then
              _MAX=$1
            fi
          else 
            echo "Parameter missing -m <max updates>"
            exit 1
          fi
          ;;
    *) echo "Invalid parameter '$1'"
       syntax 1
       ;;
  esac
  shift
done

_UPDATE_FILE=$(echo $_UPDATE_FILE | sed -e "s/{NUM}/$_MAX/g" | sed -e "s/{PEER}/$_PEER/g")
_ASN_FILE=$(echo $_ASN_FILE | sed -e "s/{NUM}/$_MAX/g" | sed -e "s/{PEER}/$_PEER/g")
_CACHE_FILE=$(echo $_CACHE_FILE | sed -e "s/{NUM}/$_MAX/g" | sed -e "s/{PEER}/$_PEER/g")

if [ ! -e $_OUT_FLDR ] ; then
  echo "Create data-experiment folder..."
  mkdir -p $_OUT_FLDR
  if [ ! $? -eq 0 ] ; then
    echo "data-experiment folder does not exist and counld not be created!"
    exit 1
  fi
fi

if [ ! -e $_RESULT_FLDR ] ; then
  echo "Create data-result folder..."
  mkdir -p $_RESULT_FLDR
  if [ ! $? -eq 0 ] ; then
    echo "data-result folder does not exist and counld not be created!"
    exit 1
  fi
fi


if [ "$_PEER_FILE" != "" ] ; then
  if [ -e $_PEER_FILE ] ; then
    if [ -d $_PEER_FILE ] ; then
      echo "'$_PEER_FILE' is a directory and not a file!"
      exit 1
    fi
    #  check file format using the first 10 lines
    head -n 10 $_PEER_FILE | grep -e "^[0-9][ 0-9\n\r]\+$" > /dev/null 2>&1
    if [ $? -eq 1 ] ; then
      echo "'$_PEER_FILE' does not match required format!"
      exit 1
    fi
    createTraffic
    createASPA
    # Clean up tmp files
    # rm $_TMP_FILE $_TMP_FILE_ASN
  else
    echo "File '$_PEER_FILE' not found!"
    exit 1
  fi
else
  syntax 1
fi