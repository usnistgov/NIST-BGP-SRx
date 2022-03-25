#!/bin/bash
#
# This script allows to compile statistics from an experiment.
# Experiments are idenitified by the ASN and the number of updates.
#
# Version 0.1.0.0
#
_PEER=$1
_COUNT=$2

if [ "$_PEER" == "" ] || [ "$_COUNT" == "" ] || [ "$3" != "" ] ; then
  echo
  echo "Syntax: $(basename $0) <peer> <update-count>"
  echo
  exit
fi


_DATA_FILE_SUFFIX="data-result/result-$_PEER-$_COUNT"
_DATA_FILE_TYPES=( "provider" "customer" "sibling" "lateral" )
_DATA_FILE_PREFIX="txt"
_UPDATE_COUNT=0
_RESULT_LINE_TOTAL=( "relation,#valid,#invalid,#unknown,#unverifiable" )
_RESULT_LINE_PERCENTAGE=( "relation,#valid,#invalid,#unknown,#unverifiable" )
for _data_file_type in ${_DATA_FILE_TYPES[@]} ; do
  _DATA_FILE="$_DATA_FILE_SUFFIX-$_data_file_type.$_DATA_FILE_PREFIX"
  if [ -e $_DATA_FILE ] ; then
    _ALL=$(grep -e "^[viu?]" $_DATA_FILE | wc -l)
    _VALID=$(grep -e "^v" $_DATA_FILE | wc -l)
    _INVALID=$(grep -e "^i" $_DATA_FILE | wc -l)
    _UNKNOWN=$(grep -e "^u" $_DATA_FILE | wc -l)
    _UNVERIFIABLE=$(grep -e "^?" $_DATA_FILE | wc -l)
    if [ $_UPDATE_COUNT -eq 0 ] ; then
      _UPDATE_COUNT=$_ALL
    else
      if [ ! $_UPDATE_COUNT -eq $_ALL ] ; then
        echo "Update count conflict with file '$_DATA_FILE'"
        echo "Expected are '$_UPDATE_COUNT' UPDATES but received are '$_ALL' UPDATES"
        exit 1
      fi
    fi
    _RESULT_LINE_TOTAL+=( "$_data_file_type,#$_VALID,#$_INVALID,#$_UNKNOWN,#$_UNVERIFIABLE" )
    _VALID=$(echo "$_ALL $_VALID" | awk ' { value=$2/$1*100 } { printf "%.2f%", value } ')
    _INVALID=$(echo "$_ALL $_INVALID" | awk ' { value=$2/$1*100 } { printf "%.2f%", value } ')
    _UNKNOWN=$(echo "$_ALL $_UNKNOWN" | awk ' { value=$2/$1*100 } { printf "%.2f%", value } ')
    _UNVERIFIABLE=$(echo "$_ALL $_UNVERIFIABLE" | awk ' { value=$2/$1*100 } { printf "%.2f%", value } ')
    _RESULT_LINE_PERCENTAGE+=( "$_data_file_type,#$_VALID,#$_INVALID,#$_UNKNOWN,#$_UNVERIFIABLE" )
  fi
done
echo "Total Updates: $_UPDATE_COUNT"
echo
for result in ${_RESULT_LINE_TOTAL[@]} ; do
  echo $result | sed -e "s/#/ /g"
done
echo 
for result in ${_RESULT_LINE_PERCENTAGE[@]} ; do
  echo $result | sed -e "s/#/ /g"
done
