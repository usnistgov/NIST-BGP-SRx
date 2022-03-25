#!/bin/bash

#
# This file generaes an ASPA script file for the BGP-SRx RPKI Test Cache Harness
# using the CAIDA AS relationship file. The CAIDA file structure presents the
# data as:
#
#         "PROVIDER|CUSTOMER|-1" ot "PEER|PEER|0".
#
# This tool only used the -1 data and creates a RPKI Test Cache Harness file in
# the format of"
#
#         addASPA 0 CUSTOMER PROVIDER < PROVIDER>*
#
# Tier one ASPA entries are listed in the file T1.txt. These are not added here.
# These ASPA objects are added using the script ```generate-data.sh```
#
# Version 0.1.0.0
#
caida_file=""
out_file="CAIDA_Data_ASPA.txt"
use_python=1

# Check if the python3 interpretor is available:
python3 --version > /dev/null 2>&1
if [ ! $? -eq 0 ] ; then
  echo "Python3 not installed, switch to shell version"
  use_python=0
fi

while [ "$1" != "" ] ; do
  case "$1" in
    "-?" | "-h") echo "Syntax: $0 [-s] <caida-text-file>" 
                 echo "    -s   Use the shell implementaion rather than the python3."
                 echo "         Though the python version is multiple times faster "
                 echo "         and the preferred verison."
                 ;;
    "-s") use_python=0 ;;
    *) if [ "$caida_file" == "" ] ; then
         caida_file="$1"
       else
         echo "Only a single CAIDA data file can be specified!"
         exit 1
       fi
       ;;
  esac
  shift
done
 
if [ "$caida_file" == "" ] ; then
  echo "CAIDA file missing!"
  exit 1
fi

if [ ! -e "$caida_file" ] ; then
  echo "CAIDA file '$1' not found!"
  exit 1
fi

tmp_file=".$caida_file.tmp"

#
# This function does exacly the same as the python script, is
# just much slower. It should be used in case python3 is not available.
#
function useShell()
{
  echo "Stage1: Generate a single customer provider relation file..."
  echo -n "* Start: "; date
  # cat $1 | sed "/^[ ]*#.*/d" | awk -F "|" '{ print $1 " " $2; if ( $3 == 0) print $2 " " $1; }' | sort -k 1 -n > $tmp_file
  cat $caida_file | sed "/^[ ]*#.*/d" | awk -F "|" '{ if ( $3 == -1 ) print $2 " " $1 }' | sort -k 1 -n > $tmp_file
  echo -n "* Stop: "; date

  echo "Stage2: Generate a BIO ASPA input..."
  echo -n "* Start: "; date
  customer=0
  counter=0
  colCt=0
  echo -n > $out_file
  while IFS='' read -r line || [[ -n "${line}" ]] ; do
    if [ $(($counter % 1000)) -eq 0 ] ; then
      if [ $(($colCt % 40)) -eq 0 ] ; then
        if [ $colCt -gt 0 ] ; then
          echo; 
        fi
        echo -n "  ";
      fi
      echo -n "."
      ((colCt++))
    fi
    # Find each occurance int he ASPA raw data file 
    # where the given AS is a CUSTOMER registering a provider
    tokens=( $(echo $line) )
    if [ $customer -eq 0 ] ; then
      customer=${tokens[0]}
      echo -n "addASPA 0 ${tokens[0]}" > $out_file
    fi
    if [ "$customer" == "${tokens[0]}" ] ; then
      echo -n " ${tokens[1]}" >> $out_file
    else
      echo >> $out_file
      customer=${tokens[0]}
      echo -n "addASPA 0 ${tokens[0]} ${tokens[1]}" >> $out_file
    fi
    ((counter++))
  done < $tmp_file
  echo >> $out_file
  echo
  echo -n "* Stop: "; date
}

if [ $use_python -eq 1 ] ; then
  echo "Stage1: Use python script to generate CAIDA file..."
  echo -n "* Start: "; date
  python3 caida-to-cache.py -i $caida_file -o $tmp_file -p
  echo -n "* Stop: "; date
  echo
  echo "Stage2: Sort CAIDA file and remove duplicates..."
  echo -n "* Start: "; date
  cat $tmp_file | sed "/^[ \t]*$/d" | sort -k 3 -n -u > $out_file
  echo -n "* Stop: "; date
else
  useShell
fi

echo
echo "Stage3: Clean up temporary data..."
echo -n "* Start: "; date
rm $tmp_file
echo -n "* Stop: "; date