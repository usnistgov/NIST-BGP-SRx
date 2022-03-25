#!/bin/bash
#
# This script counts the number of link relations found within
# the ASPA script.
#


#
# Print the syntax and exit the script
#
# $1 (optional) exit code
#
function syntax()
{
  echo
  echo "$(basename $0) <aspa file>"
  echo
  exit $1
}

case "$1" in 
  "")
    echo "ASPA file missing!"
    syntax 1
    ;;
  "?" | "-?" | "-h")
    syntax
    ;;
  *) ;;
esac

ascount=( $(cat $1 \
            | sed -e "s/addASPA 0 //g" \
            | awk --field-separator=" " "{ print NF-1 }") )
_sum=0; 
for _num in ${ascount[@]} ; do 
  _sum=$(($_sum+$_num))
done
ascount=""
echo $_sum
