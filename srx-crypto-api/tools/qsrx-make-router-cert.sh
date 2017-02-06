#!/bin/sh

# Show the tools syntax and exit 
function syntax()
{
  echo "$0 [-v] -key <keyfile> -asn <asn> [-days <days valid>] [-c <openssl-config>] [-start <date>]"
  echo
  echo "  date: Allows all formates accepted using local 'date -s <format>'"
  echo "        This setting requires root permission (or sudoers) and will modify the current date "
  echo "        for the period of the function call. The original date will be set back!" 
  echo
  echo "This script is part of the BGP-SRx Software Suite"
  echo "2017 Oliver Borchert (oliver.borchert@nist.gov)"

  exit 0
}

# Call syntax if the given parameter is ""
function checkParam()
{
  if [ "$1" == "" ] ; then
    syntax;
  fi 
}

# This function normalizes the provided ASN into an integer value. 
# Acceptable input formats are INTEGER(32) or WORD(16).WORD(16) and 
# the return value is INTEGER(32) and can be retrieved using the
# the following syntax: ASN=$(normalizeASN 1234)
# return value 0 on success, otherwise 1
function normalizeASN()
{
  if [ "$1" != "" ] ; then
    NUMBER=$1
    RETVAL=0
  else
    NUMBER=0
    RETVAL=1
  fi

  echo $NUMBER | grep -e "\." >> /dev/null

  if [ $? -eq 0 ] ; then
    L_NUM=$(echo $NUMBER | sed -e "s/\([0-9]\+\)\.\([0-9]\+\)/\1/g")
    R_NUM=$(echo $NUMBER | sed -e "s/\([0-9]\+\)\.\([0-9]\+\)/\2/g")
  else
    L_NUM=$(($NUMBER >> 16)) 
    R_NUM=$(($NUMBER & 65535))
  fi

  ASN_H=$(($L_NUM << 16))

  ASN=$(($ASN_H + $R_NUM))
  echo $ASN

  return $RETVAL
}

# Set the system date and store a backup date
function setDate()
{
  ORIGINAL_DATE=$(date)
  if [ "$(whoami)" == "root" ] ; then
    date -s "$1"
    RETVAL=$?
  else
    sudo date -s "$1"
    RETVAL=$?
  fi
}

# reset the system date to the last call of setDate
function resetDate()
{
  if [ "$ORIGINAL_DATE" != "" ] ; then
    setDate "$ORIGINAL_DATE"
    ORIGINAL_DATE=""
  fi
}

# This function does check the given parameters and sets the appropriate
# values.
# The parameter should be $@
function parseParams()
{
  while [ "$1" != "" ] 
  do
    case "$1" in
     "-asn")
        shift
        checkParam $1
        ASN=$(normalizeASN $1)
        REQUIRED_PARAMS=$(($REQUIRED_PARAMS - 1))
        ;;
     
     "-key")
        shift
        checkParam $1
        KEYFILE=$1
        REQUIRED_PARAMS=$(($REQUIRED_PARAMS - 1))
        ;;

     "-days")
        shift
        checkParam $1
        CERT_VALIDITY=$1
        ;;

     "-c")
        shift
        checkParam $1
        CFGFILE=$1
        ;;

     "-date")
        shift
        checkParam $1
        setDate $1
        ;;

     "-v")
        VERBOSE=1
        ;;
 
     "-?")
        syntax
        ;;

     *) 
        echo "Invalid Parameter '$1'"
        syntax
        ;;
    esac
    shift
  done
}

# By default use one year
CERT_VALIDITY=365
# By default use the current time
START_TIME=$(date +%Y%m%d%H%M%S%Z)
# use template file
CFGFILE=qsrx-router-key.cnf.tpl

# The number of required parameters
REQUIRED_PARAMS=2
# Parse all given parameters
parseParams $@

if [ $REQUIRED_PARAMS -gt 0 ] ; then
  echo "Invalid number of parameters"
  syntax
fi

exit 1

if [ "$VERBOSE" != "" ] ; then
  echo "Settings:"
  echo "========="
  echo " - key............: $KEYFILE"
  echo " - asn............: $ASN"
  echo " - validity.......: $CERT_VALIDITY days"
  echo " - configuration..: $CFGFILE"
  echo " - start date.....: $(date)"
  echo
fi

#exit 1

CSRFILE=ROUTER-.csr
CERTFILE=0.$KEYFILE.cert

ASN_HEX=$(printf %08X $ASN)

CSRFILE=ROUTER-$ASN_HEX.csr
CERTFILE=ROUTER-$ASN_HEX.cert

CN="ROUTER-$ASN_HEX"

# Generate an 8 byte random hex number 
SERIAL_HEX=$(cat /dev/urandom | tr -dc 'a-fA-F0-9' | tr [a-z] [A-z] | fold -w 8 | head -n 1)
SERIAL_DEC=$(echo "ibase=16; $SERIAL_HEX" | bc)

echo "Common Name....: $CN"
echo "Serial Number..: $SERIAL_HEX ($SERIAL_DEC)"

TMP_CFGFILE=$CFGFILE.$ASN.$SERIAL_HEX.tmp
cat $CFGFILE | sed -e "s/{QSRX_ASN}/$ASN/g" > $TMP_CFGFILE

# Generate the certificate request
openssl req -new -batch -config $TMP_CFGFILE -subj /CN=ROUTER-$ASN_HEX -key $KEYFILE -out $CSRFILE
# Generate the certificate itself
openssl x509 -sha256 -extfile $TMP_CFGFILE -req -signkey $KEYFILE -days $CERT_VALIDITY -extensions bgpsec_router_ext -set_serial $SERIAL_DEC -in $CSRFILE -outform DER -out $CERTFILE
rm $TMP_CFGFILE

QSRX_VIEW_CMD="openssl x509 -inform DER -in $CERTFILE -text"

SKI=$($QSRX_VIEW_CMD | grep -n "Subject Key Identifier:" | sed -e "s/\([0-9][0-9]*\):.*/echo \"$\(\(\1+1\\))\"/g" | sh | sed -e "s/\(.*\)/$QSRX_VIEW_CMD | head -n \1 | tail -n 1/g" | sh | sed -e "s/ //g" | sed -e "s/://g")

echo "ASN: $ASN [$ASN_HEX]"
echo "SKI: $SKI"

$QSRX_VIEW_CMD
echo
# in case the date function was used.
resetDate
