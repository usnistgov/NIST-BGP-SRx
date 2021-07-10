#!/bin/bash
#
# This file provides tools for IP retrieval, assignment, and verification
#
#
IP_TOOLS_LIB_VER=0.5.1.12

if [ "$FUNCTION_LIB_VER" == "" ] ; then
  funclib=$( find -name functions.sh )
  if [ -e $funclib ] ; then
    . $funclib
  else
    echo "Please install the functions library first!"
    # Needed for println and print
  fi
fi

## Contains the result of the last run of findFreeIPv4()
_IPT_FIND_FREE_IPV4_VALUE=()
## Contains the error message if any from the last findFreeIPv4 run
_IPT_FIND_FREE_IPV4_ERRMSG=""
## Contains the interfaces that can be used
_IPT_FIND_IFACE=()
## Last used IFACE search parameter
_IPT_FIND_IFACE_PARAM="lv"
## Contains the error message if any from the last findFreeIPv4 run
_IPT_FIND_IFACE_ERRMSG=""
## Contains the selected item or is empty
_IPT_SELECTED_ITEM=""
## Contains the selected item number or is empty
_IPT_SELECTED_ITEM_NR=""
## Used to store the erorr message when installing IP addresses for
## an interface
_IPT_INSTALL_IPS_ERRMSG=""
##
## This array contains the list of all successfull installed Interface
## Aliasses
## 
_IPT_ADDIP_IFACE_AIAS=()

##
## This function verifies if the given address is a valid
## IPv4 network address.
##
## $1 The addres to check
##
## Return 0 if the value is a valid IPv4 address
##        1 If the given address is not a valid IPv4 address
##
function verifyIPv4()
{
  local retVal=1
  
  if [ "$1" != "" ] ; then
    sections=( $( echo $1 | sed -e "s#\.# #g") )
    if [ ${#sections[@]} -eq 4 ] ; then
      retVal=0
      for number in ${Sections[@]} ; do
        echo "Check number: '$number'"
        if [ $number -lt 0 ] || [ $number -gt 255 ] ; then
          retVal=1
          break
        fi
      done
    fi
  fi

  return $retVal
}

##
## This function checkes if hte given IP address is available or not.
## First this function looks for a DNS assingment and if none is found,
## it attempts to ping the address. If both were unsucessful, the address
## is considered available.
##
## $1 the IPv4 address
## 
## Return 0 - if the address is available
##        1 - IP address missing or invalid.
##        2 - used in DNS
##        3 - can be pinged!
##
function isIPv4Available()
{
  local retVal=1
  local ipAddr=""
  
  verifyIPv4 $1
  if [ $? -eq 0 ] ; then
    ipAddr="$1"
  fi

  if [ "$ipAddr" != "" ] ; then
    # First check DNS using nslookup
    nslookup "$ipAddr" > /dev/null 2>&1
    if [ $? -eq 1 ] ; then 
      # No DNS entry found, check if it can be pinged.
      ##echo "ping $ip123.$byte"
      ping "$ipAddr" -c 1 -W 1 > /dev/null 2>&1
      if [ ! $? -eq 0 ] ; then
        # Yeah, no nslookup, no ping => addr available
        retVal=0
      else
        retVal=3
      fi
    else
      retVal=2
    fi
  fi

  return $retVal
}


## This function attempts to find a free IP address within the 
## /24 address space of the given IP. The last byte+1 of the 
## provided IP address is used as start value. 
## e.g: 10.0.0.0  scans from 10.0.0.1  ... 10.0.0.254
##      10.0.0.20 scans from 10.0.0.21 ... 10.0.0.254
##  
##
## The found IP address will be stored in the array $_IPT_FIND_FREE_IP_VALUE
## Error messages are stored in the variable $_IPT_FIND_FREE_IP_ERRMSG.
##
## $1 the given IPv4 Address
## $2 the number of IP Addresses requested.
## $3 (optional) TAB for each line of printout
##
## return 0 - IP address found; 
##        1 - Invalid IP address; 
##        2 - No IP found in the /24 subnet; 
##        3 - Some but not all requested addresses found. 
function findFreeIPv4()
{
  local retVal=1
  local requested=1
  local minVal=1
  local maxVal=255
  local TAB="$3"
  local PFX=""

  _IPT_FIND_FREE_IPV4_ERRMSG=""

  if [ "$3" != "" ] ; then
    PFX="* "
  fi
  
  _IPT_FIND_FREE_IPV4_VALUE=()
  if [ "$2" != "" ] ; then
    # Convert to number
    requested=$(($2 + 0))
#    echo "Requested: $requested Addresses"
  fi
  if [ "$1" != "" ] ; then
    address=( $(echo $1 | sed -e "s/\./ /g") )
    if [ ${#address[@]} -eq 4 ] ; then
      retVal=0
      for ipByte in ${address[@]} ; do
        if [ $ipByte -lt 0 ] || [ $ipByte -gt 255 ] ; then
          retVal=1
          break
        fi
      done
      if [ $retVal -eq 0 ] ; then
        ip123="${address[0]}.${address[1]}.${address[2]}"
        byte=$(( ${address[3]} + 1 ))
        print "$TAB$PFX""Scanning $ip123.0/24 for $requested IPv4 Addresses starting with $ip123.$byte [" 
        # At this point we only value-check for staying below maxVal (254) for /24 prefix.
        while [ ${#_IPT_FIND_FREE_IPV4_VALUE[@]} -lt $requested ] && [ $byte -lt $maxVal ] ; do
          isIPv4Available "$ip123.$byte"
          local xyz=$?
          case "$xyz" in
            0)
              print "-"
              _IPT_FIND_FREE_IPV4_VALUE+=( "$ip123.$byte" )
              ;;
            2)
              # DNS entry found, address NOT available
              print "d"
              ;;
            3)
              # Host with this address repsonded to ping.
              print "p"
              ;;
            *)
              print "E($xyz)"
              _IPT_FIND_FREE_IPV4_ERRMSG="An Error occured with Address '$ip123.$byte'"
              ;;
          esac
          byte=$(($byte + 1))
        done
        println "]"
        if [ ${#_IPT_FIND_FREE_IPV4_VALUE[@]} -eq 0 ] ; then
          _IPT_FIND_FREE_IPV4_ERRMSG="No free IP address found in '$ip123.0/24'"
          retVal=2
        else 
          if [ ${#_IPT_FIND_FREE_IPV4_VALUE[@]} -lt $requested ] ; then
            _IPT_FIND_FREE_IPV4_ERRMSG="Only ${#_IPT_FIND_FREE_IPV4_VALUE[@]} of $requested available IP addresses found in '$ip123.0/24'"
            retVal=3
          fi
        fi
      fi
    else
      _IPT_FIND_FREE_IPV4_ERRMSG="Invalid IP Address '$1'"
    fi
  fi

  return $retVal
}

##
## Scan the system for interface names that can be used to add Aliases too.
## The result will be stored in the _IPT_FIND_IFACE array. Error messages 
## will be stored int he _IPT_FIND_IFACE_ERRMSG variable. This function does 
## NOT show alias interfaces.
##
## $1 allows to specify starting letters of interfaces to be left out.
##    (Default: lv for lo: and virtual: or vbridge: )
##
## return 0 - at least one interface was identified
##        1 - No Interface was identified.
function findIFace()
{
  local retVal=0
  local iFace="lv"
  _IPT_FIND_IFACE_ERRMSG=""

  if [ "$1" != "" ] ; then
    iFace="$1"
  fi

  _IPT_FIND_IFACE_PARAM="$iFace"

  ## Any interface except lo and virt or any other one starting with l or v
  ## or blank (later one to remove all lines not containint the interface name.)
  _IPT_FIND_IFACE=( $(ifconfig | grep "^[^$iFace ]" | sed -e "s#\([^:]\+\):.*#\1#g" | sort -u) )
  if [ ${#_IPT_FIND_IFACE[@]} -lt 1 ] ; then
    retVal=1
    _IPT_FIND_IFACE_ERRMSG="No suitble network interfaces found!"
  fi

  return $retVal
}

##
## This function allows to add a given IPv4 Address to the given interface.
## The IPv4 Address must not be pingable or otherwise used by DNS. The given interface
## MUST not be an Alias Interface. This function will add an Alias to the given interface.
##
## $1 IPv4 address
## $2 Interface Name.
##
## Return 0 - if the alias could be installed, otherwise 1
##
function addIPv4()
{
  local retVal=1
  local ipAddr=$1
  local iFace=$2
  local aliasNumArr=()
  local nextNum=0
  _IPT_ADD_IPV4_ERRMSG=""

  if [ "$ipAddr" != "" ] && [ "$iFace" != "" ] ; then
    # First identify the IP address is available
    isIPv4Available $ipAddr
    if [ $? -eq 0 ] ; then  
      # Second identify the interface, was it prevously found
      findIFace $_IPT_FIND_IFACE_PARAM
      for _iFace in ${_IPT_FIND_IFACE[@]} ; do
        if [ "$iFace" == "$_iFace" ] ; then  
          retVal=0
        fi
      done
      if [ $retVal -eq 0 ] ; then
        ## Now determine the next available interface alias number
        aliasNumArr+=( $(ifconfig | grep -e "^$iFace:[^: ]\+: .*" | awk '{ print $1 }' \
                                  | sed -e "s/.*:\([0-9]\+\):$/\1/g" | sort -u -g ) )
        for aliasNum in ${aliasNumArr[@]} ; do
          if [ $nextNum -eq $aliasNum ] ; then
            nextNum=$(( $aliasNum+ 1 ))
          else
            # The alias inteface numbers are orderd. In case the
            # current 'nextNum' is not equals to aliasNum that means
            # aliasNum must be > then 'nextNum' and 'nextNum' is the
            # next free number. So we can break here.
            break;
          fi
        done
        print "Add $ipAddr to $iFace:$nextNum..."
        sudo ifconfig $iFace:$nextNum $ipAddr > /dev/null 2>&1
        retVal=$?
        if [ $retVal -eq 0 ] ; then
          println "done!"
          _IPT_ADDIP_IFACE_AIAS+=( $iFace:$nextNum:$ipAddr )
        else
          println "failed!"
          _IPT_ADD_IPV4_ERRMSG="Error creating the Alias assignment!"      
        fi
      else
        _IPT_ADD_IPV4_ERRMSG="Interface '$iFace' not found or suitable to add alias too!"
      fi 
    else
      retVal=1
      _IPT_ADD_IPV4_ERRMSG="IP address is already assigned elsewhere!"
    fi
  else
    if [ "$ipAddr" == "" ] ; then
      _IPT_ADD_IPV4_ERRMSG="IP address ismissing!"
    else
      _IPT_ADD_IPV4_ERRMSG="IP interface name missing!"
    fi
  fi

  return $retVal
}

##
## This function will attempt to install a given number of IP addresses on the given
## interface. It will use the /24 of the first IPv4 address assigned to the interface
##
## In case the given interface has no pre-assigned IP address then the third
## parameter if provided will be used to identify the /24 prefix to scan for 
## suitable addresses.
##
## Error Messages are posted in $_IPT_INSTALL_IPS_ERRMSG
##
## $1 interface name (no alias)
## $2 number of IP addresses to be installed - Must be > 0
## $3 Optional IP prefix (only IP portion, no /length) - (optional)
## $4 Optional TAB (will be in $3 if $3 is not an IP address)
##
## Return the number of successfully installed interfaces or 0 in case of an error
##
function installIPs()
{
  local retVal=0
  local iFace=$1
  local doInstall=$2
  local optionalIP="$3"
  local TAB="$4"
  local netIP=""
  local fullRange=1
  _IPT_INSTALL_IPS_ERRMSG=""
  ## Used to abort if more than failMax IP installs fail on this interface
  local failed=0
  local failMax=3
  
  verifyIPv4 $optionalIP
  if [ $? -eq 1 ] ; then
    optionalIP=""
    if [ "$TAB" == "" ] ; then
      TAB="$3"
    else
      _IPT_INSTALL_IPS_ERRMSG="Invalid IP: '$3'"
      doInstall=0
    fi
  fi

  if [ "$doInstall" != "" ] ; then
    ## Retrieve the first IP address already assigned to the interface
    netIP=$(ifconfig $iFace | grep "inet " | awk '{ print $2 }')
    if [ "netIP" == "" ] ; then
      println "$TAB""Interface does not have an IP address configured."
      netIP=$3
      # only use the /24 range starting with $3 + 1
      fullRange=0
    fi

    if [ "$netIP" != "" ] ; then
      if [ $fullRange -eq 1 ] ; then
        # Rewrite netIP to use 0 as last byte
        netIP=$( echo $netIP | sed -e "s/\./ /g" | awk '{ print $1"."$2"."$3".0" }')
      fi

      findFreeIPv4 $netIP $doInstall "$TAB"
      case $? in
        0 | 3)
          println "$TAB- Found ${#_IPT_FIND_FREE_IPV4_VALUE[@]} available addresses"
          for ipAddr in ${_IPT_FIND_FREE_IPV4_VALUE[@]} ; do
            print "$TAB  * "
            ## Ramaining text is generated in addIPv4
            addIPv4 $ipAddr $iFace
            if [ $? -eq 0 ] ; then
              retVal=$(( $retVal + 1 ))
            else
              failed=$(( $failed + 1 ))
              if [ "$_APT_INSTALL_IPS_ERRMSG" == "" ] ; then
                _APT_INSTALL_IPS_ERRMSG="Error installing IP $ipAddr"
              else
                _APT_INSTALL_IPS_ERRMSG="$_APT_INSTALL_IPS_ERRMSG, $ipAddr"
              fi
              if [ ! $failed -lt $failMax ] ; then
                break
              fi
            fi
          done
          ;;
        *) 
          _IPT_INSTALL_IPS_ERRMSG="No suitable IP addresses found!"
          ;;
      esac
    else
      _IPT_INSTALL_IPS_ERRMSG="Cannot identify any suitable /24 prefix for $1!"
    fi
  else
    if [ "$1" == "" ] ; then
      _IPT_INSTALL_IPS_ERRMSG="Interface name and number of IP's to install missing!"
    else
      _IPT_INSTALL_IPS_ERRMSG="Interface name is missing!"
    fi
  fi

  return $retVal
}