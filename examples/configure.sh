#!/bin/bash
_IP_FILE=IP-Address.cfg
# Extension for configuration files generated from templates.
_CONF_EXT="conf"
# Add each line exept if it is empty or contains a # "hash"
_IP_CONFIG=()
_TOOLS=( sed screen )
_FAILED=0
_FOLDERS=( $(ls -d */) )
_MY_ROOT=$(pwd)
# Parameter settings
_P_ROLLBACK=0
_P_ROLLBACK_ALIAS=0
_P_CHECK_ONLY=0
_VERBOSE=1
_IP_PRE_SELECTION=()
_P_INSTALL_ALIAS=0
# If install alias is selected, successful installed aliases are stored
# in the array _IPT_ADDIP_IFACE_ALIAS provided by ip_tools.sh
_P_REINSTALL_ALIAS=0
_P_NO_LOOPBACK=1
# Will be overwritten
_CUSTOM_PFX_24="192.168.255.0"

##############################################################################
##  LOAD THE LIBRARY
##
if [ ! -e lib/functions.sh ] ; then
  echo "WARNING: Could not find library script [lib/functions.sh]!"
  echo "         Install framework properly prior usage."
else
  . lib/functions.sh
fi
if [ "$FUNCTION_LIB_VER" == "" ] ; then
  echo "ERROR loading the functions library - Abort operation!"
  exit 1
fi

if [ ! -e lib/ip_tools.sh ] ; then
  echo "WARNING: Could not find library script [lib/ip_tools.sh]!"
  echo "         Install framework properly prior usage."
else
  . lib/ip_tools.sh
fi
if [ "$IP_TOOLS_LIB_VER" == "" ] ; then
  echo "ERROR loading the ip_tools library - Abort operation!"
  exit 1
fi
##############################################################################


#
# Print the given text without CR. In case _VERBOSE=0 nothing will be printed.
#
# $1..$n All parameters to be printed. "separated by 1 blank"
#
function print()
{
  if [ $_VERBOSE -eq 1 ] ; then
    echo -n "$@"
  fi
}

#
# Print the given text with CR. In case _VERBOSE=0 nothing will be printed.
#
# $1..$n All parameters to be printed. "separated by 1 blank"
#
function println()
{
  if [ $_VERBOSE -eq 1 ] ; then
    echo "$@"
  fi
}

#
# Load the IP configuration from the _IP_FILE. This function 
# might be called multiple times depending if the _IP_FILE is
# properly configured or not. 
#
loadIPConfig()
{
  _IP_CONFIG=( $(cat $_MY_ROOT/$_IP_FILE | grep -e "^[ ]*[^\[#]" | sed -e "/^[ ]*$/d" | sed -e "s/\([^#]*\)#.*/\1/g") )
}

#
# Exit the program and returns to the initial disectory
#
# $1 the error code to be used, 0 if none is given
#
exitPrg()
{
  local exitVal=0

  if [ "$1" != "" ] ; then
    exitVal=$1
  fi
  println
  cd $_MY_ROOT > /dev/null
  exit $exitVal
}

#
# determines if the examples section is properly configured. 
#
# return 0 if configured, 1 if no configured
#
isConfigured()
{
  local retVal=0

  cat $_IP_FILE | grep -e "^[ ]*[^\[#]" | sed -e "/^[ ]*$/d" | sed -e "s/\([^#]*\)#.*/\1/g" | grep -e "<ip-address-" > /dev/null
  if [ $? -eq 0 ] ; then
    retVal=1
  fi

  return $retVal
}

###########################################################################
## CHECK Parameters
###########################################################################
while [ "$1" != "" ] ; do
  case $1 in
    "-h" | "-H" | "-?" | "?")
       echo "Configure the experiment project or inquire about the configuration"
       echo "  state using '-c'"
       echo
       echo "Syntax: $0 [-c|-i|-?|-h] | [-R|-RA|-A|-AP][-I] [--no-interactive <Y|N>] [--no-verbose]"
       echo
       echo "  Parameters:"
       echo "        -c  Only perform a check if the project is configured!"
       echo "            Errorlevel 0: Is configured"
       echo "            Errorlevel 1: Is not configured"
       echo "        -i  Display the IP addresses available for the configurator"
       echo "        -?  Help screen."
       echo "        -h  Help screen."
       echo ""
       echo "        -R  Rollback configuration using the last backup file"
       echo "            back into the configuration file. This includes -RA"
       echo "        -RA Roll back alias install!"
       echo ""
       echo "        -I  Install IP address alias if more IP addresses are needed!"
       echo "        -A  Reinstall the IP address alias - Needed after system reboot"
       echo "            when the temporary alias installs are not active anymore."
       echo "        -AP Allows to modify the second byte to be modified."
       echo "            Loopback Prefix - By default 128 for 127.128.0.0/24"
       echo ""
       echo "        --no-interactive <Y|N> [ip-selection]"
       echo "            This option removed any interactivity and answers"
       echo "            any question with the provided value 'Y' or 'N'"
       echo "            Y: Apply [Y]es to all Y/N questions "
       echo "            N: Apply [N]o to all Y/N questions "
       echo "            ip-selection: AUTO|<num>*"
       echo "              AUTO:  Always use the next available one"
       echo "              <num>: Represents the list number of the particular IP address"
       echo "            Note: Try -i to see the list of IP addresses"
       echo ""
       echo "        --no-verbose"
       echo "            Disable any output"
       exitPrg 0
       ;;
    "-c")
       _P_CHECK_ONLY=1
       ;;
    "-i")
       echo
       fill_SYS_IP 1 "" 1 1 > /dev/null
       echo "The following System IP addresses are available for usage:"
       echo
       _idx=0
       _ct=1
       while [ $_idx -lt ${#SYS_IP[@]} ] ; do
         echo "  - [$_ct]: ${SYS_IP[$_idx]}"
         ((_idx++))
         ((_ct++))
       done
       exitPrg 0
       ;;
    "-R")
       _P_ROLLBACK=1
       _P_ROLLBACK_ALIAS=1
       ;;
    "-RA")
       _P_ROLLBACK_ALIAS=1
       ;;
    "-I")
       _P_INSTALL_ALIAS=1
       ;;
    "-A")
       _P_REINSTALL_ALIAS=1
       ;;
    "-AP")
       shift
       ERR_MSG=""
       if [ "$1" == "" ] ; then
         ERR_MSG="-AP requires a parameter. Try --? for more info"
       else
         _ipNum=$(($1+0))
         if [ "$_ipNum" != "$1" ] ; then
           ERR_MSG="-AP $1 - Value '$1' is not a valid number!"
         else
           if [ $_ipNum -lt 0 ] || [ $_ipNum -gt 255 ] ; then
             ERR_MSG="Value '$1' must be bewteen 0..255"
           fi
         fi
       fi
       if [ "$ERR_MSG" != "" ] ; then
         println "$ERR_MSG"
         exitPrg 1
       fi
       _CUSTOM_PFX_24="$1"
       verifyIPv4 $_CUSTOM_PFX_24
       if [ $? -eq 0 ] ; then
         println "Parameter -AP is invalid IP prefix $_CUSTOM_PFX_24/24!"
         exitPrg 1
       fi
       ;;
    "--no-interactive")
      shift
      parseYN "-$1"
      if [ ! $? -eq 0 ] ; then
        println "Invalid --no-interactive value '$1'"
        exitPrg 1
      fi
      # Now check for IP pre-selections      
      _IP_PRE_SELECTION=();
      if [ "$2" == "AUTO" ] ; then
        _IP_CT=$($0 -i | sed -e "s/^[ ]*Select.*//g" | sed -e "/^[ ]*$/d" | wc -l)
        _IP_SEL=0
        while [ $_IP_SEL -lt $_IP_CT ] ; do
          _IP_SEL=$(($_IP_SEL+1))
          _IP_PRE_SELECTION+=($_IP_SEL)
        done
        println "_IP_PRE_SELECTION=${_IP_PRE_SELECTION[@]}"
        shift
        _paramTest=0
      fi
      _paramTest=$((${#_IP_PRE_SELECTION[@]}+1));
      while [ $_paramTest -eq 1 ] && [ "$2" != "" ] ; do
        _testResult=$(($2+0))
        if [ "$_testResult" == "$2" ] ; then
          _IP_PRE_SELECTION+=($2)
          shift
        else
          _paramTest=0
        fi
      done
      if [ ${#_IP_PRE_SELECTION[@]} -gt 0 ] ; then
        print "Configure IP selection using pre-selection: "
        println $(echo ${_IP_PRE_SELECTION[@]} | sed -e "s/ /, /g")
      fi
      ;;
    "--no-verbose")
      _VERBOSE=0
      ;;
    *) 
       println "Unknown parameter '$1'"
       exitPrg 1
       ;;
  esac
  shift
done


println "NIST BGP-SRx EXAMPLE configurator."

_retVal=0
###########################################################################
## CHECK IF ALIAS Reinstall is selected.
###########################################################################
if [ $_P_REINSTALL_ALIAS -eq 1 ] ; then

  _aliasCFG=( $( grep -e "^#>:.*" $_IP_FILE | sed -e "s/#>: //g" )  )

  if [ ${#_aliasCFG[@]} -eq 0 ] ; then
    println "No alias configuration available. To rebuild the examples"
    println "Roll back the configuration with ./configure.sh -R and then"
    println "create a new configuration using ./confiure.sh"
    _retVal=1
  else
    println "Start installing alias interfaces and IP addresses..."
    for ifaceCfg in ${_aliasCFG[@]} ; do
      _alias=( $( echo $ifaceCfg | sed -e "s/:/ /g" | awk '{ print $1":"$2" "$3 }' ) )
      isIPv4Available ${_alias[1]}
      pingVal=$?
      if [ $pingVal -eq 0 ] ; then
        # Verify that the interface is not already used elsewhere. If so don't proceed
        # Retrieve the first IP address already assigned to the interface
        nicIP=$(ifconfig ${_alias[0]} | grep "inet " | awk '{ print $2 }')
        verifyIPv4 $nicIP
        if [ $? -eq 0 ] ; then
          println "* Interface alias ${_alias[0]} is already configured with IP address '$nicIP'."
          if [ "$nicIP" != "${_alias[1]}" ] ; then
            println "  - Assigned IP differs from the requested IP '${_alias[1]}' address!"
            println "  - Skip this interface!"
            _retVal=1
            continue
          fi
        fi
        print "* Install alias interface ${_alias[0]} with IP ${_alias[1]}..."
        sudo ifconfig ${_alias[0]} ${_alias[1]} > /dev/null 2>&1
        if [ $? -eq 0 ] ; then
          println "done."
          isIPv4Available ${_alias[1]}
          pingVal=$?
        else
          println "failure!"
          _retVal=1
        fi
      fi
      if [ $pingVal -eq 3 ] ; then
        println "  - Host ${_alias[1]} responds to ping!"
      fi
    done

    if [ $_retVal -eq 1 ] ; then
      println "Not all interface aliasses could be installed properly."
      println "Verify manually which IP addresses still need to be."
      println "If problems persist, reconfigure the examples folder!"
    fi
  fi
  exitPrg $_retVal
fi

###########################################################################
## CHECK IF Remove Alias is selected.
###########################################################################
if [ $_P_ROLLBACK_ALIAS -eq 1 ] ; then

  _aliasCFG=( $( grep -e "^#>:.*" $_IP_FILE | sed -e "s/#>: //g" )  )

#echo "_IP_FILE: $_IP_FILE"
#echo "_aliasCFG: ${_aliasCFG[@]}"

  if [ ${#_aliasCFG[@]} -eq 0 ] ; then
    println "No alias configuration available."
  else
    println "Start rolling back alias interfaces..."
    for ifaceCfg in ${_aliasCFG[@]} ; do
      _alias=( $( echo $ifaceCfg | sed -e "s/:/ /g" | awk '{ print $1":"$2" "$3 }' ) )
      # Verify that the interface is not already used elsewhere. If so don't proceed
      # Retrieve the first IP address already assigned to the interface
      nicIP=$(ifconfig ${_alias[0]} | grep "inet " | awk '{ print $2 }')
      verifyIPv4 $nicIP
      if [ $? -eq 1 ] ; then
        print "* Interface alias ${_alias[0]} is not configured with a"
        if [ "$nicIP" == "" ] ; then
          println "n IPv4 Address."
        else
          println "valid IPv4 Address '$nicIP'."
        fi
        println "  - Skip ${_alias[0]}"
        continue
      fi

      if [ "$nicIP" != ${_alias[1]} ] ; then
        println "* Interface alias ${_alias[0]} is configured with IP address '$nicIP'."
        if [ "$nicIP" != "${_alias[1]}" ] ; then
          println "  - Assigned IP differs from the IP '${_alias[1]}' stored in the configuration!"
          println "  - Skip removal of this alias interface!"
          _retVal=1
          continue
        fi
      fi

      print "- Removing alias interface ${_alias[0]} with IP ${_alias[1]}..."
      sudo ifconfig ${_alias[0]} down > /dev/null 2>&1
      ifconfig | grep ${_alias[0]} > /dev/null 2>&1
      if [ $? -eq 1 ] ; then
        println "done."
      else
        println "failure!"
        _retVal=1
      fi
    done
  fi

  if [ $_P_ROLLBACK -eq 0 ] ; then
    exitPrg $_retVal
  fi
fi

###########################################################################
## CHECK IF Rollback is selected.
###########################################################################
if [ $_P_ROLLBACK -eq 1 ] ; then
  _ROLLBACK_FILE_CT=0
  _currNumber=0
  _BAK_FILE=$_IP_FILE.bak
  ls $_BAK_FILE* > /dev/null 2>&1
  if [ $? -eq 0 ] ; then
    println "Rollback '$_IP_FILE'"
    _ROLLBACK_FILE_CT=$(($_ROLLBACK_FILE_CT+1))
    _bak_files=( $(ls $_BAK_FILE* | sort -u ) )
    _lastFileNr=$((${#_bak_files[@]}-1))
    readYN "Rolling back $_IP_FILE using ${_bak_files[$_lastFileNr]}"
    if [ $? == 1 ] ; then
      mv ${_bak_files[$_lastFileNr]} $_IP_FILE
    else
      println "Skipp rolling back $_IP_FILE!"
    fi
  fi

  for _folder in "${_FOLDERS[@]}" ; do
    ls $_folder/*.tpl > /dev/null 2>&1
    if [ $? -eq 0 ] ; then
      println "Process '$_folder'..." 
      _tpl_files=( $(ls $_folder/*.tpl | sed -e "s/\(.*\)\.tpl$/\1.$_CONF_EXT/g" | sed -e "s#//#/#g") )
      for _tpl_file in ${_tpl_files[@]} ; do
        if [ -e $_tpl_file ] ; then
          readYN "  - Removing '$_tpl_file'"
          if [ $? == 1 ] ; then
            rm $_tpl_file
            _ROLLBACK_FILE_CT=$(($_ROLLBACK_FILE_CT+1))
          else
            println "    skipped!"
          fi
        fi
      done
    fi
  done

  if [ $_ROLLBACK_FILE_CT -eq 0 ] ; then
    println "Nothing found to be rolled back!"
  else
    println "$_ROLLBACK_FILE_CT file(s) rolled back!"
  fi
  exitPrg $_retVal
fi

###########################################################################
## CHECK IF IP-Address is configured.
###########################################################################
println "1) Verify the configuration status of the experiments..."
isConfigured
_retVal=$?
if [ $_P_CHECK_ONLY -eq 1 ] ; then
  print "   Project is "
  if [ $_retVal -eq 0 ] ; then
    print "properly "
  else
    print "not "
  fi
  println "configured!"
  exitPrg $_retVal
fi

if [ $_retVal -eq 0 ] ; then
  println "   Project is properly configured!"
else
  # Store all configuration IDs alphabetically sorted in a list.
  _IP_IDS=( $(cat $_IP_FILE | grep -e "<ip-address-" | sed -e "s/.*<ip-address-\([0-9]\+\)>.*/\1/g" | sort -u -g) )
  # check that the list starts with 1 and is non interupted.
  _ID_CT=0
  _OK=1
  for ip_id in ${_IP_IDS[@]} ; do
    _ID_CT=$(($_ID_CT+1))
    if [ ! $_ID_CT -eq $ip_id ] ; then
      _OK=0
    fi
  done
  println
  if [ $_OK -eq 0 ] ; then
    println "   Project's IP-Address.cfg needs to be manually configured first!"
  else
    print "   Start auto configuration of $_ID_CT IP address"
    if [ $_ID_CT -gt 1 ] ; then
      print "es"
    fi
    println "!"
    println "   * Configuration to be modified:"
    cat $_IP_FILE | sed -e "s/^[ ]*## /** /g" | grep -e "^[ ]*[^\[#]" | sed -e "/^[ ]*$/d" \
                  | sed -e "s/\([^#]*\)#.*/\1/g" | sed -e "s/\*\* /\n* /g" \
                  | sed -e "s/\(^[^ ]\+\)/    -> \1/g" | sed -e "s/-> \*[ ]*//g"
    println
    # get IP addresses
    _SELECTION_OK=0
    SYS_IP_TAB="  "
    _ignore_apply_global_yn=""
    if [ "$GLOBAL_YN" != "" ] ; then
      if [ "$GLOBAL_YN" == "N" ] ; then
        # here automation must be disables if no is default,
        # other whise the IP selection never will succeed.
        # For that interactivity MUST be enabled.
        _ignore_apply_global_yn=1
      fi
    fi

    # Reset _retVal again - current value has no meaning anymore.
    _retVal=0
    while [ $_SELECTION_OK -eq 0 ] ; do
      reset_SYS_IP
      fill_SYS_IP $_ID_CT "ip-address-" 2 ${_IP_PRE_SELECTION[@]}
      _retVal=$?

      if [ ! $_retVal -eq 0 ]; then
        # Not enough IP addresses available to configure.
        if [ $_P_INSTALL_ALIAS -eq 1 ] ; then
          println "   * Identify feasable network interface cards..."
          # Ignore interface starting with 'l' (lo),'v' (vibr) (virt) (v...), and (tun..)
          findIFace "lvt"
          _retVal=$?

          if [ $_retVal -eq 0 ] ; then
            println "   * found: ${_IPT_FIND_IFACE[@]}"
            # Now just select the first interface found:
            iFaceNum=0
            while [ $iFaceNum -lt ${#_IPT_FIND_IFACE[@]} ] && [ $SYS_MISSING_IPS -gt 0 ] ; do
              iFace=${_IPT_FIND_IFACE[$iFaceNum]}
              println "   * Select interface [$iFace]!"
              installIPs $iFace $SYS_MISSING_IPS $_CUSTOM_PFX_24 "     "
              instIPs=$?
              if [ $instIPs -gt 0 ] ; then
                SYS_MISSING_IPS=$(( $SYS_MISSING_IPS - $instIPs ))
              fi
              iFaceNum=$(($iFaceNum+1))
            done       
            
            if [ $SYS_MISSING_IPS -gt 0 ] ; then
              println
              println "Could not install all necessary IP's,"
              println "please continue with manual install!"
              ## Check if inside docker container
              dockerID="cat /proc/1/cgroup | grep 'docker/' | tail -1 | sed 's/^.*\///' | cut -c 1-12"
              if [ "$dockerID" != "" ] ; then
                println
                println "This script cannot install additional IP "
                println "addresses into a running Docker container."
                println "Please reconfigure the Container to use $SYS_MISSING_IPS"
                println "additional IP's to allow proper configuration!"
                println
              fi
              _retVal=1
              break
            else
              _retVal=0
              continue
            fi
          else
            println "   ERROR[$_retVal]: $_IPT_FIND_IFACE_ERRMSG Abort configuration!"
            _retVal=1
            break
          fi
        else          
          println
          println "More IP addresses are needed. Please consult the README file"
          println "or restart this script with '-I' to identify and install the $SYS_MISSING_IPS"
          println "needed IP-Addresses!"
          _retVal=1
          break
        fi
      fi
      println "    * Selection:"
      for ip_idx in ${!SYS_IP[@]} ; do
        println "      - $SYS_IP_LBL_PFX${SYS_IP_LABEL[$ip_idx]}$SYS_IP_LBL_SFX := ${SYS_IP[$ip_idx]}"
      done
      println
      readYN "      Apply selection?" $_ignore_apply_global_yn
      _SELECTION_OK=$?
      if [ $_SELECTION_OK -eq 0 ] ; then
        echo
        if [ ${#_IPT_ADDIP_IFACE_ALIAS[@]} -gt 0 ] ; then
          println "    * Remove ${#_IPT_ADDIP_IFACE_ALIAS[@]} installed Alias Interfaces:"
        fi
        for iFaceInfo in ${_IPT_ADDIP_IFACE_ALIAS[@]} ; do
          iFaceData=( $( echo $iFaceInfo | sed -e "s/:/ /g") )
          print "      - Remove ${iFaceData[2]} from ${iFaceData[0]}:${iFaceData[1]}..."
          sudo ifconfig ${iFaceData[0]}:${iFaceData[1]} down
          if [ $? -eq 0 ] ; then
            println "done!"
          else
            println "failed!"
          fi
        done
        println
        println "Selection not applied, abort installation!"
        println
        exitPrg 1
      fi
    done
    SYS_IP_TAB=""
    if [ $_retVal -eq 0 ] ; then
      println "   * Rewrite the IP configuration file."
      _currNumber=0
      _nextNumber=1
      _ip_addr=""
      _ip_label=""
      _run="stage-"
      _bak="bak"
      # Determine backup file
      _BAK_FILE=$_IP_FILE.bak
      while [ -e $_BAK_FILE ] ; do
        _currNumber=$(($_currNumber+1))
        _BAK_FILE=$_IP_FILE.$bak$_currNumber
      done
      mv $_IP_FILE $_BAK_FILE
      # Now rewrite the configuration file each IP at a time
      _currNumber=0
      cp $_BAK_FILE $_IP_FILE.$_run$_currNumber
      _ip_addr=""
      _ip_label=""
      for ip_idx in ${!SYS_IP[@]} ; do
        _ip_addr=${SYS_IP[$ip_idx]}
        _ip_label=${SYS_IP_LABEL[$ip_idx]}
        println "     - Stage $_nextNumber: replace '<$_ip_label>' with '$_ip_addr'"
        cat $_IP_FILE.$_run$_currNumber | sed -e "s/<$_ip_label>/$_ip_addr/g" > $_IP_FILE.$_run$_nextNumber

        # Clean up the stage file
        rm $_IP_FILE.$_run$_currNumber
        _currNumber=$_nextNumber
        _nextNumber=$(($_nextNumber+1))
      done
      println "     - Build new configuration file '$_IP_FILE'"
      mv $_IP_FILE.$_run$_currNumber $_IP_FILE
      if [ ${#_IPT_ADDIP_IFACE_ALIAS[@]} -gt 0 ] ; then
        println "     - Add information of ALIAS interface configuration to file '$_IP_FILE'"
        echo >> $_IP_FILE
        echo "# Interface Configuration:" >> $_IP_FILE
        for iFace in ${_IPT_ADDIP_IFACE_ALIAS[@]} ; do
          echo "#>: $iFace" >> $_IP_FILE
        done
      fi 
      _retVal=0
    fi      
  fi
fi

if [ $_retVal -eq 1 ] ; then
  exitPrg 1
fi

# The main configuration must be in the conditional block.
# calling exit here does also end a possible calling script
# such as install.sh.
if [ $_P_CHECK_ONLY -eq 0 ] ; then
  ###########################################################################
  ## CHECK TOOLS
  ###########################################################################
  println "2) Check if required tools are available"
  _MISSING=()
  for cfg_test in "${_TOOLS[@]}" ; do
    print "   - locate '$cfg_test'..."
    which $cfg_test > /dev/null 2>&1
    if [ $? -eq 0 ] ; then
      println "found"
    else
      println "missing"
      _MISSING+=("$cfg_test")
      _FAILED=1
    fi
  done

  if [ $_FAILED -eq 1 ] ; then
    println
    println "   Install all required tools - See list:"
    for missing in "${_MISSING[@]}" ; do
      println "    - $missing"
    done
    exitPrg 1
  fi

  ###########################################################################
  ## CHECK IP CONFIGURATION
  ###########################################################################
  println "3) Check configured IP addresses for AS configurations:"
  _MISSING=()
  # Load the configured IP configuration file.
  loadIPConfig
  if [ ${#_IP_CONFIG[@]} -eq 0 ] ; then
    println "   - No IP configuration found, check '$_IP_FILE'!"
    println "     Otherwise nothing to configure!"
    exitPrg 1
  fi
  for cfg_test in "${_IP_CONFIG[@]}" ; do
    _EXAMPLE=$(echo $cfg_test | sed -e "s/\([^:]*\):[^:]\+:.*/\1/g")
    _ASN=$(echo $cfg_test | sed -e "s/[^:]*:\([^:]\+\):.*/\1/g")
    _ASIP=$(echo $cfg_test | sed -e "s/[^:]*:[^:]\+:\(.*\)/\1/g")
    print "   - Test AS $_ASN reachablility to $_ASIP..."
    ping -c 1 $_ASIP >> /dev/null
    if [ $? -eq 0 ] ; then
      println "OK"
    else
      println "Failed!"
      _MISSING+=("$_ASIP")
      _FAILED=1
    fi
  done
  if [ $_FAILED -eq 1 ] ; then
    println
    println "   Please verify the IP configuration in file '$_IP_FILE'!"
    for missing in "${_MISSING[@]}" ; do
      println "    - IP: $missing"
    done
    exitPrg 1
  fi

  ###########################################################################
  ## Write Configuration files
  ###########################################################################
  println "4) Configure examples:"
  for folder in "${_FOLDERS[@]}" ; do
    cd $folder
    # Determine if templates exist
    _TPL_FILES=($(ls | grep tpl$ | sed -e "s/.tpl$//g"))
    if [ ${#_TPL_FILES[@]} -gt 0 ] ; then
      # remove ending slash, that just messes up the seg command
      folder=$(echo $folder | sed -e "s%/$%%g")
      println "   * Start configuring $folder"
      # Read the configurations only for all and this folder
      loadIPConfig
      # Now for each template perform a rewrite
      for template in "${_TPL_FILES[@]}" ; do
        _TPL_CURR=0
        _TPL_NEXT=1
        print "     - Process $template.tpl ["
        cp "$template.tpl" "$template.tpl-$_TPL_CURR"
        if [ ! -e $template.tpl-$_TPL_CURR ] ; then
          println "]...ERROR: Template preparation failed."
          exitPrg 1
        fi
        _BLANK=""
        for as_config in "${_IP_CONFIG[@]}" ; do
          _ASN=$(echo $as_config | sed -e "s/[^:]*:\([^:]\+\):.*/\1/g")
          _ASIP=$(echo $as_config | sed -e "s/[^:]*:[^:]\+:\(.*\)/\1/g")
          print "$_BLANK($_ASN=$_ASIP)"
          _BLANK=" "
          #println "cat $template.tpl-$_TPL_CURR | sed -e \"s/{IP_AS_$_ASN}/$_ASIP/g\" > $template.tpl-$_TPL_NEXT"
          cat $template.tpl-$_TPL_CURR | sed -e "s/{IP_AS_$_ASN}/$_ASIP/g" > $template.tpl-$_TPL_NEXT
          rm $template.tpl-$_TPL_CURR
          _TPL_CURR=$_TPL_NEXT
          _TPL_NEXT=$(($_TPL_NEXT + 1))
          if [ ! -e $template.tpl-$_TPL_CURR ] ; then
            println "]...ERROR: Template preparation failed."
            exitPrg 1
          fi
        done
        mv $template.tpl-$_TPL_CURR $template.$_CONF_EXT
        if [ -e $template.$_CONF_EXT ] ; then
          println "]...OK"
        else
          println "ERROR: Could not generate template '$template.cfg'"
        fi
      done
    fi
    # Go back to start folder
    cd $_MY_ROOT
  done
fi