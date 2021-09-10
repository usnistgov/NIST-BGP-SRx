#!/bin/bash
# The following parameters are defined in the main start program
# but can be overwritten here. For more detail on that they do
# please see the file ../bin/start_example.sh

# PORT_CACHE=50000
# PORT_SRX=17900
# PORT_ROUTER=179
# STOP_ALL_LOOP=3
# LISTEN_TIMEOUT=10
# SUDO_MODULES+=("router")
# SIT_AND_WAIT_TIME=5
# SIT_AND_WAIT_MOD=("router")

CFG_CACHE_NAME="rpki_cache.script"
CFG_SRX_NAME="srx_server.conf"
CFG_SCA_NAME="srxcryptoapi.conf"
CFG_ROUTER_NAME="as65000.bgpd.conf"
CFG_BIO1_NAME="as65005.bio.conf"
CFG_BIO2_NAME="as65010.bio.conf"

_STARTER="../bin/start_example.sh"
if [ -e $_STARTER ] ; then
  _BGP_SRX_CALLER=$(pwd | sed -e "s#.*/\([^/]*\)#\1#g")
  source $_STARTER 
else
  echo "Cannot find '$_STARTER', Abort Operation"
  exit 1 
fi
