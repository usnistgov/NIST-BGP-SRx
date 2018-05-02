#!/bin/sh
# usage: get-from-quagga.sh <host> <command> | telnet
#
# Example: ./get-from-quagga localhost "show ip bgp" | telnet
#
# This does log into the router calls "show ip bgp" and disconnects
#

if [ "$1" == "-?" ] || [ "$1" == "?" ] ; then
  echo "$0 <host> <command> | telnet"
  exit 0
fi

echo open $1 2605                                                              
sleep 1 
# transmit password
echo zebra                                                                         
sleep 1                                                                      
echo enable                                                                        
sleep 1                                                                        
echo $2
sleep 5
echo q
#while :; do                                                                    
#    echo $2                                                                    
#    sleep 5                                                                    
#done                                                                            
#echo quit
