#!/bin/bash
if [ "$1" == "" ] ; then
  data="data"
else
  data="$1"
fi 

../local-trunk/bin/rpkirtr_svr -f src/test/test-"$data".rpki 5000
