#!/bin/bash

while [ "$1" != "" ] ; do
  qsrx-publish --with-pem $1 repo
  shift
done
