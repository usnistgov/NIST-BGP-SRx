#!/bin/bash

MY_FOLDER="opt/bgp-srx-examples"
FOLDERS=( $(ls -d */) )

# Print the given text and exit the shell scipt
# 
# $1 The text to display
# $2 The exit code or 0
#
function print_and_exit()
{
  if [ "$1" != "" ] ; then
    echo $1
    shift
  fi
  if [ "$1" == "" ] ; then
    exit
  else
    exit $1
  fi 
}

# 
# Print the program syntax and exit with the given error code
#
# $1 Exit code (optional)
#
function syntax()
{
  local RETVAL=0
  if [ "$1" != "" ] ; then
    RETVAL=$1
  fi
  print_and_exit "Syntax: $0 <install-dir>" $RETVAL
}

#
# Check if the given $1 parameter is not 0. In this case
# exit the program and print the text in $2
#
function checkRetVal()
{
  if [ ! $1 -eq 0 ] ; then
    print_and_exit "$2" $1
  fi
}

##############################################################################
##     Main Section
##############################################################################

if [ "$1" == "" ] ; then
  syntax 0
fi

# Check that the project is properly configured.
./configure.sh -c
_retVal=$?
if [ $_retVal -eq 1 ] ; then
  exit $_retVal
fi

INSTALL_FOLDER=" "
while [ "$1" != "" ] ; do
  case "$1" in
    "-?" | "-h" | "-H" | "?")
      syntax 0
      ;;
    *)
      INSTALL_FOLDER=$( echo "$1"/$MY_FOLDER | sed -e "s#//#/#g")        
      ;;
  esac
  shift
done

if [ "$INSTALL_FOLDER" == " " ] ; then
  echo "Install directory ' ' invalid!"
  print_and_exit "Abort installation!" 1
fi

if [ ! -e $INSTALL_FOLDER ] ; then
  echo "Create folder $INSTALL_FOLDER"  
  mkdir -p $INSTALL_FOLDER
  _RET_VAL=$?
  if [ ! $? -eq 0 ] || [ ! -e $INSTALL_FOLDER ]; then
    echo "An error occurred during creation of the install folder."
    print_and_exit "Abort operation" 1
  fi
fi

# backup of install folder is not necessary, uninsall does a unique sort
INSTALL_LOG=$0.log

# Now install each module within the examples folder exept template files.
for folder in ${FOLDERS[@]} ; do
  echo "Install $folder in  $INSTALL_FOLDER"
  _INSTALL=( $(find $folder -type d) )
  for instFolder in ${_INSTALL[@]} ; do
    mkdir -p $INSTALL_FOLDER/$instFolder >> /dev/null 2>&1
    checkRetVal $? "Error during install of '$folder', abort install"
  done
  _INSTALL=( $(find $folder | sed -e "s/.*\.tpl$//g" | sed -e "/^$/d") )
  for instFile in ${_INSTALL[@]} ; do
    cp $instFile $INSTALL_FOLDER/$instFile >> /dev/null 2>&1
  done
  
  echo "$INSTALL_FOLDER/$folder" >> $INSTALL_LOG
done

print_and_exit "Done." 0
