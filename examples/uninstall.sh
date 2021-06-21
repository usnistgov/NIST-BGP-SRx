#!/bin/bash

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
##############################################################################s

MY_FOLDER="opt/bgp-srx-examples"
FOLDERS=( $(ls -d */) )

# Print the given text and exit the shell scipt
# 
# $1 The text to display
# $2 The exit code or 0
#
print_and_exit()
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

syntax()
{
  print_and_exit "Syntax: $0 <install-log-file> [--no-interactive <Y|N>]" $1
}

if [ "$1" == "" ] ; then
  syntax 0
fi

# parse parameter
while [ "$1" != "" ] ; do
  case "$1" in
    "--no-interactive")
      shift
      echo "Parse $1"
      parseYN "-$1"
      if [ $? -eq 1 ] ; then
        echo "ERROR: switch --no-interactive needs a default answer!"
        syntax 1
      fi 
      shift
      echo "Operate in non interactive mode."
      ;;
    "-?" | "?" | "-h" | "-H")
      syntax 0
      ;;
    *) 
      INSTALL_LOG=$1
      if [ ! -e $INSTALL_LOG ] ; then  
        echo "Install log '$INSTALL_LOG' not found!"
        print_and_exit "Abort operation" 1
      fi
      shift
      ;;
  esac
done

if [ ! -e $INSTALL_LOG ] ; then
  echo "Install file '$INSTALL_LOG' not found!"
  print_and_exit "Abort uninstall" 1
fi

MODULES=( $(sort -u $INSTALL_LOG) )

echo "Verify uninstall..."
# Each module must be a valid directory
# That maked sure we don't accidentally use a shell script or so
# as install log file.
for module in ${MODULES[@]} ; do
  if [ ! -d $module ] ; then
    echo "Invalid module: '$module'"
    echo "Verify the install file '$INSTALL_LOG'"
    print_and_exit "Abort Operation!" 1
  fi
done

# Now find an available backup name
bak_NUM=1
while [ -e "$INSTALL_LOG.$bak_NUM" ] ; do
  bak_NUM=$(($bak_NUM + 1))
done

# Create a backup
mv $INSTALL_LOG $INSTALL_LOG.$bak_NUM > /dev/null

# Stop if the backup could not be generated or found
if [ ! $? -eq 0 ] ; then
  echo "Could not rename '$INSTALL_LOG'"
  print_and_exit "Abort Operation" 1
fi
if [ -e "$INSTALL_LOG.bak_NUM" ] ; then
  echo "Backup '$INSTALL_LOG.$bak_NUM' not found!"
  print_and_exit "Abort Operation" 1
fi

# Now start the uninstall - Scarry act - we delete data
echo "Start Unininstall..."
# Clean the install log
MODULES=( $(echo ${MODULES[@]} | sed -e "s#//#/#g") )
for module in ${MODULES[@]} ; do
  echo "Found module '$module'"
  readYN "- Confirm removal --This cannot be un-done-- (Y/N): "
  if [ $? -eq 1 ] ; then
    echo "- Removing module..."
    rm -rf $module
  else
    echo "- Skipping module"
    echo "$module" >> $INSTALL_LOG
  fi
done

# Now check if still installed modules exist, if so keep the log,
# otherwise remove all log files.
if [ -e $INSTALL_LOG ] ; then
  echo "Not all modules were uninstalled"
else
  echo "All modules uninstalled, remove install log backups"
  rm -f $INSTALL_LOG.*
fi
 
echo "Done."
