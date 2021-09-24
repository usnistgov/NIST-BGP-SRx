# BGP-SRx INSTALL file #
This package provides tools to facilitate an easy install without
worrying about dependencies.
This file describes two simple means on how to install the software
on a minimal CentOS 7 and minimal CentOS 8 install.
This software package provides 2 scripts that help compiling and installing
all software modules on a fresh minimal CentOS 7/8 install.

## Build and Install ##

In case the build and install is preferred to be completely manual, please
check each module's source directory for README and INSTALL files that do
explain how the install should be done. This will be of big help if the
installation is done on systems other than CentOS7 and CentOS8.

This install section deals with helper scripts that allow a __plug'n play__
install fully automated as well as partial automated. The most important
script for building the software is ```get-BGPSRx.sh```. It is highly
recommended to get familiar with all the options of this script which can
be retrieved using the parameter ```-?```.

This script removed the hassle of specifying all ```configure``` parameters
etc. It allows to install the complete software in the folder where the code
base is located in. This is of interest for everyone who prefers to have the
install **sandboxed**.

### Platforms ###

We thoroughly tested the configuration on different platforms such as
Physical systems, VirtualBox, Proxmox, and Docker. All systems were using
CentOS-7 and CentOS-8 installs (minimal)

It is important to notice that the virtualized systems require the capability
to modify the systems networking. To allow that for docker instances, each
container must be called using the following command or similar:

```docker run --cap-add=NET_ADMIN -ti --name=C7 centos:7 bash```

### Manual Install ###
Installing everything manual without any install script.
This method does not use the install script specified in the README.md file.
For this method all libraries must be installed by hand before calling the
```./build-BGP-SRx.sh``` script.

To see the full list of repositories needed consult the CONTENT file. It is
updated to provide the latest information.

  The following command allows to generate a list of packages to required.

  ```cat CONTENT | grep requires | sort -u ``` 

  To generate the list with yum install command use the command below

  ```cat CONTENT | grep requires | sort -u | sed -e "s/- requires/yum install -y /g" | sh``` 

  Once all libraries are installed call the build script.

  ```./build-BGPSRx.sh -A -T -X examples 1 -I```

  - ```-A```: Answer all questions with Y(es)
  - ```-T```: Touch all autoconfig files. This is sometimes required.
  - ```-X```: Pass a configuration setting to the given module.

  The parameter ```-X examples 1``` specifies to have one parameter to the
  configure.sh script of examples. The parameter is ```-I``` for automated
  NIC-ALIAS installation.

  In case the build script fails, it is recommended to clean the failed module
  by calling ```./build-BGPSrx.sh -D <MODULE>``` before starting a new attempt.

  Each script provides the parameter "-?" for help. Also see the appropriate
  README file in each module folder for more information.

### Automated Install ###

To facilitate automated installation, create a file on the target system
called ```install.sh```. This file should be located in the ```/opt```
folder or any other folder you plan on installing the software in.
Edit the newly created ```install.sh``` file and copy the bash script listed
at the end of this file into the newly created ```install.sh``` file.

Once this is done, call ```sh install.sh```. The script will ask for a set of 
parameters.

  - (git|zip) Specifies the source of the software, clone a git repo or
    download and extract the zip file
  - (master|v5|v6) Specifies the version. Since 6.1 master and v6 are same.
  - (c8) Specify this install is on CentOS 8
  - (-I) Specify that interfaces are to be installed if missing, needed
    for the EXAMPLE project

This form is the simplest install. The install script does install all
required libraries, installs the system, and executes the system checks.

## Troubleshooting ##

### Install or Compile Fails ###

First look at the output and try to identify what went wrong. In most cases
the system provides enough information towards the end of the output what
happened. Each file can be compiled individually by specifying the module
name. It is recommended to use get familiarized with the build script using
the ```-?``` parameter. The proper command is ```./build-BGPSRx.sh -?```.

To clean a module (uninstall and clean configuration) cal the build script
```./build-BGPSRx.sh -D <module-name>``` or omit the ```<module-name>``` to
clean all modules.

### Problems Installing the Examples ###

The most common error while compiling and installing the examples is related
to networking. The examples are using multiple different interfaces. In case
not enough interfaces are available the system allows to automatically install
the required interfaces using ALIAS interfaces.

To allow an automatic install of ALIAS interfaces, the configure script of the
examples project needs the parameter ```-I```. To pass this parameter to the
configuration script the ```build-BGPSRx.sh``` script provides a mechanism to
pass the parameters through to the install script. This is done using the 
parameter ```-X <module-lower-case> <num-params> <param> [<param>*]```.
in this case the proper command is ```./build-BGPSRx.sh EXAMPLES -A -X examples 1 -I```
where the parameter ```-A``` which allows to answer every user input with 'Y'.

Then automatically installing the examples the configuration script determines
how many IP addresses are needed and scans each interface available. Then it
uses the already assigned IP address of the interface and tries to locate
available  IP addresses int he /24 network of the NIS's IP address.

NOTE: While parsing through the /24 network, the configuration script provides
a search progress bar ```[pppp-pp-]``` with  ```p``` indicating an address is
used and ```-``` a free address is located and will be used. The parsing starts
from ```A.B.C.1``` to ```A.B.C.254```.

#### Error During Install incl. Bootstrap Install Script

In case the ```buildBGP-SRx.sh``` script terminates in an error, analyse
the output of the script. Most likely the script will provide enough
information to decide the next steps.

The general order for installing is:
* SCA (needed by SRxSnP, QSRx, and BIO)
* SRxSnP (needed by QSRx) / BIO (order irrelevant)
* QSRx / BIO (if not installed already)

In case the install script stops with an error, carefully read the message.
Each module can be re-build manually. It is recommended to deep clean a module
prior configuration and building. This can be achieved using the command
```./buildBGP-SRx.sh -D <module> [<module> ]*```

The most likely error will happen during the configuration of the experiments using the ```buildBGP-SRx.sh``` script. In this case the following steps will most
likely solve the issues:

* Deep clean EXAMPLES:
  ```./buildBGP-SRx.sh EXAMPLES -D```
* Reconfigure and build EXAMPLES:
   ```./buildBGP-SRx.sh -A -T -X examples 1 -I```

Afterwards calling ```./buildBGP-SRx.sh -R``` allows to ***quicktest*** the installation. ssss

#### Lost ALIAS NIC After System Reboot ####

Once the system is rebooted, all ALIAS interfaces are lost. To re-bind the previously
assigned IP addresses the examples module must be re-configured. To RE-configure
the module, call ```./build-BGPSRx.sh -C EXAMPLES -X examples -1 -A``` to allow
re-binding of the previously installed IP addresses.

In case the IP addresses are not available anymore we recommend to clean the example
projects (all changed to installed examples will be lost) and rebuild the examples.

### The Fully Automated Bootstrap Install Script ###

This section provides a script that can be used for a CentOS 7 and
CentOS 8 minimal install. Copy the script below into a new install
script file and run it. The script is tested and should be free of
bugs but regardless it is to be used on your on risk!

The script functions works with default CentOS 7 and CentOS 8 Docker
containers, though the configuration of the experiments does fail if
not enough interfaces are provided to the container itself. Due to
security restrictions, this script is not able to generate alias
interfaces from within a docker container as it is possible from within
virtual machines, [ProxMox](https://www.proxmox.com/en/) containers,
and physical systems. The script is configured for CentOS 7 distributions
but also can operate under CentOS 8 distributions using the switch 'c8'.

In case the target system is a Docker container, the container must
either contain 3 or more NICs or be started with the parameter
```docker run --cap-add=NET_ADMIN -ti --name=C7 centos:7 bash```
to allow for the examples being properly installed.
The issue is related to allowing the generation of missing ALIAS NICs
from within the docker image.

```
#!/bin/bash

#Install Script for BGP-SRx on clean CentOS 7 and CentOS 8 install
echo "Install Script for BGP-SRx on clean CentOS 7 and CentOS 8 install"

# wget:   needed to retrieve the GitHub repo via zip file
# unzip:  needed to extract the repo
# git:    needed to retrieve the GitHub repo via clone
# epel-release: needed for uthash-devel later on
# sed:    needed to configure the EXAMPLES correctly
# screen: needed to allow EXAMPLES to be started in separate screen sessions
# telnet: needed for view-tables command in examples
# ifconfig: needed to identify IP addresses in the system for EXAMPLES configuration
# gnome-terminal: Only is used on gnome-based systems (manual install)

repo=( "https://github.com/usnistgov/NIST-BGP-SRx" NIST-BGP-SRx-master
       "--branch__version5__https://github.com/usnistgov/NIST-BGP-SRx" NIST-BGP-SRx-master
       "https://github.com/usnistgov/NIST-BGP-SRx/archive/refs/heads/master.zip" NIST-BGP-SRx-version6
       "https://github.com/usnistgov/NIST-BGP-SRx/archive/refs/heads/version5.zip" NIST-BGP-SRx-version5
      )

select_repo=0
select_file=$(($select_repo+1))
version=0
zip_start=0
use_c8=0
switches=( "master" "v5" "v6" )
sw_str=$(echo ${switches[@]} | sed -e "s/ /|/g")
in_docker_image="$(cat /proc/1/cgroup | grep 'docker/' | tail -1 | sed 's/^.*\///' | cut -c 1-12)"

for item in ${repo[@]} ; do
  echo $item | grep -e "\.zip$" > /dev/null
  if [ $? -eq 0 ] ; then break; else zip_start=$(($zip_start+1)); fi
done

# Used to allow configuration of interface addresses.
config_iface=""

mode=""
while [ "$1" != "" ]
do
  case "$1" in 
    "git") mode="git"; select_repo=0; tool_pkg="$(echo $tool_pkg) git" ;;
    "zip") mode="zip"; select_repo=zip_start ; tool_pkg="$(echo $tool_pkg) wget unzip" ;;
    "-I")  config_iface='-X examples 1 -I' ;;
    "-h" | "-?" | "?" | "h") 
           echo "$0 <git|zip> <$sw_str> [c8] [-I]"; 
           echo "  git  Retrieve the git repository"
           echo "  zip  Download and install the zip file"  
           echo "  c8   Install on CentOS 8 system"
           echo "  -I   Allow script to install ALIAS interfaces for experiments"
           echo "       if needed. See ./buildBGP-SRx.sh -? for more information!"
           exit 
           ;;

    "master" \
    | "v6") select=0; version="GitHub V6" ;;
    "v5")   select=1; version="GitHub V5" ;;

    "pr6") echo "Pre-Release is deprecated! Abort !!"; exit 99 ;;

    "c8") echo "Prepare for CentOS 8"
          tool_pkg="$(echo $tool_pkg) dnf-plugins-core"
          devel_pkg="$(echo $devel_pkg) make tar patch"
          use_c8=1
          ;;
    *) echo "Unknown parameter '$1'"; exit ;; 
  esac
  shift
done

if [ "$version" == "0" ] ; then
  echo "You must select an install version."
  echo "$0 <git|zip> <$sw_str> [c8] [-I]"
  exit 1
else
  echo "Install version $version!"
fi

if [ "$mode" == "" ] ; then
  echo "You must select an install mode."
  echo "$0 <git|zip> <$sw_str> [c8] [-I]"
  exit 1
else
  echo "Use $mode mode"
fi

select_repo=$(( ($select*2) + $select_repo ))
select_fldr=$(( $select_repo+1 ))

repo_name="$(echo ${repo[$select_repo]} | sed -e "s/__/ /g")"
repo_fldr="${repo[$select_fldr]}"

tool_pkg="$(echo $tool_pkg) gcc patch openssl epel-release autoconf net-tools bind-utils sudo which sed telnet"
devel_pkg="$(echo $devel_pkg) file screen libconfig-devel openssl-devel uthash-devel readline-devel net-snmp-devel"
echo "yum -y install $tool_pkg"
yum -y install $tool_pkg
if [ ! $? -eq 0 ] ; then
  echo
  echo "An error occurred installing one or more of the required packages!"
  echo
  exit 1
fi
# $devel_pkg requires one package from the epel-release repo and for C8 from CentOS8-PowerTools. 
# Therefore 2 steps of install.
if [ $use_c8 -eq 1 ] ; then
  if [ "$in_docker_image" == "" ] ; then
    # In VM or real system
    echo "Enable CentOS-PowerTools"
    yum config-manager --set-enabled PowerTools
  else
    # In docker container
    echo "Enable CentOS-Linux-PowerTools"
    yum config-manager --set-enabled powertools
  fi
  if [ ! $? -eq 0 ] ; then
    echo
    echo "An error occurred during enabling the PowerTools repository!"
    echo
    exit 1
  fi
fi
echo “yum -y install $devel_pkg”
yum -y install $devel_pkg
if [ ! $? -eq 0 ] ; then
  echo
  echo "An error occurred installing one or more of the required packages!";
  echo
  exit 1
fi

if [ "$mode" == "zip" ] ; then
  # Now get the repository and unpack it
  echo "wget $repo_name"
  wget $repo_name
  echo "unzip $( basename $repo_name )"
  unzip $( basename $repo_name )
else
  # Now get the source via git clone
  echo "git clone $repo_name $repo_fldr"
  git clone $repo_name $repo_fldr
fi

# Enter into the Source code folder
echo "cd $repo_fldr/"
cd $repo_fldr/

# Check if enough IP addresses are available
ip_needed=$(grep "<ip-address-[0-9]\+>" examples/IP-Address.cfg | sed -e "s/.*\(<.*>\)/\1/g" | sort -u | wc -l)
ip_available=$(ip addr | grep "inet " | wc -l)
if [ $ip_available -gt 0 ] ; then
  # Remove count for 127.0.0.1
  ip_available=$(( $ip_available-1 ))
fi
if [ $ip_available -lt $ip_needed ] && [ "$config_iface" == "" ]; then
  echo 
  echo "******************************************************************************"
  echo " It is recommended to run the install script with the option -I to allow"
  echo " the installation of additional ALIAS interfaces."
  echo " The current system configuration does NOT have enough IP addresses available"
  echo " to properly install the EXAMPLES."
  echo "   - Available IPv4 Addresses: $ip_available"
  echo "   - Needed IPv4 Addresses: $ip_needed"
  echo "******************************************************************************"
  echo
  yn=""
  while [ "$yn" == "" ] ; do
    read -p "Continue using the recommended setting -I ? [Y/N]" yn
    case $yn in
      "y" | "Y") config_iface='-X examples 1 -I' ;;
      "n" | "N") config_iface='' ;;
      *) yn="" ;;
    esac
  done
fi

# Build the software (-A runs it fully automated) (-T prevent aclocal error)
# $config_iface might add -I if requested.
echo "./buildBGP-SRx.sh -A -T $config_iface"
./buildBGP-SRx.sh -A -T $config_iface
errCode=$?

if [ $errCode -gt 10 ] && [ $errCode -lt 20 ] ; then
  errCode=$(( $errCode - 10 ))
  echo "Error during install of SRx Crypto API (SCA)!"
fi
if [ $errCode -gt 20 ] && [ $errCode -lt 30 ] ; then
  errCode=$(( $errCode - 20 ))
  echo "Error during install of SRx Server and Proxy (SRxSnP)!"
fi
if [ $errCode -gt 30 ] && [ $errCode -lt 40 ] ; then
  errCode=$(( $errCode - 30 ))
  echo "Error during install of QuaggaSRx (QSRx)!"
fi
if [ $errCode -gt 40 ] && [ $errCode -lt 50 ] ; then
  errCode=$(( $errCode - 40 ))
  echo "Error during install of BGPsec-IO (BIO)!"
fi
if [ $errCode -gt 50 ] && [ $errCode -lt 60 ] ; then
  errCode=$(( $errCode - 50 ))
  echo "Error during install of Examples (EXAMPLES)!"
  echo "In case alias interfaces needed to be installed,"
  if [ "$(whoami)" != "root" ] ; then
    echo "make sure '$(whoami)' is in the sudoers file."
    echo -n "In addition "
  fi
  echo "be aware that interfaces cannot be added from "
  echo "within Docker images. Configure the Docker image with"
  echo "the required amount of interfaces prior configuring the"
  echo "EXAMPLES project!"
fi

if [ $errCode -eq 0 ]  ; then
  # Call the quick tester
  echo "./buildBGP-SRx.sh -R"
  ./buildBGP-SRx.sh -R
  errCode=$?

  if [ $errCode -gt 0 ] ; then
    echo "An error [$errCode] occurred during testing."
    exit $errCode
  fi 
else
  echo 
  echo "To rerun the build script, call ./buildBGP-SRx.sh [SCA] [SRxSnP] [QSRx] [BIO] [EXAMPLES]"
fi

# Display the compiled and installed software 
echo "The installed software can be found at:"
ls | grep local-

exit $errCode
```