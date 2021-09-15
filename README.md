# BGP (S)ecure (R)outing E(x)tension Software Suite

The NIST BGP Secure Routing Extension (NIST-BGP-SRx) is an open source
reference implementation and research platform for investigating emerging BGP
security extensions and supporting protocols such as RPKI Origin Validation
and BGPsec Path Validation.

Additional information can be found at
https://www.nist.gov/services-resources/software/bgp-secure-routing-extension-bgp-srx-prototype

Please read the [NIST disclaimer](https://www.nist.gov/director/copyright-fair-use-and-licensing-statements-srd-data-and-software) regarding
the software of this project, the information it provides and the other
resources it uses. In particular, note that these software prototypes are
expressly provided as is and are intended for research and development purposes
only.

Additional 3rd party license Information can be found in the
quagga-srx and srx-server codebase in files and folders listed
but not limited to:

  * [quagga-srx/COPYING](quagga-srx/COPYING)
  * [quagga-srx/COPYING.LIB](quagga-srx/COPYING.LIB)
  * [srx-server/extras/README](srx-server/extras/README)
  * [srx-server/extras/COPYING](srx-server/extras/COPYING)

## Project Status

The project contains two major versions:
* **version 6** which is the current major
version providing BGPsec path validation (BGP-PV), BGP origin validation (BGP-OV) and ASPA validation (BGP-AV).

* **version 5** only contains BGP-PV and BGP-OV.

Version 6 provides
an overhaul of the QuaggaSRx policy processing by separating BGP-PV and BGP-OV as well as adding ASPA validation (BGP-PV).
This version is the preferred version available in the master branch.

## Branching

The main branch of the repository will deliver NIST-BGP-SRx version 6.
Branch:
* **master**: This branch provides the current recommended version of NIST-BGP-SRx (version6.1).
            This version contains ASPA validation and a complete re-write of the Quagga-SRx
            policy scripting and processing for BGP-OV, BGP-PV, and BGP-AV.
            The ASPA implementation follows the IETF draft draft-ietf-sidrops-aspa-verification-07
            including an expected modification for Downstream validation which is expected in the
            next draft.
* **version5**: This branch stands on its own and is only maintained for BUG fixes.
            New features are added to the master branch which is contains NIST-BGP-SRx Version 6.
* **pre-release-6** (*deprecated*): This branch was a "sneak preview" of the upcoming version 6 and
            is not further maintained and expected to be removed in the future.

## Testing

The software was continuously tested during development. We performed
interoperability test and published them at IETF SIDR meetings as well as
IETF SIDROPS meetings.
The codebase itself provides a simple testing to test basic functionality.
The development was done using CentOS 7 though we compiled the project on CentOS 8 and successfully executed the test suite provided in this release.

### Unit Test

BGP-SRx consists of fours semi-independent components. Semi-independent only
because some components such as the srx-crypto-api and srx-server do provide
API's for other components within the package. The development though is
performed separately.

For this reason each component will have its own unit tests if at all. These
will if available be located within the appropriate source folder or the newly
added EXAMPLES project which will be installed in ```opt/bgp-srx-examples```. Please
consult the README files located in each component directory for more information.

### Performance Test

The software was tested throughout the development and multiple publications are
available regarding performance testing. Please visit the
[NIST BGP-SRx project page](https://bgp-srx.antd.nist.gov) for more information.


## Getting Started

This project archive provides a "buildBGP-SRx.sh" shell script for an easy
sandbox installation. This script allows to have the software installed within
the code folder.

The codebase itself contains multiple components

These instructions will get you a copy of the project up and running on your
local machine for development and testing purposes.
See Installing for notes on how to deploy the project on a live system.

### Prerequisites

It is recommended to install the "Development Tools" which contain
a full set of libraries and tools to build the software. For a list
of the required developer (*-devel) packages in CentOS please see
the [CONTENT](CONTENT) file.

For minimal installs without the "Development Tools" the following
packages are needed:

- patch        ( needed to compile the extras package in srx-server )
- openssl      ( required for srx-crypto-api )
- epel-release ( provides the uthash-devel package )
- gcc
- automake     ( only needed if the following error is displayed!
                 WARNING: 'aclocal-1.13' is missing on your system. )

The section quick-install below provides a sample script that can be
used to configure and install the software without prior download.

## Building & Installing

This archive provides two forms of building and installing the software.

* Using Linux System(s) / VM / Containers other than docker
* Using Docker

### Building & Installing (Single System Install - Physical system, VM, other)

The CONTENT file does specify what development libraries are required
to be for a successful installation. This is based upon a fresh CentOS 7
install.
Other distributions might require additional or different packages.

It is recommended to use the provided build and install script rather
than configuring and compiling the software manual. Nevertheless the
build script allows different modes of operation which are explained
in detail by calling

```
./buildBGP_SRx.sh -h
```

#### Automated Building

For building the software we provide a bash shell script which allows
the software to be configured, build, and installed within the folder
it is stored in. This folder functions as a sandbox.

```
./buildBGP-SRx.sh
```

Furthermore this script allows to build, configure, install, or clean
not only the complete project but also separately sub components.

**SCA:**       SRx Crypto API

**SRxSnP:**    SRx-Server and SRx-Proxy

**QSRx:**      Quagga SRx

**BIO:**       BGPsec traffic generator and crypto module tester.

**EXAMPLES:**  Examples and test scripts the  BGP-SRx modules.

#### Manual Building

For manual installation, each component's separate source folder contains the
appropriate README and INSTALL files. They contain all necessary information.
It is important to note that building the components requires to keep a certain
order. It is also possible to manually call the auto build script for each
component individually.

To rebuild the configuration scripts call *autoreconf -i --force*. For that
the automake tools are required.

To build and install only the SRx Crypto API use the SCA option.
```
./buildBG_SRx.sh SCA
```

##### Required to build SRx Crypto API (SCA):
1) Build SRx Crypto API (srx-crypto-api)

##### Required to build SRx-Server (SRxSnP):
1) Build and install SRx Crypto API (srx-crypto-api)
2) Build SRx Server and Proxy (srx-server)

##### Required to build BGPsec IO (BIO):   
1) Build and install SRx Crypto API (srx-crypto-api)
2) BGPsec-IO (bgpsec-io)

##### Required to build Quagga-SRx (QSRx):
1) Build and install SRx Crypto API (srx-crypto-api)
2) Build and install SRx Server and Proxy (srx-server)
3) Quagga SRx (quagga-srx)

#### Using Bootstrap Install Script

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

To use this script, create a folder and create an empty file. Copy
the above content into the file and call 'sh <your-file>'

To install the binaries outside of the "sandbox" folder where the code is
located, call the build script ```buildBGP-SRx.sh -P <absolute-path> [<more parameters>]```
and the binaries will will be installed in the given ```<absolute-path>```
folder. Make sure the build script has access to either create the path
and or create the binaries in the  given path.

#### Error during install incl. Bootstrap Install Script

In case the ```buildBGP-SRx.sh``` script terminates in an error, analyse
the output of the script. Most likely the script will provide enough
information to decide the next steps.

The general order for installing is:
* SCA (needed by SRxSnP, QSRx, and BIO)
* SRxSnP (needed by QSRx) / BIO (order irrelevant)
* QSRx / BIO (if not installed already)

In case the install script stops with an error, read carefully the message.
Each module can be re-build manually. It is recommended to deep clean a module
prior configuration and building. This can be achieved using the command
```./buildBGP-SRx.sh -D <module> [<module> ]*```

The most likely error will happen during the configuration of the experiments using the ```buildBGP-SRx.sh``` script. In this case the following steps will most
likely solve the issues:

* Deep clean EXAMPLES:
  ```./buildBGP-SRx.sh EXAMPLES -D```
* Reconfigure and build EXAMPLES:
   ```./buildBGP-SRx.sh -A -T -X examples 1 -I```

Afterwards calling ```./buildBGP-SRx.sh -R``` allows to ***quicktest*** the installation. 

### Quick Functional Test / Demo

The BGP-SRx software suite does provide a test system integrated in the build  
script. The script does test proper functionality of the srx-crypto-api as well
as the integration into BGPsec-IO.

Furthermore BGP-SRx provides a complete set of examples, demos which are
located in the examples folder but will be compiled for the host system
using the buildBGP-SRx.sh script.
The examples will be installed in the folder ```opt/bgp-srx-examples/``` folder.
Each example does have it's own example starter script which allows to easily
start all needed components either using the ```screen``` tool (default) or
the ```gnome-terminal``` using ```-t```.
Furthermore the test folders contain an appropriate run/sh script.
All scripts provide a help which will be printed by using the ```-?``` switch.

### Building and Installing using Docker

#### Docker Requirements

* **Docker Version:**

  Docker Engine - Community version 18 or later is required.

* **Operating Systems:**

  MacOS, Linux, Windows 10 Professional or Enterprise edition
    (https://docs.docker.com/engine/install/)
* **Docker-compose install links:**

  https://docs.docker.com/compose/install/

#### Docker Running Examples

In order to edit QuaggaSRx, SRx Server and Rpkirtr server's configuration files in detail,
please refer to each example file within the example directories.

* **Generate Docker image**

  To generate docker image, you need to run 'docker build' command with the Dockerfile

  ```
  docker build -f <docker file> -t <docker image name> <path>
  ```
  In our example,
  ```
  docker build -t nist/bgp-srx .  (Don't forget '.' at the end)
  ```

* **Staring the RPKI Cache Test Harnes (rpkirtr_svr)**
  
  (1) Create the configuration file for the RPKI Cache Test Harnes: *rpkirtr_svr.conf*
  ```
  echo "add 10.0.0.0/8 9 7675" > ./rpkirtr_svr.conf
  ```

  (2) Start the docker container for *rpkirtr_svr* instance
  ```
  docker run --rm -it --name rpkirtr_server \
         -v $PWD/./rpkirtr_svr.conf:/usr/etc/rpkirtr_svr.conf \
         -p 323:323 \
         nist/bgp-srx \
         rpkirtr_svr -f /usr/etc/rpkirtr_svr.conf
  ```
  Or run a *rpkirtr_svr* instance with a pre-defined configuration
  ```
  docker run --rm -it --name rpkirtr_server \
         -v <location/user-defined/rpkirtr_svr.conf:/usr/etc/rpkirtr_svr.conf \
         -p 323:323 \
         nist/bgp-srx \
         rpkirtr_svr -f /usr/etc/rpkirtr_svr.conf
  ```

* **Starting the SRx Server**

  (1) Identify the IP address of the RPKI Cache Test Harness *rpkirtr_svr*
  ```
  docker inspect --format '{{ .NetworkSettings.IPAddress }}' <container name>
  ```
  Here:
  ```
  docker inspect --format '{{ .NetworkSettings.IPAddress }}' rpkirtr_server

  Example Result: 172.17.0.2
  ```
  Using the retrieved IP address, configure the SRx Server instance to point ot the RPKI Cache Test Harness. Here replace 172.17.0.2 with the IP address retrieved prior.
  ```
  sed "s/localhost/172.17.0.2/g" ./srx-server/src/server/srx_server.conf > /tmp/srx_server.conf
  ```
  Now start the SRx Server *srx_server* docker container.
  ```
  docker run --rm -it --name srx_server \
         -v /tmp/srx_server.conf:/usr/etc/srx_server.conf \
         -v $PWD/./examples/bgpsec-keys/:/usr/opt/bgp-srx-examples/bgpsec-keys \
         -p 17900:17900 -p 17901:17901 \
         nist/bgp-srx \
         srx_server -f /usr/etc/srx_server.conf
  ```
  Or use our pre-defined keys and config files in the example directories
  ```
  docker run --rm -it --name srx_server \
         -v </location/user-defined/srx_server.config>:/usr/etc/srx_server.conf  \
         -v </location/user-defined/keys/>:/usr/opt/bgp-srx-examples/bgpsec-keys \
         -p 17900:17900 -p 17901:17901 \
         nist/bgp-srx \
         srx_server -f /usr/etc/srx_server.conf
  ```

* **Starting QuaggaSrx**

  First gather the IP address for the SRx Server instance as described earlier and add modify the quagga configuration.
  ```
  docker inspect --format '{{ .NetworkSettings.IPAddress }}' srx_server

  Example result: 172.17.0.3
  ```
  Use the learned IP address and update the QuaggaSRx configuration
  ```
  sed "s/srx connect/srx connect 172.17.0.3 17900/g" ./quagga-srx/bgpd/bgpd.conf.sampleSRx > /tmp/bgpd.conf
  ```
  Finally start the QuaggaSRx server
  ```
  docker run --rm -it --name quaggasrx \
         -v /tmp/bgpd.conf:/usr/etc/bgpd.conf \
         -v $PWD/./examples/bgpsec-keys/:/usr/opt/bgp-srx-examples/bgpsec-keys \
         -p 179:179 -p 2605:2605 \
         nist/bgp-srx \
         bgpd -f /usr/etc/bgpd.conf
  ```
  Or use pre-defined keys and config files in our example directories
  ```
  docker run --rm -it --name quaggasrx \
         -v </location/user-defined/quagga.config>:/usr/etc/bgpd.conf  \
         -v </location/user-defined/keys/>:/usr/opt/bgp-srx-examples/bgpsec-keys \
         -p 179:179 -p 2605:2605 \
         nist/bgp-srx \
         bgpd -f /usr/etc/bgpd.conf  
  ```

* **Docker compose**

  Docker Compose (https://docs.docker.com/compose/) allows to  define and run multi-container Docker applications.
  With Compose, you use a YAML file to configure your application’s services.
  Then, with a single command, you create and start all the services from your configuration.

  The following command will execute all three docker containers in the docker-compose.yml file.
  ```
  docker-compose up
  ```
  To stop and remove containers, simply **Ctrl-C** twice or
  ```
  docker-compose down
  ```

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute
to the projects.

## Authors & Main Contributors

### Developer

- Oliver Borchert (Lead)
- Kyehwan Lee

### Previous Developer

- Patrick Gleichmann

## Copyright

For license information see the [LICENSE](LICENSE) file.

## Contacts

For information, questions, or comments, contact by sending
an email to itrg-contact@list.nist.gov.
