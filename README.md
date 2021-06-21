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

The code base is currently in maintenance mode only. Other projects within 
the larger scope do use portions of this implementation and these portions, 
e.g. SRx-Server will be further enhanced to provide the needed functionality.


## Testing Summary

The software was continuously tested during development. We performed 
interoperability test and published them at IETF SIDR meetings as well as 
IETF SIDROPS meetings.
The codebase itself provides a simple testing to test basic functionality.


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
of the required developer (*-devel) packages in CENTOS please see 
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

### Building & Installing

The CONTENT file does specify what development libraries are required 
to be for a successful installation. This is based upon a fresh 
CENTOS 7 install. 
Other distributions might require additional or different packages. 

It is recommended to use the provided build and install script rather 
than configuring and compiling the software manual. Nevertheless the 
build script allows different modes of operation which are explained 
in detail by calling

```
./buildBG_SRx.sh -h
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

### Manual Building

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

#### For SRx Crypto API (SCA):
1) Build SRx Crypto API (srx-crypto-api)

#### For SRx-Server (SRxSnP):
1) Build and install SRx Crypto API (srx-crypto-api)
2) Build SRx Server and Proxy (srx-server)

#### For BGPsec IO (BIO):   
1) Build and install SRx Crypto API (srx-crypto-api)
2) BGPsec-IO (bgpsec-io)

#### For Quagga-SRx (QSRx):
1) Build and install SRx Crypto API (srx-crypto-api)
2) Build and install SRx Server and Proxy (srx-server)
3) Quagga SRx (quagga-srx)

### Install Script

This section provides a script that can be used for a CENTOS 7 minimal
install:

```
#Install Script for BGP-SRx on clean CentOS-7 install
echo "Install Script for BGP-SRx on clean CentOS-7 install"

# wget: needed to retrieve the GitHub repo via zip file
# unzip: needed to extract the repo
# git:  needed to retrieve the GitHub repo via clone
# epel-release: needed for uthash-devel later on

mode=""
while [ "$1" != "" ]
do
  case "$1" in 
    "git") mode="git" ; tool_pkg="git" ;;
    "zip") mode="zip" ; tool_pkg="wget unzip" ;;
    "-h" | "-?" | "?" | "h") echo "$0 <git|zip>"; exit ;;
    *) echo "Unknown parameter '$1'"; exit ;; 
  esac
  shift
done

if [ "$mode" == "" ] ; then
  echo "You must select an install mode."
  echo "$0 <git|zip>"
  exit 1
else
  echo "Use $mode mode!"
fi

tool_pkg="$(echo $tool_pkg) gcc patch openssl epel-release autoconf"
devel_pkg="libconfig-devel openssl-devel uthash-devel readline-devel net-snmp-devel"
echo "yum -y install $tool_pkg"
yum -y install $tool_pkg
# $devel_pkg requires one package from the epel-release repo. Therefore 2 steps of install.
echo “yum -y install $devel_pkg”
yum -y install $devel_pkg

if [ "$mode" == "zip" ] ; then
  # Now get the repository and unpack it
  echo "wget https://github.com/usnistgov/NIST-BGP-SRx/archive/master.zip"
  wget https://github.com/usnistgov/NIST-BGP-SRx/archive/master.zip
  echo "unzip master.zip"
  unzip master.zip 
else
  # Now get the source via git clone
  echo "git clone https://github.com/usnistgov/NIST-BGP-SRx NIST-BGP-SRx"
  git clone https://github.com/usnistgov/NIST-BGP-SRx NIST-BGP-SRx-master
fi

# Enter into the Source code folder
#echo "cd NIST-BGP-SRx-master/"
cd NIST-BGP-SRx-master/

# Build the software (-A runs it fully automated)
echo "./buildBGP-SRx.sh -A"
./buildBGP-SRx.sh -A

# Call the quick tester
echo "./buildBGP-SRx.sh -R"
./buildBGP-SRx.sh -R

# Display the compiled and installed software 
echo "The installed software can be found at:"
ls | grep local-
```

To use this script, create a folder and create an empty file. Copy
the above content into the file and call 'sh <your-file>'

To install the binaries outside of the "sandbox" folder where the code is
located, call the build script ```buildBGP-SRx.sh -P <absolute-path> [<more parameters>]```
and the binaries will will be installed inthe given ```<absolute-path>```
folder. Make sure the build script has access to either create the path 
and or create the binaries in the  given path.

### Quick Functional Test / Demo

The BGP-SRx software suite does provide a test system integrated in the build  
script. The script does test proper functionality of the srx-crypto-api as well 
as the integration into BGPsec-IO.

Furthermore BGP-SRx provides a complete set of examples, demos which are
located in the examples folder but will be compiled for the host system 
uding the buildBGP-SRx.sh script. 
The examples will be installed in the folder ```opt/bgp-srx-examples/``` folder.
Each example does have it's own example starter script which allows to easily
start all needed components eiterh usinf the ```screen``` tool (default) or
the ```gnome-terminal``` using ```-t```. 
Furthermore the test folders contain an appropriate run/sh script.
All scripts provide a help which will be printed by using the ```-?``` switch.

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
