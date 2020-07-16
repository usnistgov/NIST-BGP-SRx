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

For required libraries please check the [CONTENT](CONTENT) file.

### Building & Installing

The CONTENT file does specify what libraries are required to be 
installed for a successful installation. This is based upon a 
fresh CENTOS 7 install. Other distributions might require additional
packages. 

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

**SCA:**     SRx Crypto API

**SRxSnP:**  SRx-Server and SRx-Proxy

**QSRx:**    Quagga SRx

**BIO:**     BGPsec traffic generator and crypto module tester.

### Manual Building

For manual installation, each component's separate source folder contains the 
appropriate README and INSTALL files. They contain all necessary information. 
It is important to note that building the components requires to keep a certain order.
It is also possible to manually call the auto build script for each component
individually.

To rebuild the configuration scripts call *autoreconf -i --force*. For that the autoconfig tools
are required.

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


### Quick Functional Test / Demo

The BGP-SRx software suite does provide a simple system test in form of a test 
script. The script does test proper functionality of the srx-crypto-api as well 
as the integration into BGPsec-IO.

Furthermore the script creates QuaggaSRx configuration scripts that can be used
to test QuaggaSRx together with BGPsec-IO

```
./testBGP-SRx.sh
```

### Unit Test

BGP-SRx consists of fours semi-independent components. Semi-independent only
because some components such as the srx-crypto-api and srx-server do provide
API's for other components within the package. The development though is 
performed separately. 

For this reason each component will have its own unit tests if at all. These
will if available be located within the appropriate source folder. Please
consult the README files located in each component directory for more information.

### Performance Test

The software was tested throughout the development and multiple publications are
available regarding performance testing. Please visit the 
[NIST BGP-SRx project page](https://bgp-srx.antd.nist.gov) for more information.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) sfor details on how to contribute
to the projects.

## Authors & Main Contributors

### Developer

Oliver Borchert (Lead)
Kyehwan Lee

### Previous Developer

Patrick Gleichmann

## Related Work

Note: Optional - if there are related works or background reading
Add links to any papers or publications here if appropriate. 

## Copyright

For license information see the [LICENSE](LICENSE) file. 

## Contacts

Please send an email to bgpsrx-dev@nist.gov for more information on the project.
