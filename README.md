# BGP (S)ecure (R)outing E(x)tension Software Suite

The NIST BGP Secure Routing Extension (NIST-BGP-SRx) is an open-source
reference implementation and research platform for investigating emerging BGP
security extensions and supporting protocols such as RPKI Origin Validation
and BGPsec Path Validation.

Additional information can be found at the [BGP-SRx Software Page](https://www.nist.gov/services-resources/software/bgp-secure-routing-extension-bgp-srx-prototype) and the latest
publication [BGP Secure Routing Extension (BGP-SRx): Reference Implementation and Test Tools for Emerging BGP Security Standards](https://csrc.nist.gov/publications/detail/white-paper/2021/09/15/bgp-secure-routing-extension-bgp-srx/final) based on NIST-BGP-SRx version 5.

Please read the [NIST disclaimer](https://www.nist.gov/director/copyright-fair-use-and-licensing-statements-srd-data-and-software) regarding
the software of this project, the information it provides and the other
resources it uses. Note that these software prototypes are expressly provided
as is and are intended for research and development purposes only.

Additional 3rd party license Information can be found in the
quagga-srx and srx-server codebase in files and folders listed
but not limited to:

* [quagga-srx/COPYING](quagga-srx/COPYING)
* [quagga-srx/COPYING.LIB](quagga-srx/COPYING.LIB)
* [srx-server/extras/README](srx-server/extras/README)
* [srx-server/extras/COPYING](srx-server/extras/COPYING)

## Project Status

The project contains two major versions:

* **version 6** which is the current version providing BGPsec path
validation (BGP-PV), BGP origin validation (BGP-OV) and ASPA validation
(BGP-AV).

* **version 5** only contains BGP-PV and BGP-OV.

Version 6 provides an overhaul of the QuaggaSRx policy processing by
separating BGP-PV and BGP-OV as well as adding ASPA validation (BGP-PV).
This version is the preferred version available in the master branch.

To view a complete list of the NIST BGP-SRx capabilities see the [CAPABILITIES](CAPABILITIES.md) file.

## Branching

The main branch of the repository will deliver NIST-BGP-SRx version 6.
Branch:

* **master**: This branch provides the current recommended version of
            NIST-BGP-SRx (version6.3). This version is updated to be 
            used with Rocky 9 and contains ASPA validation and a 
            complete re-write of the Quagga-SRx policy scripting and 
            processing for BGP-OV, BGP-PV, and BGP-AV. 
            The ASPA implementation in BGP-SRx incorporates the algorithms
            for ASPA-based upstream and downstream AS path verifications.
            It is our understanding that while the style of describing these
            algorithms may have changed, they have remained unchanged in
            their function in draft versions 10 through 18
            (https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-verification-18 ).
            So, our implementation of the algorithms is consistent with draft
            version-18.  Our code includes the basic cases of customer-to-provider,
            lateral peer, and provider-to-customer peering relationships.
            We have not coded the specialized cases such as those involving
            route server (RS), mutual-transit, or complex relations.
* **version5**: This branch stands on its own and is only maintained
            for BUG fixes. New features are added to the master branch
            which is contains NIST-BGP-SRx Version 6.
* **pre-release-6** (*deprecated*): This branch was a "sneak preview"
            of the upcoming version 6 and is not further maintained
            and expected to be removed in the future.

## Testing

The software was continuously tested during development. We performed
interoperability test and published them at IETF SIDR meetings as well as
IETF SIDROPS meetings.
The codebase itself provides a simple testing to test basic functionality.
The development was done using CentOS 7 though we compiled the project on CentOS 8 and successfully executed the test suite provided in this release.

### Unit Test

BGP-SRx consists of four semi-independent components. Semi-independent only
because some components such as the srx-crypto-api and srx-server do provide
API's for other components within the package. The development though is
performed separately.

For this reason, each component will have its own unit tests if at all. These
will if available be located within the appropriate source folder or the newly
added EXAMPLES project which will be installed in ```<install-root>/opt/bgp-srx-examples```.
Please consult the README files located in each component directory for more
information.

### Performance Test

The software was tested throughout the development and multiple publications are
available regarding performance testing. Please visit the [BGP-SRx Software Page](https://www.nist.gov/services-resources/software/bgp-secure-routing-extension-bgp-srx-prototype)
for more information.

## Getting Started

This project archive provides a "buildBGP-SRx.sh" shell script for an easy
sandbox installation. This script allows to have the software installed within
the code folder.

The codebase itself contains multiple components.

These instructions will get you a copy of the project up and running on your
local machine for development and testing purposes.
See Installing for notes on how to deploy the project on a live system.

### Prerequisites

The [CONTENT](CONTENT) file contains the most recent requirements for the
build.

## Building & Installing

Building and installation is explained in detail in the [INSTALL.md](INSTALL.md) file.

This software suite provides the following list of modules:

* **SCA:**       SRx Crypto API (provides cryptographic capabilities)
* **SRxSnP:**    SRx-Server and SRx-Proxy (the validation server and proxy)
* **QSRx:**      Quagga SRx (the routing engine)
* **BIO:**       BGPsec traffic generator and crypto module tester.
* **EXAMPLES:**  Examples, test scripts, and test framework generators (TFG) to test BGP-SRx modules.

Two more implementations are available ExaBGPsec and GoBGPsec. More information on then
can be found in the [CAPABILITIES](CAPABILITIES.md) file.

The newest addition is the Test Framework Generator for ASPA (TFG-ASPA). It is part of the EXAMPLES module. More
information on the TFG-ASPA can be found in the TFGA-ASPA [README.MD](examples/tfg-aspa/README.md) file.

### Required to build SRx Crypto API (SCA)

1) Build SRx Crypto API (srx-crypto-api)

### Required to build SRx-Server (SRxSnP)

1) Build and install SRx Crypto API (srx-crypto-api)
2) Build SRx Server and Proxy (srx-server)

### Required to build BGPsec IO (BIO)

1) Build and install SRx Crypto API (srx-crypto-api)
2) BGPsec-IO (bgpsec-io)

### Required to build Quagga-SRx (QSRx)

1) Build and install SRx Crypto API (srx-crypto-api)
2) Build and install SRx Server and Proxy (srx-server)
3) Quagga SRx (quagga-srx)

### Quick Functional Test / Demo

The BGP-SRx software suite does provide a test system integrated in the build  
script. The script does test proper functionality of the srx-crypto-api as well
as the integration into BGPsec-IO.

Furthermore BGP-SRx provides a complete set of examples, demos which are
in the examples folder but will be compiled for the host system using the
```buildBGP-SRx.sh``` script.
The examples will be installed in the folder ```opt/bgp-srx-examples/``` folder.
Each example does have its own example starter script which allows to easily
start all needed components either using the ```screen``` tool (default) or
the ```gnome-terminal``` using ```-t```.
Furthermore, the test folders contain an appropriate run/sh script.
All scripts provide a help which will be printed by using the ```-?``` switch.

## Building and Installing using Docker

### Docker Requirements

* **Docker Version:**

  Docker Engine - Community version 18 or later is required.

* **Operating Systems:**

  MacOS, Linux, Windows 10 Professional or Enterprise edition
    [Docker Engine](https://docs.docker.com/engine/install/)

* **Docker-compose install links:**

    [Docker Compose](https://docs.docker.com/compose/install/)

### Docker Running Examples

In order to edit QuaggaSRx, SRx Server and RPKI-Rtr server's configuration files
in detail, please refer to each example file within the example directories.

#### *Generate Docker image*

To generate docker image, you need to run 'docker build' command with the
Docker file

```/bin/bash
docker build -f <docker file> -t <docker image name> <path>
```

In our example,

```/bin/.bash
docker build -t nist/bgp-srx .  (Don't forget '.' at the end)
```

* **Staring the RPKI Cache Test Harnes (rpkirtr_svr)**
  
1) Create the configuration file for the RPKI Cache Test Harnes: *rpkirtr_svr.conf*

```/bin/bash
  echo "add 10.0.0.0/8 9 7675" > ./rpkirtr_svr.conf
```

2) Start the docker container for *rpkirtr_svr* instance

```/bin/bash
  docker run --rm -it --name rpkirtr_server \
         -v $PWD/./rpkirtr_svr.conf:/usr/etc/rpkirtr_svr.conf \
         -p 323:323 \
         nist/bgp-srx \
         rpkirtr_svr -f /usr/etc/rpkirtr_svr.conf
```

Or run a *rpkirtr_svr* instance with a pre-defined configuration

```/bin/bash
  docker run --rm -it --name rpkirtr_server \
         -v <location/user-defined/rpkirtr_svr.conf:/usr/etc/rpkirtr_svr.conf \
         -p 323:323 \
         nist/bgp-srx \
         rpkirtr_svr -f /usr/etc/rpkirtr_svr.conf
```

* **Starting the SRx Server**

1) Identify the IP address of the RPKI Cache Test Harness *rpkirtr_svr*

```/bin/bash
  docker inspect --format '{{ .NetworkSettings.IPAddress }}' <container name>
```

Here:

```/bin/bash
  docker inspect --format '{{ .NetworkSettings.IPAddress }}' rpkirtr_server

  Example Result: 172.17.0.2
```

Using the retrieved IP address, configure the SRx Server instance to point ot the RPKI Cache Test Harness. Here replace 172.17.0.2 with the IP address retrieved prior.

```/bin/bash
  sed "s/localhost/172.17.0.2/g" ./srx-server/src/server/srx_server.conf > /tmp/srx_server.conf
```

Now start the SRx Server *srx_server* docker container.

```/bin/bash
  docker run --rm -it --name srx_server \
         -v /tmp/srx_server.conf:/usr/etc/srx_server.conf \
         -v $PWD/./examples/bgpsec-keys/:/usr/opt/bgp-srx-examples/bgpsec-keys \
         -p 17900:17900 -p 17901:17901 \
         nist/bgp-srx \
         srx_server -f /usr/etc/srx_server.conf
```

Or use our pre-defined keys and config files in the example directories

```/bin/bash
  docker run --rm -it --name srx_server \
         -v </location/user-defined/srx_server.config>:/usr/etc/srx_server.conf  \
         -v </location/user-defined/keys/>:/usr/opt/bgp-srx-examples/bgpsec-keys \
         -p 17900:17900 -p 17901:17901 \
         nist/bgp-srx \
         srx_server -f /usr/etc/srx_server.conf
```

* **Starting QuaggaSrx**

First gather the IP address for the SRx Server instance as described earlier and add modify the quagga configuration.

```/bin/bash
docker inspect --format '{{ .NetworkSettings.IPAddress }}' srx_server

Example result: 172.17.0.3
```

Use the learned IP address and update the QuaggaSRx configuration

```/bin/bash
sed "s/srx connect/srx connect 172.17.0.3 17900/g" ./quagga-srx/bgpd/bgpd.conf.sampleSRx > /tmp/bgpd.conf
```

Finally start the QuaggaSRx server

```/bin/bash
  docker run --rm -it --name quaggasrx \
         -v /tmp/bgpd.conf:/usr/etc/bgpd.conf \
         -v $PWD/./examples/bgpsec-keys/:/usr/opt/bgp-srx-examples/bgpsec-keys \
         -p 179:179 -p 2605:2605 \
         nist/bgp-srx \
         bgpd -f /usr/etc/bgpd.conf
```

Or use pre-defined keys and config files in our example directories

```/bin/bash
  docker run --rm -it --name quaggasrx \
         -v </location/user-defined/quagga.config>:/usr/etc/bgpd.conf  \
         -v </location/user-defined/keys/>:/usr/opt/bgp-srx-examples/bgpsec-keys \
         -p 179:179 -p 2605:2605 \
         nist/bgp-srx \
         bgpd -f /usr/etc/bgpd.conf  
```

* **Docker compose**

[Docker Compose](https://docs.docker.com/compose/) allows to  define and run multi-container Docker applications.
With Compose, you use a YAML file to configure your application’s services.
Then, with a single command, you create and start all the services from your configuration.

The following command will execute all three docker containers in the docker-compose.yml file.

```/bin/bash
docker-compose up
```

To stop and remove containers, simply **Ctrl-C** twice or

```/bin/bash
docker-compose down
```

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute
to the projects.

## Authors & Main Contributors

### Developer

* Oliver Borchert (Lead)

* Kyehwan Lee

### System Design

* Oliver Borchert
* Kyehwan Lee
* Sriram Kotikalapudi
* Doug Montgomery

### Previous Developer

* Patrick Gleichmann

## Copyright

For license information see the [LICENSE](LICENSE) file.

## Contacts

For information, questions, or comments, contact by sending
an email to itrg-contact@list.nist.gov
