# NIST BGP-SRx Software Suite #

## Introduction ##
>
>The NIST (S)ecure (R)outing E(x)tension (SRx) provides a set of tools for BGP-Security. The Software Suite contains five major components:
>
>1. SRx-Crypto-API
>2. SRx-Server and Proxy
>3. BGPsec-IO Traffic Generator and BGPsec validation tester
>4. QuaggaSRx
>5. Experimentation Framework
>
>The details of the components 1 - 4 can be found int the NIST Technical Note [TN-2060](https://www.nist.gov/publications/bgp-secure-routing-extension-bgp-srx-reference-implementation-and-test-tools-emerging). This document functions as a quick overview of the capabilities and features of the NIST BGP-SRx Software Suite.

## Overall Capabilities ##
>
>* Perform BGP Origin Validation (BGP-OV) (RFC 6811):
>   * Using SRx-Server validation engine decoupled from router.
>* Perform BGPsec Path Validation (RFC 8205):
>   * Using SRx-Server validation engine decouples from router.
>   * Allow validation using crypto API within router implementation.
>* BGP-OV validation state signaling (RFC 8097)
>* Extended Quagga BGP routing engine to be BGPsec capable
>   * Added BGPsec path processing (RFC 8205)
>   * Policies for route validation in router
>     * Modify the routers local preference
>     * Set ignore policies
>   * Extended CLI to configure and monitor BGP-OV, BGP-PV and ASPA validation.
>* Perform ASPA Path Validation (version 6+)
>* SRx-Server allows to provide validation to multiple clients
>   * Assures same validation results throughout all connected router clients
>* Create end to end signed BGPsec UPDATES (RFC 8205, RFC 8608)
>* Emulate an RPKI validation server
>   * Propagate ROAs (RFC 6810)
>   * BGPsec Keys (RFC 8210)
>   * ASPA Objects (draft-ietf-sidrops-8210bis) (NIST BGP-SRx Version 6+)
>   * Allow time-based scenario scripting of when data will be pushed to client.
>   * CLI to control emulator in real time.
>* Allow configuration of BGPsec validation algorithm using API plugin mechanism.
>   * Use alternative BGPsec cryptographic implementations.
>* BGP/BGPsec Traffic generator
>   * Allow to script BGP-4 and BGPsec UPDATES.
>   * Provide debug printer to analyze BGP/BGPsec traffic on sender and receiver side.
>   * Provide capability of deterministic ECDSA signatures using specified k-value.
>   * Provide capability to use pre-scripted signature value to test validation algorithm.
>   * Allow traffic generator to function as traffic monitor.
> * Allow to bind BGP UPDATE player to specific NIC to allow multiple traffic generators to operate on the same system

## Module Description ##
>
>### SRx Crypto API ###
>
>The SRx Crypto API (SCA) is used to provide a mechanism to exchange BGPsec cryptographic implementations without the need to recompile the software. Once installed, it provides a configuration file that is used to select the appropriate BGPsec algorithm implementation. The implementation MUST follow the SCA's API specification outlined in the header file srxcryptoapi.h.
>
>Furthermore, SCA provides a simplified key storage that allows to load keys on the hard drive for easy access.
>
>### SRx-Server ###
>
>The SRx-Server (SRxSnP) provides the validation engine for BGPsec Path Validation, BGP Route Origin Validation, and introduced in version 6 of the software also ASPA path validation. The SRx-Server communicates with RPKI validation caches using the cache to router protocol RFC 8210 and 8610. For communication with routers the SRx-Server implementation provides a proxy API that hides the communication complexities to the client. In case the router does not want to use the proxy, the SRx-Server provides a TCP based protocol to communicate validation requests and validations.
>
>#### Utilities ####
>
>> This package provides a validation server test harness that emulates a Resource PKI (RPKI) validation cache that is providing Route Attestation Objects (ROA), BGPsec keys, and with NIST BGP-SRx version 6 also ASPA Objects to be send to the routers. This emulator can be controlled using scripts.

### BGPsec-IO ###

>The BGPsec-IO (BIO) is a traffic generator that allows to generate regular BGP-4 UPDATES as well as scripted multi-hop end to end signed BGPsec UPDATE traffic. It can pre-generate traffic to be re-played at a later time as well as generate traffic while receiving ASCII text-based UPDATE (prefix-as-path list) via standard in and send it to a connected BGP/BGPsec router instance.
>
>### Quagga-SRx ###
>
> The Quagga-SRx (QSRx) implementation is based on Quagga 0.99. It implements the capability to process BGP Origin Validation, BGP Path Validation, as well as with version 6.0 ASPA path validation.
>
>#### Version 5 ####
>
>>This implementation modified the decision process of the BGP routing engine. It allows to either perform BGP Origin Validation (BGP-OV) or both BGP-OV combined with BGPsec Path Validation (BGP-PV). Therefore, the policies are tailored to a final validation outcome.
>
>#### Version 6 ####
>>
>> Version 6 does not touch the decision process anymore. Also, the validation results are no longer combined to calculate a cumulative result. Policies can be crafted around each validation separately.
>
>### Experiments ###
>
>The experiments folder contains experimentation for each validation mode and one combining all tree modes. Each experiment can be run in a "Sandbox" environment.
