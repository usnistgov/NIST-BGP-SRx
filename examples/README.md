NIST BGP-SRx Examples
=====================

This project contains contains multiple examples to illustrate how
to configure each module of the BGP-SRx Software Framework.
The framework consists of 4 main software modules and one additional
test harness.

To keep the examples and configuration files simple, most documentation is
removed from the example configuration files. To see the complete 
documentation and features provided within each software module, see the 
proper sample configuration that is installed either in the 'etc', 'bin', 
or 'sbin' folder.

This Project provides next to the examples a demo key vault. This key vault 
provides BGPsec router keys in regular generated certificates. They do not 
adhere to RFC8608 and do NOT expire. This key vault was previously part of 
the BGPsec-IO code base.

The examples are split into four main sections:

1)  Integrated Demonstration Examples

    **demo-\<type\>**

    This examples show how to configure complete topologies and perform 
    different validations and pre-determined traffic. 
    These examples come with a starter script to provide a more plug and 
    play experience.

2)  Component Configuration Examples

    **config-\<component\>**

    This examples are used to demonstrate quick and simple component 
    configurations. They can be considered Quick start guides.

3)  Component Test Examples

    **test-\<component\>**

    These examples replace the previously used test script. These test 
    are very simple function tests to verify that the installation works 
    properly.

4)  Custom Examples

    This folder contains custom generated examples. Most likely buy you in
    case you want to build your own examples.

Template Configuration:
=======================

Templates are used to generate system specific ```.conf``` files that require
configuration parameters, mainly IP addresses. Within a template file the 
following parameter is supported:

* {IP_AS_number} - Part of template files

  With ```number``` being the AS number the IP address has to be set for. The
  IP address will be collected from the IP-Address.cfg file. This file is the
  only file that needs to be configured for all examples to properly function.

  A template file must have the extension ```.tpl``` and all references to 
  ```{IP_AS_XYZ}``` will be replaced with the IP address found in the project
  file IP-Address.cfg

* IP-Address.cfg - Main configuration file.

  This file is used to configure all IP assignments within the experiment 
  folders.
  This file not only provides theIP mapping, it specifies also which example test 
  and other folders in general do need to be configured.

* \<ip-address-#\> - Part of IP-Address.cfg

  IP addresses are assigned to AS numbers. The # in the tag must be a continuous number.

  Example: \<ip-address-1\> \<ip-address-2\> ... \<ip-address-n\>
  They are used in combination with AS numbers.

  Example: :65500:\<ip-address-1\>

  In addition to the ASN-IP mapping this can be done for the global space and/or experiment space
  
  * Global

    :ASN:\<ip-address-#\>

  * Experiment Specific

    experiment-1:ASN:\<ip-address-#\>
  
  IP Network configuration:
  =========================
  
  Currently the experiments use a total of 3 different IP addresses. The total number can 
  be found by looking into the file IP-Address.cfg. In case all experiments are started 
  on the same system, either 3 network cards are needed or network aliases need to be configured.
  The internet provides plenty of examples on how to configure multiple IP addresses on a single 
  network interface. ```ifconfig eth0:0 <IP-ADDRESS> up``` does temporarily add an alias but only 
  until the next reboot. 
  For a more persistent solution configuration files are needed. But as mentioned above, the internet 
  has plenty of examples on how to configure this.

  With the latest update the configuration script received 3 more settings: 
  * '-I' : Automatically add unused IP addresses to the system interfaces.
  * '-A' : Reinstall the alias configurations after system reboot.
  * '-RA': Uninstall the added alias configurations. (Only if they match the installed ones.)
  The alias configuration is added to the IP-Address.cfg configuration file during alias configurations.

  IMPORTANT: 
  ==========
  Before adding additional IP addresses to the system, consult with your organizations network engineers to enquire which IP addresses can safely be used without disrupting any network operations.

  IP Network configuration for multiple systems:
  ==============================================
  In case the framework is installed over multiple systems, the configuration cannot be done
  fully automated. Here prior calling ./configure.sh the file IP-Address.cfg needs to be
  modified on each system manually.
