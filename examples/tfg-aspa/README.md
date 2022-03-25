# BGP-SRx - Test Framework Generator for ASPA #
The basis of this project was started during the IETF 112 Hackathon. Since this time
the codebase is cleaned up and correctly documented.
This framework allows to generate large ASPA experimentations with large datasets.
The ASPA objects are generated using the [CAIDA](https://www.caida.org/catalog/datasets/as-classification)
generated as relationship database. Here only provider - customer tuples are used.
The source for BGP AS path data is RouteViews. This framework allows to easily retrieve
the observed AS path announcements from routers that peer with the collectors. This framework
identifies which collectors do peer with a particular router to collect their announcements.
Then a selected RIB file of each identified collector is downloaded and only the UPDATEs that
were received from the requested AS will be used. Here the first occurrence of the peer will be
removed to allow the BGPsec-IO traffic generator to take on the role of the requested AS.

## Installation ##

The installation requires to retrieve the NIST-BGP-SRx Software Suite V6. BGP-SRx V5 does
NOT provide any ASPA implementation and is therefore not suited. This software packet is
part of the BGP-SRx Software Suite. Please refer to the installation of the BGP-SRx Software
Suite.

## Acquire routing Data from RouteViews ##
To extract RouteViews data use the ```bgpdump``` tool. This tool is essential and on CentOS
builds it can be installed via ```yum```, available using the ```epel``` repository.

Once the software installation was successful the next step is to download and prepare
RouteViews data. All RouteViews related data and scripts are located in the folder
```data-peers```.
This folder contains two major Linux shell scripts:
* ```find-peer.sh```
  This script downloads the latest RouteViews peering status file ```peering-status.html```
  and queries which collector is peering with the AS in question.

* ```get_path_data.sh```
  This script makes usage of ```find-peer.sh``` to determine the proper collectors. Once
  one or more collectors are identified this script will download the MRT RIB data files
  for this current day midnight (00:00) and extracts all AS path information from the
  requested ASN. Note, the script also allows to select different MRT files when provided
  with a valid date and time. Most RIB files are generated in a two-hour interval starting
  at midnight and counting in 24h mode. (e.g. 0000 - 0200 - ... - 1400 - 1500 - ...).
  
  Furthermore, only UPDATE data from the requested AS will be extracted, assuming the AS in question
  does peer with any of the RouteViews Collectors.
  The result outcome is a list of unique AS paths provided by the AS without the AS itself
  (In case the ASN concatenated itself n times, then n-1 occurrences are still in the path).
  Using command line parameters this tool allows to specify a different date and time.

__Note:__ To identify ASes that peer with RouteViews, either use the ```find-peer.sh``` script or
manually parse the peering-status html file.

## Acquire Data from CAIDA and prepare for ASPA usage ##
A second step is to download the CAIDA AS relationship data. The latest data is available
at [CAIDA](https://www.caida.org/catalog/datasets/as-classification)
The CAIDA data file must be saved in the ```data-aspa``` folder. This folder contains a
a Linux shell script as well as a Python script, both format the data into BGP-SRx usable
ASPA input data for the BGP-SRx RPKI Cache Test Harness.

* ```make-ASPA.sh```
  This Linux shell script provides two operation modes. 
  (1) for systems with python3 installed, it functions as wrapper for the ```caida-to-cache.py```
  python script. Once the Python based script generated the data, the shell script cleans up the
  output and removes any duplicate leftovers and empty lines.
  (2) Systems that do not have python3 installed use the shell script itself for translating the
  data from CAIDA to BGP-SRx compatible ASPA data.
  
  By default, this script uses the python wrapper. The reason is performance. The python script is
  multiple magnitudes faster (3-5 seconds vs. ~5 minutes). Nevertheless, some systems do not have
  python3 installed and therefore the shell version does the job as well.
  The shell mode can be forced usig the program parameter ```-s```.

* ```caida-to-cache.py```
  This script requires python3 and will not function properly with earlier versions. It is recommended
  to use this script by calling the ```make-ASPA.sh``` script.

## Preparation of the experimentation ##
Assuming the the AS traffic data and the ASPA data is prepared, the script ```generate-data.sh``` allows
to generate the experimentation. This script allows to prepare full or reduced UPDATE datasets.
The UPDATE traffic generated uses the RouteViews collected BGP AS path, but the prefixes used are synthetic.
The prefixes are /24 and by default start with 0.0.1.0/24 and move up to maximum 255.255.255.0/24.

__Note:__ The script allows to start at a different location, e.g. start prefix ```1 => 0.0.1.0/24, 257 => 0.1.1.0/24```.

To reduce the number of UPDATES being used, the parameter ```-m <max-num-updates>``` allows to down-scale the
size of the experiment. if max-num-updates is larger than the number of available updates than only the
available number of updates is used. In case no max number is provided, all UPDATES are included.

The number of ASPA objects included depend on the number of ASN's used in the traffic. This script identifies
all unique ASNs used in the traffic file and only selects ASPA objects whose customers are part of the set of ASNs
used.

The UPDATE traffic contains the BGP-SRx specific identifier ```B4``` that indicates BGPsec-IO will only generate
BGP-4 UPDATES and not attempt to generate BGPsec UPDATES.

* ```generate-data.sh```
  Requires as input the ```data-peers/<AS>.txt``` and ```data-aspa/CAIDA_Data_ASPA.txt``` files. These files are
  generated with the ```make-ASPA.sh``` and ```get_path_dtaa.sh``` shell scripts.
  
  This script generates three main files:
  * ```<AS>-<UPD_COUNT>-data-updates.bio``` BGPsec-IO traffic file.
  * ```<AS>-<UPD_COUNT>-data-updates.asn``` Contains the unique number of AS numbers used. (Informative only!)
  * ```<AS>-<UPD_COUNT>-data-aspa.cache``` The RPKI Cache Test Harness - ASPA data.
  These files are located in the folder ```data-experiment```.

## Starting an experiment ##
Experiments are identified by their peering AS number and the number of updates. The first steps to run an experiment
are to generate the ASPA and UPDATE data. All is explained in detail in the sections above.
Once the code data is available, an experiment is started using the wrapper sctip ```run.sh```.
This script will call the ```startService.sh``` up to four times by changing the relationship between the Quagga router
and the BGPsec-IO traffic generator.

The BGPsec-IO traffic generator takes on the following roles: provider, customer, sibling, lateral.

__Note:__ Do not infer any statistics from the experiments without prior verification that the ASPA and configured
      relations do make sense.

## Retrieve statistics ###
After an experiment is successfully executed, the script ```./show-statistics.sh``` represents the outcome
in a table form.

__Example:__
```
relation, valid, invalid, unknown, unverifiable
provider, 97, 96, 7, 0
customer, 75, 122, 3, 0
sibling, 97, 96, 7, 0
lateral, 75, 122, 3, 0

relation, valid, invalid, unknown, unverifiable
provider, 48.50%, 48.00%, 3.50%, 0.00%
customer, 37.50%, 61.00%, 1.50%, 0.00%
sibling, 48.50%, 48.00%, 3.50%, 0.00%
lateral, 37.50%, 61.00%, 1.50%, 0.00%
```