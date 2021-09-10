/**
 * This software was developed at the National Institute of Standards and
 * Technology by employees of the Federal Government in the course of
 * their official duties. Pursuant to title 17 Section 105 of the United
 * States Code this software is not subject to copyright protection and
 * is in the public domain.
 *
 * NIST assumes no responsibility whatsoever for its use by other parties,
 * and makes no guarantees, expressed or implied, about its quality,
 * reliability, or any other characteristic.
 *
 * We would appreciate acknowledgment if the software is used.
 *
 * NIST ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" CONDITION AND
 * DISCLAIM ANY LIABILITY OF ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING
 * FROM THE USE OF THIS SOFTWARE.
 *
 *
 * This software might use libraries that are under GNU public license or
 * other licenses. Please refer to the licenses of all libraries required
 * by this software.
 *
 * This header file contains data structures needed for the application.
 * 
 * @version 0.2.1.7
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.1.7 - 2021/07/12 - oborchert
 *            * Added P_TYPE_NSM_BGP_4="BGP-4" as inofficial alternative to 
 *              setting "BGP4"
 *  0.2.1.5 - 2021/05/10 - oborchert
 *            * Updated changes from 0.2.1.3 to point into /opt/bgp-srx-examples
 *            * Modified SRX_DEV_TOYEAR to reflect 2021
 *  0.2.1.3 - 2021/03/26 - oborchert
 *            * Changed DEF_KEYLOCATION and DEF_SKIFILE from /var/lib/key-volt 
 *              to /var/lib/key-vault 
 *  0.2.1.1 - 2020/07/29 - oborchert
 *            * Fixed speller in documentation
 *            * Added define for development year (SRX_DEV_TOYEAR).
 *  0.2.1.0 - 2018/01/16 - oborchert
 *            * Added DEF_PACKING and deprecated useMPNLRI attribute.
 *          - 2018/01/12 - oborchert
 *            * Further split updates into now two stacks, one for updates 
 *              passed as program parameter and one for global configuration.
 *          - 2018/01/10 - oborchert
 *            * Added some DO DO statements.
 *          - 2017/12/22 - oborchert
 *            * Added more error handling in session configuration.
 *          - 2017/12/20 - oborchert
 *            * Added processing of multi sessions.
 *          - 2017/12/14 - oborchert
 *            * Added template for RPKI cache integration.
 *              - Added required structure RPKI_Cache
 *          - 2017/12/13 - oborchert
 *            * Added -n for network interface and added variable iface to 
 *              struct PrgParams
 *          - 2017/12/11 - oborchert
 *            * Fixed parameter assignment to -y as specified in-line docu
 *              for capi configuration. Was previously -p in the define
 *          - 2017/12/05 - oborchert
 *            * Replaced interface binding with outgoing IP address binding.
 *              (does not require elevated privileges - better solution)
 *            * Added capability to use an update as BGP-4 only
 *          - 2017/11/12 - oborchert
 *            * Added configuration for interface binding
 *  0.2.0.21 -2018/06/08 - oborchert
 *            * MERGED from branch 0.2.0.x
              * Added P..._CONVERGENCE parameters.
 *  0.2.0.21 -2018/06/08 - oborchert
 *            * Added P..._CONVERGENCE parameters.
 *  0.2.0.17 -2018/04/26 - oborchert
 *            * Added UPD_AS_SET_OPEN and UPD_AS_SET_CLOSE
 *  0.2.0.14 -2018/04/19 - oborchert
 *            * Added 'validation' to update structure.
 *  0.2.0.12 -2018/04/14 - oborchert
 *            * Added switch 'printSimple' to update printer. 
 *  0.2.0.11- 2018/03/22 - oborchert
 *            * Added configuration P_CFG_CAP_AS4
 *          - 2018/03/21 - oborchert
 *            * Added switch to disable global updates for a session.
 *            * Added define DEF_INCL_GLOBAL_UPDATE
 *  0.2.0.7 - 2017/05/03 - oborchert
 *            * Moved include of config.h into this  file rather then 
 *              configuration.c.
 *          - 2017/03/15 - oborchert
 *            * Changed values of print filter defines.
 *          - 2017/03/10 - oborchert
 *            * Added print filter
 *          - 2017/02/14 - oborchert (branch 2017/02/07) 
 *            * Added missing configuration for IPv6 next hop.
 *            * Added alternative configuration for IPv4 next hop.
 *  0.2.0.6 - 2017/02/15 - oborchert
 *            * Added switch to force sending extended messages regardless if
 *              capability is negotiated. This is a TEST setting only.
 *          - 2017/02/14 - oborchert
 *            * Added missing include config.h
 *          - 2017/02/13 - oborchert
 *            * Renamed define from ..._EXTMSG_SIZE to EXT_MSG_CAP
 *            * BZ1111: Added liberal policy to extended message capability 
 *              processing
 *  0.2.0.5 - 2017/01/31 - oborchert
 *            * Added configuration setting to enable/disable extended message 
 *              size capability // draft-ietf-idr-bgp-extended-messages
 *            * Added configuration to selectively enable/disable V4 and V6 
 *              support for BGPSEC
 *          - 2016/11/15 - oborchert
 *            * Added parameter P_CFG_ONLY_EXTENDED_LENGTH
 *          - 2016/10/21 - oborchert
 *            * Fixed issue with 32/64 bit libconfig integer type BZ1033 - added
 *              define LCONFIG_INT.
 *          - 2016/10/19 - oborchert
 *            * Fixed errors in documentation.
 *  0.2.0.0 - 2016/05/13 - oborchert
 *            * Added maximum update processing BZ:961
 *          - 2016/05/10 - oborchert
 *            * Changed parameter -c to -f to be same as for the other programs
 *          - 2016/05/06 - oborchert
 *            * Added parameter srxCryptoAPICfg to PrgParams and corresponding
 *              configuration settings.*          
 *  0.1.1.0 - 2016/05/03 - oborchert
 *            * Added functionality to append to an outfile.
 *          - 2016/04/18 - oborchert
 *            * Added configuration for fallback methods in case the signature
 *              could not be generated.
 *            * Split GEN into GEN-B and GEN-C for CAPI data generation and BGP
 *              data generation.
 *          - 2016/03/17 - oborchert
 *            * Added print configurations for debugging. 
 *  0.1.0.0 - 2015/08/26 - oborchert
 *            * Created File.
 */
#ifndef CONFIGURATION_H
#define	CONFIGURATION_H

#include <stdbool.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "antd-util/stack.h"
#include "bgpsec/BGPSecPathBin.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#define PRG_NAME    PACKAGE
#define PRG_VERSION "V" VERSION
#else
#define PRG_NAME    "bgpsecio"
#define PRG_VERSION ""
#endif

// CONFIG_INT will be set to int for 64 bit platform during configure. See
// configuration.ac - used for libconfig 
#ifndef LCONFIG_INT
#define LCONFIG_INT long
#endif

// Can be overwritten in configure.ac if needed.
#ifndef SRX_DEV_TOYEAR
#define SRX_DEV_TOYEAR "2021"
#endif

/******************************************************************************/
/***  Defines for default BGP session configuration  **************************/
/******************************************************************************/
// The default location where to find the keys
#define DEF_KEYLOCATION        "/opt/bgp-srx-examples/bgpsec-keys/\0"
// The default file containing the list of public keys
#define DEF_SKIFILE            "/opt/bgp-srx-examples/bgpsec-keys/ski-list.txt\0"
// The default port of the peer
#define DEF_PEER_PORT          179
// The default BGP hold time
#define DEF_HOLD_TIME          180
// The time (0=infinite) the BGP session stays up after the last update is sent
#define DEF_DISCONNECT_TIME    0
// The default algorithm ID used.
#define DEF_ALGO_ID            1
// The default value for including global updates
#define DEF_INCL_GLOBAL_UPDATE true
// The default IPv4 to IPv6 PREFIX
#define DEF_V4_V6_PREFIX       "0:0:0:0:0:ffff:"
// The default IPv4 next hop and local address
#define DEF_IPV4               "10.0.1.64"
// The default IPv4 peer IP address
#define DEF_PEER_IP            "10.0.1.32"
// The default local ASN
#define DEF_LOCAL_ASN          64
// The default peer ASN
#define DEF_PEER_ASN           32
// The default print setting
#define DEF_PRINT              false
// The default setting for encoding IPv4 updates in MP_NLRI format.
#define DEF_MPNLRI_V4          true
// The default setting for BGP-4 UPDATE prefix packing
#define DEF_PACKING            false;

/******************************************************************************/
/***  Other defaults **********************************************************/
/******************************************************************************/
// Operational type
#define P_TYPE_BGP  "BGP"
#define P_TYPE_CAPI "CAPI"
#define P_TYPE_GENB "GEN-B"
#define P_TYPE_GENC "GEN-C"

// Specification for null signature mode.
/* Drop the update. */
#define P_TYPE_NSM_DROP "DROP" 
/* Use the fake signature. */
#define P_TYPE_NSM_FAKE "FAKE" 
/* Use BGP-4 attribute instead of BGPSec*/
#define P_TYPE_NSM_BGP4  "BGP4"
/** Inofficial alternative to "BGP4" 
 * @since 2.1.7 */
#define P_TYPE_NSM_BGP_4 "BGP-4"

// Specification for signature mode
#define P_TYPE_SIGMODE_CAPI   "CAPI"
#define P_TYPE_SIGMODE_BIO    "BIO"
#define P_TYPE_SIGMODE_BIO_K1 "BIO-K1"
#define P_TYPE_SIGMODE_BIO_K2 "BIO-K2"

// -?                   -help screen
#define P_HELP          "--help"
#define P_C_HELP        '?'
#define P_C_HELP_1      'h'
#define P_C_HELP_2      'H'

// Display the version number
#define P_VERSION       "--version"
#define P_C_VERSION     'V'

// for the configuration file
#define P_CFG_SESSION   "session"

// update="<prefix>,<path>"   - Can be used multiple times
#define P_CFG_UPD_PARAM "update"
// --update "<prefix>,<path>"   - Can be used multiple times
#define P_UPD_PARAM     "--" P_CFG_UPD_PARAM
// -u "<prefix>,<path>"   - Can be used multiple times
#define P_C_UPD_PARAM   'u'

// ski_file="<filename>"  - The SKI filename (/var/lib/bgpsec/ski-list.txt)
#define P_CFG_SKI_FILE  "ski_file"
// --ski_file <filename>  - The SKI filename (/var/lib/bgpsec/ski-list.txt)
#define P_SKI_FILE      "--" P_CFG_SKI_FILE
// -s <filename>  - The SKI filename (/var/lib/bgpsec/ski-list.txt)
#define P_C_SKI_FILE    's'

// ski_key_loc="<directory>"  - The SKI key locations (/var/lib/bgpsec)
#define P_CFG_SKI_LOC   "ski_key_loc"
// --lski_key_loc <directory> - The SKI key locations (/var/lib/bgpsec)
#define P_SKI_LOC       "--" P_CFG_SKI_LOC
// -l <directory> - The SKI key locations (/var/lib/bgpsec)
#define P_C_SKI_LOC     'l'

// mode="BGP|CAPI|GEN" - The type, BGP, CAPI, or GEN
#define P_CFG_TYPE      "mode"
// --mode <BGP|CAPI|GEN> - The type, BGP, CAPI, or GEN
#define P_TYPE          "--" P_CFG_TYPE
// -m <BGP|CAPI|GEN>" - The type, BGP, CAPI, or GEN
#define P_C_TYPE        'm'

// signature_generation="CAPI|BIO|BIO-K1|BIO-K2" - The signature generation mode.
#define P_CFG_SIG_GENERATION   "signature_generation"

// max=<number> - the maximum number of updates to be processed.
#define P_CFG_MAX_UPD   "max"
// --max=<number> - the maximum number of updates to be processed.
#define P_MAX_UPD       "--" P_CFG_MAX_UPD
// -U <number> - the maximum number of updates to be processed.
#define P_C_MAX_UPD     'U'

// The following only if BGP is selected.
// asn=<asn> - The ASN of the player
#define P_CFG_MY_ASN    "asn"
// --asn <asn> - The ASN of the player
#define P_MY_ASN        "--" P_CFG_MY_ASN
// -a <asn> - The ASN of the player
#define P_C_MY_ASN      'a'

// bgp_ident="<IPv4 address>" - My BGP Identifier
#define P_CFG_BGP_IDENT "bgp_ident"
// --bgp_ident <IPv4 address> - My BGP Identifier
#define P_BGP_IDENT     "--" P_CFG_BGP_IDENT
// -i <IPv4 address> - My BGP Identifier
#define P_C_BGP_IDENT   'i'

// next_hop_ipv4="<IPv4 address>" - Alternative IPv4 next hop address
#define P_CFG_NEXT_HOP_IPV4 "next_hop_ipv4"
// --next_hop_ipv4 <IPv4 address> - IPv6 next hop address
#define P_NEXT_HOP_IPV4     "--" P_CFG_NEXT_HOP_IPV4
// -4 <IPv4 address> - IPv6 next hop address
#define P_C_NEXT_HOP_IPV4   '4'

// next_hop_ipv6="<IPv6 address>" - IPv6 next hop address
#define P_CFG_NEXT_HOP_IPV6 "next_hop_ipv6"
// --next_hop_ipv6 <IPv6 address> - IPv6 next hop address
#define P_NEXT_HOP_IPV6     "--"
// -6 <IPv6 address> - IPv6 next hop address
#define P_C_NEXT_HOP_IPV6   '6'

// The interface specification - Only in combination with -C
#define P_C_IFACE           'n'

// The local IP address used for this session (only configuration and optional)
// local_addr=<local IP Address>
#define P_CFG_LOCAL_ADDR     "local_addr"

// hold_timer=<time_in_seconds>   - The requested BGP hold time
#define P_CFG_HOLD_TIME "hold_timer"
// --hold_timer=<time_in_seconds> - The requested BGP hold time
#define P_HOLD_TIME     "--" P_CFG_HOLD_TIME
// -t <time_in_seconds> - The requested BGP hold time
#define P_C_HOLD_TIME   't'

// peer_asn=<asn> - The peer ASN
#define P_CFG_PEER_AS   "peer_asn"
// --peer_asn <asn> - The peer ASN
#define P_PEER_AS       "--" P_CFG_PEER_AS
// -A <asn> - The peer ASN
#define P_C_PEER_AS     'A'

// peer_ip="<ip>" - The Peer IP address
#define P_CFG_PEER_IP   "peer_ip"
// --peer_ip <ip> - The Peer IP address
#define P_PEER_IP       "--" P_CFG_PEER_IP
// -I <ip> - The Peer IP address
#define P_C_PEER_IP     'I'

// peer_port=<int> - The peer port (Default 179)
#define P_CFG_PEER_PORT "peer_port"
// --peer_port <int>  - The peer port (Default 179)
#define P_PEER_PORT     "--" P_CFG_PEER_PORT
// -P <int>  - The peer port
#define P_C_PEER_PORT   'P'

// config="filename" - Allows a configuration file.
#define P_CFG_CONFIG    "config"
// --config <filename> - Allows a configuration file.
#define P_CONFIG        "--" P_CFG_CONFIG
// -f <filename> - Allows a configuration file.
#define P_C_CONFIG      'f'

// capi_cfg="filename" - Allows to specify a custom SRxCryptoAPI config file
#define P_CFG_CAPI_CFG  "capi_cfg"
// --capi_cfg <filename> - Allows to specify a custom SRxCryptoAPI config file
#define P_CAPI_CFG      "--" P_CFG_CAPI_CFG
// -y <filename> - Allows to specify a custom SRxCryptoAPI config file
#define P_C_CAPI_CFG    'y'

// encodeMPNLRI="true|false" - enable / disable MPNLRI IPv4 (default enabled)
// DEPRECATED ATTRIBUTE
#define  P_CFG_MPNLRI   "encodeMPNLRI"
// --no_mpnlri         - do not use MPNLRI encoding for IPv4
#define  P_NO_MPNLRI    "--no_mpnlri"
// -M                  - do not use MPNLRI encoding for IPv4
#define  P_C_NO_MPNLRI  'M'

// Allow printing convergence time during keepalive
#define  P_CFG_CONVERGENCE   "convergence"
// --convergence       - enable printing out of convergence time
#define  P_CONVERGENCE       "--" P_CFG_CONVERGENCE
// --T                 - enable printing out of convergence time
#define  P_C_CONVERGENCE     'T'

// ext_msg_cap="true|false" - enable / disable the extended message size 
//                                    capability (default enabled)
#define  P_CFG_EXT_MSG_CAP   "ext_msg_cap"
// --no_ext_msg_cap         - do not use extended message size capability
#define  P_NO_EXT_MSG_CAP    "--no_" P_CFG_EXT_MSG_CAP
// -e                        - do not use extended message size capability
#define  P_C_NO_EXT_MSG_CAP  'e'

// ext_msg_liberal="true|false" - enable / disable liberal processing of 
//                                extended message capability
#define P_CFG_EXT_MSG_LIBERAL "ext_msg_liberal"
// --ext_msg_liberal
#define P_NO_EXT_MSG_LIBERAL  "--no_" P_CFG_EXT_MSG_LIBERAL
// -:
#define P_C_NO_EXT_MSG_LIBERAL   'L'

// --ext_msg_force (For debugging peer only!!)
#define P_CFG_EXT_MSG_FORCE  "ext_msg_force"
// --ext_msg_force (For debugging peer only!!)
#define P_EXT_MSG_FORCE      "--" P_CFG_EXT_MSG_FORCE

// preload_eckey="true|false" - enable / disable the pre-computation of EC_KEY
//                                                           (default enabled)
#define P_CFG_PL_ECKEY  "preload_eckey"
// --no_precomp_eckey  - do not pre-compute the EC_KEY
#define P_NO_PL_ECKEY   "--no_" P_CFG_PL_ECKEY
// -E                  - do not pre-compute the EC_KEY
#define P_C_NO_PL_ECKEY 'E'

// out="filename" - The outfile name.
#define P_CFG_OUTFILE "out"
// --out <filename> - The outfile name.
#define P_OUTFILE     "--" P_CFG_OUTFILE
// -o <filename> - The outfile name.
#define P_C_OUTFILE   'o'

// appendOut - Append to an existing out file.
#define P_CFG_APPEND_OUT "appendOut"
// --appendOut - Append to an existing out file.
#define P_APPEND_OUT     "--" P_CFG_APPEND_OUT
// -O - Append to an existing out file - "NOT ZERO".
#define P_C_APPEND_OUT   'O'

// bin="filename" - Pre-calculated data in binary format stored in a file.
#define P_CFG_BINFILE "bin"
// --bin <filename> - Pre-calculated data in binary format stored in a file.
#define P_BINFILE     "--" P_CFG_BINFILE
// -b <filename> - Pre-calculated data in binary format stored in a file.
#define P_C_BINFILE   'b'

// disconnect=<int> - disconnect time in seconds after the last update sent
#define P_CFG_DISCONNECT_TIME "disconnect"
// --disconnect <int> - disconnect time in seconds after the last update sent
#define P_DISCONNECT_TIME     "--" P_CFG_DISCONNECT_TIME
// -d <int> - disconnect time in seconds after the last update sent
#define P_C_DISCONNECT_TIME   'd'


// Only command line parameter
// -C <config-file> - Generate a config file.
#define P_C_CREATE_CFG_FILE   'C'

// Only configuration parameter - all part of session

// prefixPacking
#define P_CFG_PACKING               "prefixPacking"

// print bgp packages on receive
#define P_CFG_PRINT_ON_RECEIVE      "printOnReceive"
// print bgp packages on send
#define P_CFG_PRINT_ON_SEND         "printOnSend"
// define if messages are printed simple (one liner) or in wireshark format.
#define P_CFG_PRINT_SIMPLE          "printSimple"
// print the poll loop for the session
#define P_CFG_PRINT_POLL_LOOP       "printPollLoop"
// print the status information on invalid - CAPI mode"
#define P_CFG_PRINT_CAPI_ON_INVALID "printOnInvalid"

// algorithmID
#define P_CFG_ALGO_ID              "algo_id" 
#define P_CFG_ALGO_ID_DEF_VAL      1
// allow fake signatures
#define P_CFG_NULL_SIGNATURE_MODE  "null_signature_mode"
// fake signature
#define P_CFG_FAKE_SIGNATURE       "fake_signature"
// fake ski
#define P_CFG_FAKE_SKI             "fake_ski"

// Add Global updates to sessions.
#define P_CFG_INCL_GLOBAL_UPDATES  "incl_global_updates"

// Enable/Disable own capability of AS4 as numbers
#define P_CFG_CAP_AS4              "cap_as4"

// Force generation of one byte BGPSEC Path Attribute length field if attribute
// length is less than 255 byte.
#define P_CFG_ONLY_EXTENDED_LENGTH "only_extended_length"

// Enable and disable BGPSEC IPv4 Receive
#define P_CFG_BGPSEC_V4_R          "bgpsec_v4_rcv"
// Enable and disable BGPSEC IPv4 Send
#define P_CFG_BGPSEC_V4_S          "bgpsec_v4_snd"
// Enable and disable BGPSEC IPv6 Receive
#define P_CFG_BGPSEC_V6_R          "bgpsec_v6_rcv"
// Enable and disable BGPSEC IPv6 Send
#define P_CFG_BGPSEC_V6_S          "bgpsec_v6_snd"

// Enable / disable printing of OPEN message
#define P_CFG_PRNFLTR_OPEN         "open"
// Enable / disable (true|simple|false) printing of UPDATE message
#define P_CFG_PRNFLTR_UPDATE       "update"
// Enable / disable printing of NOTIFICATION message
#define P_CFG_PRNFLTR_NOTIFICATION "notification"
// Enable / disable printing of KEEPALIVE message
#define P_CFG_PRNFLTR_KEEPALIVE    "keepalive"
// Enable / disable printing of unknown (future) message
#define P_CFG_PRNFLTR_UNKNOWN      "unknown"

// Max size for the error message buffer
#define PARAM_ERRBUF_SIZE 255
// Max size for file names 
#define FNAME_SIZE        255
// MAX size for IP addresses
#define IP_STRING         255
// MAX size for an interface name
#define IFACE_STRING      255

// Error template while parsing session parameter in configuration file.
#define SESS_ERR   "Session[%i]: parameter '%s' missing!"
#define SESS_ERR_1 "Session[%i]: parameter '%s' %s!"
// Error in session configuration (not parameter specific)
#define SESS_ERR_2 "Session[%i]: %s!"
#define SESS_ERR_3 "Session[%i]: Unknown error!"


// Used for updates
/** Used to specify no validation state available. */
#define UPD_RPKI_NONE     '-'
/** Used to signal validation state 'valid' */
#define UPD_RPKI_VALID    'V'
/** Used to signal validation state 'invalid' */
#define UPD_RPKI_INVALID  'I'
/** Used to signal validation state 'not found'*/
#define UPD_RPKI_NOTFOUND 'N'

/** Character to open AS_SET in update string */
#define UPD_AS_SET_OPEN    '{'
/** Character to close AS_SET in update string */
#define UPD_AS_SET_CLOSE   '}'
/**
 * Determines how the program operates
 */
typedef enum OP_Mode 
{
  OPM_GEN_B  = 0,
  OPM_GEN_C  = 1,
  OPM_BGP    = 2,
  OPM_CAPI   = 3        
} OP_Mode;

/** This structure is used to allow the parameter parsing outside of the 
 *  main method. */
typedef struct 
{
  /** Indicates if this update MUST be used as BGP-4 only update. */
  bool            bgp4_only;
  /** Can be typecase to IPv4 and IPv6. */
  BGPSEC_V6Prefix prefixTpl;
  /** The as path as string. */
  char*           pathStr;
  /** The as_set string - NULL if no AS_SET exists. */
  char*           asSetStr;
  /** used to determine if a validation state can be send via community string. 
   */
  char            validation; // contains the RPKI validation state 
                              // either 0, 'V', 'I', 'N'
  // @TODO: Maybe here we can add the binary data as well?????
} UpdateData;

/** This structure contains the configuration for the RPKI Cache test harness.
 */
typedef struct
{
  /** Port address of the RPKI cache. */
  int port;  
} RPKI_Cache;

/** Max updates to play. */
#define MAX_UPDATES 0xFFFFFFFF

/** This structure is used to allow the parameter parsing outside of the 
 *  main method. */
typedef struct 
{
  /** Buffer containing the name of the ski file. */
  char      skiFName[FNAME_SIZE];
  /** buffer containing the root folder of the keys and ski file. */
  char      keyLocation[FNAME_SIZE];
  /** Indicate if the OpenSSL EC_KEY should be generated during loading.*/
  bool      preloadECKEY;
  
  /** Specify if all BGPSec Path Attributes must be generated with extended 
   * length flag set and 2 byte length field. */
  bool      onlyExtLength;
  
   /** Holds all updates passed to the program using the -u parameter. This stack
   * will be added to session 0 after the configuration. */
  Stack     paramUpdateStack;
  /** Holds all updates that are scripted as global updates. This stack will be
   *  distributed over all session stacks after the configuration. */
  Stack     globalUpdateStack;
  /** Specifies the operational mode GEN|BGP|CAPI*/
  OP_Mode   type;
  /** The number of bgp sessions. */
  u_int16_t sessionCount;
  /** The array containing the session configurations*/
  BGP_SessionConf** sessionConf;
  /** Holds the configuration for the active BGP session. Also needed for the 
  /* the RPKI Cache Test harness. */
  RPKI_Cache rpkiCache;
  /** Name of the configuration file to be read. */
  char      cfgFile[FNAME_SIZE];
  /** Some buffer to store error messages. */
  char      errMsgBuff[PARAM_ERRBUF_SIZE];
  
  /** Name of the binary input file of pre-computed BGPSEC data */
  char      binOutFile[FNAME_SIZE]; // Only used in mode GEN
  /** Indicate if the out file will be opened in append mode or overwrite mode*/
  bool      appendOut;
  /* Name of the file that contains the binary pre-computed BGPSEC data. */
  char      binInFile[FNAME_SIZE];  // Only used for BGP and CAPI
  /* Indicate if also the standard input is used. */
  bool      useStdIn; // indicates if the standard input is used as well. 
  /* Indicates if a new configuration file has to be generated. */
  bool      createCfgFile;
  /* Allows to restrict the player to play a maximum of updates. */
  u_int32_t maxUpdates;
  /* Contains the configuration name if a configuration file has to be 
   * generated. */
  char      newCfgFileName[FNAME_SIZE];
  /* Contains the name of the SRxCryptoAPI configuration file. If none is 
   * provided, keep the content of this char array '\0' (strlen == 0)*/
  char      capiCfgFileName[FNAME_SIZE];
  /* The interface where the local IP address information are retrieved from.
   * This setting is ONLY ALLOWED in combination with -C */
  char      iface[IFACE_STRING];
} PrgParams;

/**
 * Print the program Syntax.
 */
void printSyntax();

/**
 * Translate the given parameter in a one character parameter if possible or 0 
 * if not known.
 * 
 * @param argument The argument
 * 
 * @return the one character replacement or 0 "zero"
 */
char getShortParam(char* argument);

/**
 * This function will post process the update stacks. This means the updates
 * added via program parameters will be added to Session 0. These updates will
 * be the first to be 'popped'.
 * Also all global updates will be distributed over all sessions. After this 
 * method is called the two stacks 'paramUpdateStack' and 'globalUpdateStack'
 * will be empty.
 * For this function to properly function all session stacks MUST be properly 
 * initialized.
 * 
 * @param params The program params containing all configurations
 * 
 * @since 0.2.1.0
 */
void postProcessUpdateStack(PrgParams* params);

/**
 * This function verifies that all necessary data is provided to tun the BGP
 * daemon.
 * 
 * @param params The parameters / configurations.
 * 
 * @return true if BGP daemon can be started, false if not. 
 */
bool checkBGPConfig(PrgParams* params);

/**
 * Read the given configuration file and set the params.
 * 
 * @param params The parameters
 * 
 * @return true if the configuration file could be read.
 */
bool readConfig(PrgParams* params);

/**
 * Initialize the params and set default values.
 * 
 * @param params The parameters object.
 * 
 */
void initParams(PrgParams* params);

/**
 * Remove all memory allocated within the params structure and set all 
 * allocated memory to "0". If desired free will be called on params as well. 
 * 
 * @param params the params instance
 * @param doFree if true the memory will be freed as well
 */
void cleanupParams(PrgParams* params, bool doFree);

/**
 * Parse the given program parameter
 * 
 * @param params Stores the settings found in the program arguments
 * @param argc The number of arguments
 * @param argv the array containing the program arguments
 * 
 * @return 1 for success, 0 for stop (help), -1 for error
 */
int parseParams(PrgParams* params, int argc, char** argv);

/**
 * Generate the UpdateData instance from the given string in the format given 
 * format prefix[,[as-path]]
 * 
 * @param prefix_path the given path
 * @param params the program params
 * 
 * @return the update data or NULL in case of an error. 
 */
UpdateData* createUpdate(char* prefix_path, PrgParams* params);

/** 
 * free the Update data parsed from program parameters. 
 * 
 * @param update The update parameter that has to be freed.
 */
void freeUpdateData(void* upd);

#endif	/* CONFIGURATION_H */
