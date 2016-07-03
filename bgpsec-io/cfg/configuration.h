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
 * @version 0.2.0.0
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
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
#include "antd-util/stack.h"
#include "bgpsec/BGPSecPathBin.h"

#ifdef HAVE_CONFIG_H
#define PRG_NAME    PACKAGE
#define PRG_VERSION "V" VERSION
#else
#define PRG_NAME    "bgpsecio"
#define PRG_VERSION ""
#endif

#define DEF_KEYLOCATION     "/var/lib/key-volt/\0"
#define DEF_SKIFILE         "/var/lib/key-volt/ski-list.txt\0"
#define DEF_PEER_PORT       179
#define DEF_HOLD_TIME       180
#define DEF_DISCONNECT_TIME 0
#define DEF_ALGO_ID         1

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
/* Use BGP4 attribute instead of BGPSec*/
#define P_TYPE_NSM_BGP4 "BGP4"

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

// hold_timer=<time_in_seconds> - The requested BGP hold time
#define P_CFG_HOLD_TIME "hold_timer"
// --hold_timer=<time_in_seconds> - The requested BGP hold time
#define P_HOLD_TIME     "--" P_CFG_HOLD_TIME
// -x <time_in_seconds> - The requested BGP hold time
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

// peer-port=<int> - The peer port (Default 179)
#define P_CFG_PEER_PORT "peer_port"
// --peer-port <int>  - The peer port (Default 179)
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
#define P_C_CAPI_CFG    'p'

// encodeMPNLRI="true|false" - enable / disable MPNLRI (default enabled)
#define  P_CFG_MPNLRI   "encodeMPNLRI"
// --no_mpnlri         - do not use MPNLRI encoding for IPv4
#define  P_NO_MPNLRI    "--no_mpnlri"
// -M                  - do not use MPNLRI encoding for V4
#define  P_C_NO_MPNLRI  'M'

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
// print bgp packages on receive
#define P_CFG_PRINT_ON_RECEIVE      "printOnReceive"
// print bgp packages on send
#define P_CFG_PRINT_ON_SEND         "printOnSend"
// print the poll loop for the session
#define P_CFG_PRINT_POLL_LOOP       "printPollLoop"
// print the status information on invalid - CAPI mode"
#define P_CFG_PRINT_CAPI_ON_INVALID "printOnInvalid"

/// algorithmID
#define P_CFG_ALGO_ID              "algo_id" 
#define P_CFG_ALGO_ID_DEF_VAL      1
// allow fake signatures
#define P_CFG_NULL_SIGNATURE_MODE  "null_signature_mode"
// fake signature
#define P_CFG_FAKE_SIGNATURE       "fake_signature"
// fake ski
#define P_CFG_FAKE_SKI             "fake_ski"

// Max size for the error message buffer
#define PARAM_ERRBUF_SIZE 255
// Max size for file names 
#define FNAME_SIZE        255
// MAX size for IP addresses
#define IP_STRING         255

// Error template while parsing session parameter in cofiguration file.
#define SESS_ERR   "Session[%i]: parameter '%s' missing!"
#define SESS_ERR_1 "Session[%i]: parameter '%s' %s!"

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
  BGPSEC_V6Prefix prefixTpl; // can be typecase to v4 and v6
  char*           pathStr;
  // @TODO: Maybe here we can add the binary data as well?????
} UpdateData;

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
  
  /** Holds all updates */
  Stack     updateStack;
  /** Specifies the operational mode GEN|BGP|CAPI*/
  OP_Mode   type;
  /** Holds the configuration for the main BGP session. Also needed for the 
   * BGPSEC attribute generation if no BGP player is used. */
  BGP_SessionConf bgpConf;
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