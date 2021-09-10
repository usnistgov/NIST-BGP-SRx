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
 * This software might use libraries that are under GNU public license or
 * other licenses. Please refer to the licenses of all libraries required
 * by this software.
 *
 * This header file contains data structures needed for the application.
 *
 * @version 0.2.1.8
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.1.8 - 2021/09/09 - oborchert
 *            * Fixed incorreck k value being printed out for BIO-2 when 
 *              printing syntax
 *  0.2.1.7 - 2021/09/03 - oborchert
 *            * Fixed formatting in code.
 *          - 2021/07/12 - oborchert
 *            * Fixed spellers in the configuration.
 *            * Added P_TYPE_NSM_BGP_4="BGP-4" as inofficial alternative to 
 *              setting "BGP4"
 *  0.2.1.6 - 2021/05/21 - oborchert
 *            * Fixed a segmentation fault in update processing
 *  0.2.1.5 - 2021/05/10 - oborchert
 *            * Fixed document output when called using -?
 *            * Modified output to use defines rather than hard coded text.
 *  0.2.1.2 - 2020/09/14 - oborchert
 *            * Fixed segmentation fault in postProcessUpdateStack.
 *  0.2.1.1 - 2020/07/31 - oborchert
 *            * Added define SRX_DEV_TOYEAR
 *  0.2.1.0 - 2018/11/29 - oborchert
 *            * Removed merge comments in version control.
 *          - 2018/01/16 - oborchert
 *            * Fixed some issues with multi session handling.
 *          - 2018/01/12 - oborchert
 *            * Modified processing of update configuration. Distribute global
 *              updates to each session.
 *          - 2018/01/10 - oborchert
 *            * Fixed TO DO tags
 *          - 2018/01/09 - oborchert
 *            * Removed define SUPPORT_MULTI_SESSION and error generation in 
 *              case of multi-session generation.
 *          - 2017/12/26 - oborchert
 *            * Fixed segmentation fault during while configuring multiple
 *              sessions.
 *          - 2017/12/22 - oborchert
 *            * Rewrote function _setConfigSessErr
 *          - 2017/12/20 - oborchert
 *            * Added processing of multi sessions.
 *          - 2017/12/20 - oborchert
 *            * Moved default BGP session configuration into function 
 *              initBGPSessionConfig.
 *            * Added missing configuration portion for bgp_identifier
 *          - 2017/12/11 - oborchert
 *            * Fixed syntax documentation printout.
 *            * Added interface specification into syntax.
 *          - 2017/12/05 - oborchert
 *            * Replaced interface binding with outgoing IP address binding.
 *              (does not require elevated privileges - better solution)
 *            * Added capability to use an update as BGP4 only
 *            * Modified the "to date" in syntax.
 *          - 2-17/11/22 - oborchert
 *            * Updated function printSyntax()
 *          - 2017/11/20 - oborchert
 *            * Added configuration for interface binding
 *  0.2.0.21- 2018/06/08 - oborchert
 *            * Updated configuration initialization.
 *          - 2018/06/07 - oborchert
 *            * Added -T --convergence to allow enabling and  disabling the 
 *              convergence printout.
 *  0.2.0.16- 2018/04/21 - oborchert
 *            * Added more syntax description for update scripting.
 *  0.2.0.14- 2018/04/19 - oborchert
 *            * Added parsing of possible validation state to createUpdate.
 *  0.2.0.11- 2018/03/22 - oborchert
 *            * Added processing of P_CFG_CAP_AS4
 *          - 2018/03/21 - oborchert
 *            * Added inclGlobalUpdates
 *            * Updated printSyntax with latest settings.
 *  0.2.0.10- 2017/09/01 - oborchert
 *            * Removed not used variables.
 *  0.2.0.7 - 2017/07/11 - oborchert
 *            * Fixed speller in command line documentation.
 *          - 2017/05/03 - oborchert
 *            * Moved include config.h into configuration.h
 *          - 2017/04/28 - oborchert
 *            * BZ1153: Updated error that GEN-C generated updates could not be 
 *              used by peer, missing next hop information.
 *            * Modified create Session by removing configuration setup that 
 *              belongs into the configuration.
 *          - 2017/03/22 - oborchert
 *            BZ1145: Updated error in using BIO-K1 which did not specify the k
 *            as advertised.
 *          - 2017/03/16 - oborchert
 *            * Updated the syntax printout.
 *          - 2017/03/15 - oborchert
 *            * Modified print filter to allow being a scalar or a configuration
 *          - 2017/03/10 - oborchert
 *            * Added filter for BGP message printer
 *          - 2017/03/09 - oborchert
 *            * BZ1113: Removed selective disabling of BGPSEC_IPv6 send.
 *          - 2017/03/01 - oborchert
 *            * BZ1115: Added more info to error message for invalid scripted
 *              update messages.
 *          - 2017/02/28 - oborchert
 *            * Slight modification in update processing.
 *          - 2017/02/16 - oborchert
 *            * Added missing function documentation.
 *            * modified the return value of _setIP6Address from void to bool
 *          - 2017/02/14 - oborchert (branch 2017/02/10)
 *            * Modified the bgp identifier variable in such that the IP value 
 *              is stored in network format rather than host format to be in 
 *              line with the next hop identifiers.
 *          - oborchert (branch 2017/02/07)
 *            * Added missing configuration for IPv6 next hop.
 *            * Added alternative configuration for IPv4 next hop.
 *            * Fixed some spellers in documentation.
 *  0.2.0.6 - 2017/02/15 - oborchert
 *            * Added switch to force sending extended messages regardless if
 *              capability is negotiated. This is a TEST setting only.
 *          - 2017/02/13 - oborchert
 *            * Renamed define from ..._EXTMSG_SIZE to EXT_MSG_CAP
 *            * Removed invalid DEPRECATION message
 *            * BZ1111: Added liberal policy to extended message capability 
 *              processing
 *  0.2.0.5 - 2017/01/31 - oborchert
 *            * Added missing configuration for extended message size capability
 *          - 2017/01/03 - oborchert
 *            * Added parameter P_CFG_SIGMODE
 *          - 2016/11/15 - oborchert
 *            * Added parameter P_CFG_ONLY_EXTENDED_LENGTH
 *          - 2016/10/21 - oborchert
 *            * Fixed issue with 32/64 bit libconfig integer type BZ1033.
 *  0.2.0.3 - 2016/06/28 - oborchert
 *            * Added missing description of parameter -U to help output.
 *  0.2.0.2 - 2016/06/27 - oborchert
 *            * Added warning message in case useMPNLRI is set to false.
 *            * Added --version / -v to print version number
 *            * Also added version to help screen
 *          - 2016/06/24 - oborchert
 *            * Fixed BUG 923 - Added detection for invalid scripted updates
 *  0.2.0.0 - 2016/06/08 - oborchert
 *            * Fixed memory leak
 *          - 2016/05/13 - oborchert
 *            * Added maximum update processing BZ:961
 *          - 2016/05/11 - oborchert
 *            * Re-arranged help output.
 *          - 2016/05/06 - oborchert
 *            * Added processing of configuration for SRxCryptoAPI configuration.
 *            * Replaced sprintf with snprintf for filename specifications.
 *            * Fixed a bug if the prefix misses the prefix length (BZ: 948)
 *  0.1.1.0 - 2016/04/27 - oborchert
 *            * Removed debug printout.
 *          - 2016/04/19 - oborchert
 *            * Added write boundary for filenames to not produce a segmentation
 *              fault.
 *          - 2016/04/15 - oborchert
 *            * Fixed prefix generation in createUpdate. Generate prefix in 
 *              big-endian (network) format.
 *            * Set prefix to SAFI_UNICAST in update generation.
 *          - 2016/03/26 - oborchert
 *            * Added initialization of algoParam in session init. 
 *          - 2016/03/21 - oborchert
 *            * fixed BZ892
 *            * Added more specific print instructions for BGP traffic.
 *          - 2016/03/17 - oborchert
 *            * Modified _createUpdate to allow an empty path. This will allow
 *              bgpsec-io to generate a one hop path with a prefix originated
 *              by bgpsec-io itself.
 *  0.1.0.0 - 2015/08/26 - oborchert
 *            * Created File.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <malloc.h>
#include <libconfig.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include "antd-util/prefix.h"
#include "antd-util/printer.h"
#include "antd-util/stack.h"
#include "bgp/BGPSession.h"
#include "bgp/BGPHeader.h"
#include "bgp/printer/BGPPrinterUtil.h"
#include "bgp/printer/BGPHeaderPrinter.h"
#include "bgpsec/Crypto.h"
#include "cfg/configuration.h"

/**
 * This message fills the error message buffer with the given string.
 * 
 * @param param (PrgParams*) The program parameters that contain the buffer
 * @param str (char*) The message string
 */
static void _setErrMsg(PrgParams* param, char* str)
{
  int buffLen = PARAM_ERRBUF_SIZE;
  memset (&param->errMsgBuff, '\0', buffLen);

  int size = strlen(str) < buffLen ? strlen(str) : (buffLen - 1);
  // Only copy the amount of text into the error message as space is available
  memcpy(&param->errMsgBuff, str, size);
}


/**
 * Print the program Syntax.
 */
void printSyntax()
{
  printf ("\nSyntax: %s [parameters]\n", PRG_NAME);
  printf (" This program allows receiving updates via pipe stream, one update"
          " per line.\n");
  printf ("\n Parameters:\n");
  printf (" ===========\n");
  // Help
  printf ("  -%c, -%c, -%c, %s\n", P_C_HELP, P_C_HELP_1, P_C_HELP_2, P_HELP);
  printf ("          This screen!\n");

  printf ("  -%c, %s\n", P_C_VERSION, P_VERSION);
  printf ("          Display the version number.\n");
  
  printf ("  -%c <config>, %s <config>\n", P_C_CONFIG, P_CONFIG);
  printf ("          config: The configuration file.\n");

  printf ("  -%c <config>, %s <config>\n", P_C_CAPI_CFG, P_CAPI_CFG);
  printf ("          config: An alternative SRxCryptoAPI configuration file.\n");
  
  // Update: <prefix,path>
  printf ("  -%c <prefix, path>, %s <prefix, path>\n", P_C_UPD_PARAM, P_UPD_PARAM);
  printf ("          prefix: Prefix to be announced.\n");
  printf ("          path: The list of AS numbers (right most is origin).\n");
  printf ("                The path can contain pCount values using <asn>p<value>\n");
  printf ("                  to create p repetitions of asn.\n");
  printf ("                In case the path contains the value 'I', 'V', or 'N'\n");
  printf ("                  an extended community string will be added with\n");
  printf ("                  the RPKI validation state I:invalid, V:valid, or\n");
  printf ("                  N:not-found (no difference between iBGP or eBGP\n");  
  printf ("                To define BGP-4 only path, start path with B4 for BGP-4!\n");

 // SKI_FILE
  printf ("  -%c <filename>, %s <filename>\n", P_C_SKI_FILE, P_SKI_FILE);
  printf ("          Name of the SKI file generated by qsrx-publish\n");
  //SKI_LOC
  printf ("  -%c <directory>, %s <directory>\n", P_C_SKI_LOC, P_SKI_LOC);
  printf ("          Specify the location where the keys and certificates"
                     " are located.\n");
  // type
  printf ("  -%c <type>, %s <type>\n", P_C_TYPE, P_TYPE);
  printf ("          Enable the operational mode:\n");
  printf ("          type %s: run BGP player\n", P_TYPE_BGP);
  printf ("          type %s: run as SRxCryptoAPI tester.\n", P_TYPE_CAPI);
  printf ("          type %s: Generate the binary data of BGPsec "
                     "UPDATES.\n", P_TYPE_GENB);
  printf ("          type %s: Generate the binary data of BGPsec Path "
                     "Attributes.\n", P_TYPE_GENC);
  
  // ASN  
  printf ("  -%c <asn>, %s <asn>\n", P_C_MY_ASN, P_MY_ASN);
  printf ("          Specify the own AS number.\n");
  // BGP identifier
  printf ("  -%c <IPv4>, %s <IPv4>\n", P_C_BGP_IDENT, P_BGP_IDENT);
  printf ("          The BGP identifier of the BGP daemon.\n");
  // Hold Timer
  printf ("  -%c <time>, %s <time>\n", P_C_HOLD_TIME, P_HOLD_TIME);
  printf ("          The hold timer in seconds (0 or >=3).\n");
  // Peer ASN
  printf ("  -%c <asn>, %s <asn>\n", P_C_PEER_AS, P_PEER_AS);
  printf ("          The peer as number.\n");
  // Peer IP
  printf ("  -%c <IPv4>, %s <IPv4>\n", P_C_PEER_IP, P_PEER_IP);
  printf ("          The IP address of the peer.\n");
  // Peer Port
  printf ("  -%c <port>, %s <port>\n", P_C_PEER_PORT, P_PEER_PORT);
  printf ("          The port number of the peer.\n");
  
  printf ("  -%c, %s\n", P_C_NO_MPNLRI, P_NO_MPNLRI);
  printf ("          DEPRECATED.\n");
  printf ("          Disable MPNLRI encoding for IPv4 addresses.\n");
  printf ("          If disabled prefixes are encoded as NLRI only.\n");

  printf ("  -%c, %s\n", P_C_NO_EXT_MSG_CAP, P_NO_EXT_MSG_CAP);
  printf ("          Disable the usage of messages larger than 4096 bytes.\n");
 printf ("          This includes the capability exchange.(Default enabled)\n");
  printf ("  -%c, %s\n", P_C_NO_EXT_MSG_LIBERAL, P_NO_EXT_MSG_LIBERAL);
  printf ("          Reject extended messages if not properly negotiated.\n");
  printf ("  %s\n", P_EXT_MSG_FORCE);
  printf ("          Force sending extended messages regardless if capability\n");
  printf ("          is negotiated. Allows debugging the peer.\n");
  
  // Disconnect time
  printf ("  -%c <time>, %s <time>\n", P_C_DISCONNECT_TIME, P_DISCONNECT_TIME);
  printf ("          The minimum time in seconds the session stays up after\n");
  printf ("          the last update was sent. The real disconnect time is\n");
  printf ("          somewhere between <time> and <holdTime> / 3.\n");
  printf ("          A time of 0 \"zero\" disables the automatic disconnect.\n");
  
  // Convergence
  printf ("  -%c, %s\n", P_C_CONVERGENCE, P_CONVERGENCE);
  printf ("          Enable BGP convergence statistics to be displayed for\n");
  printf ("          updates received.\n");
  
  // Pre-compute EC_KEY
  printf ("  -%c, %s\n", P_C_NO_PL_ECKEY, P_NO_PL_ECKEY);
  printf ("          Disable pre-computation of EC_KEY structure during\n");
  printf ("          loading of the private and public keys.\n");

  // Binary Input file
  printf ("  -%c <filename>, %s <filename>\n", P_C_BINFILE, P_BINFILE);
  printf ("          The filename containing the binary input data. Here \n");
  printf ("          only the first configured session will be used.\n");

  // Binary Output file
  printf ("  -%c <filename>, %s <filename>\n", P_C_OUTFILE, P_OUTFILE);
  printf ("          The filename where to write the output to - Here only\n");
  printf ("          the first configured session will be used.\n");
  printf ("          Requires GEN mode!!\n");

  // Binary Output file
  printf ("  -%c, %s\n", P_C_APPEND_OUT, P_APPEND_OUT);
  printf ("          If specified, the generated data will be appended to\n");
  printf ("          given outfile. In case the outfile does not exist, a\n");
  printf ("          new one will be generated.\n");
  printf ("          Requires GEN mode!!\n");
  
  // Use Maximum number of updates 
  printf ("  -%c, %s\n", P_C_MAX_UPD, P_MAX_UPD);
  printf ("          Allows to restrict the number of updates generated.\n");
  
  // -C <config-file> - Generate a config file.
  printf ("  -%c <filename>\n", P_C_CREATE_CFG_FILE);
  printf ("          Generate a configuration file. The configuration file\n");
  printf ("          uses the given setup (parameters, configuration file)\n");
  printf ("          or generates a sample file if no configuration is\n");
  printf ("          specified.\n");
  
  printf ("  -%c <interface>\n", P_C_IFACE);
  printf ("          Use the interface to determine the local IP address.\n");
  printf ("          This setting is only used in combination with the\n");
  printf ("          creation of a configuration file.\n");
  
  printf ("\n Configuration file only parameters:\n");
  printf (" ===================================\n");
  
  // ENABLE / DISABLE Global updates per session
  printf ("  %s\n", P_CFG_INCL_GLOBAL_UPDATES);
  printf ("          Enable/Disable adding global updates to this session.\n");
  printf ("          Default: %s\n", DEF_INCL_GLOBAL_UPDATE ? "true" : "false");

  // ENABLE / DISABLE 4 byte ASNs
  printf ("  %s\n", P_CFG_CAP_AS4);
  printf ("          Enable/Disable the usage of 4 byte ASN.\n");
  printf ("          Default: true (enable)\n");
  
  // BGPSEC Configuration
  // Enable and disable BGPSEC IPv4 Receive
  printf ("  %s\n", P_CFG_BGPSEC_V4_R);
  printf ("          Specify if bgpsec-io can receive IPv4 BGPSEC traffic.\n");
  printf ("          Default: true\n");
  // Enable and disable BGPSEC IPv4 Send
  printf ("  %s\n", P_CFG_BGPSEC_V4_S);
  printf ("          Specify if bgpsec-io can send IPv4 BGPSEC traffic.\n");
  printf ("          Default: true\n");
  // Enable and disable BGPSEC IPv6 Receive
  printf ("  %s\n", P_CFG_BGPSEC_V6_R);
  printf ("          Specify if bgpsec-io can receive IPv6 BGPSEC traffic.\n");
  printf ("          Default: true\n");
  // Enable and disable BGPSEC IPv6 Send
  printf ("  %s\n", P_CFG_BGPSEC_V6_S);
  printf ("          Specify if bgpsec-io can send IPv6 BGPSEC traffic.\n");
  printf ("          Default: false\n");
  
  // Bind the session to an IP address
  printf ("  %s\n", P_CFG_LOCAL_ADDR);
  printf ("          Specify the IP address used for this session. In case\n");
  printf ("          no local IP is specified the BGP identifier is\n");
  printf ("          used.\n");

  // signature_generation
  char kStr[STR_MAX];
  memset (kStr, '\0', STR_MAX);
  printf ("  %s\n", P_CFG_SIG_GENERATION);
  printf ("          Specify the signature generation mode:\n");
  printf ("          mode CAPI: Use CAPI to sign the updates.\n");
  printf ("          mode BIO: Use internal signature algorithm (default).\n");
  printf ("          mode BIO-K1: Same as BIO except it uses a static k.\n");
  printf ("          mode BIO-K2: Same as BIO except it uses a static k.\n");
  printf ("          The signature modes BIO-K1 and BIO-K2 both use a k \n");
  printf ("          which is specified in RFC6979 Section A.2.5\n");
  printf ("          BIO-K1 uses k for SHA256 and msg=sample.\n");
  CRYPTO_k_to_string(kStr, STR_MAX, SM_BIO_K1);
  printf ("           k=%s\n", kStr);
  printf ("          BIO-K2 uses k for SHA256 and msg=test.\n");
  CRYPTO_k_to_string(kStr, STR_MAX, SM_BIO_K2);
  printf ("           k=%s\n", kStr);
  
  // Force extended length for BGPSEC path attribute.
  printf ("  %s\n", P_CFG_ONLY_EXTENDED_LENGTH);
  printf ("          Force usage of extended length also for BGPSEC\n");
  printf ("          path attributes with a length of less than 255 bytes.\n");
  
  // Fake signature portion
  printf ("  %s\n", P_CFG_NULL_SIGNATURE_MODE);
  printf ("          Specify what to do in case no signature can be\n");
  printf ("          generated. Example: no key information is found.\n");
  printf ("          Valid values are (%s|%s|%s).\n", 
          P_TYPE_NSM_DROP, P_TYPE_NSM_FAKE, P_TYPE_NSM_BGP4);

  // fake signature
  printf ("  %s\n", P_CFG_FAKE_SIGNATURE);
  printf ("          This string contains the fake signature in hex format.\n");
  printf ("          The signature must not be longer than %i bytes.\n", 
          MAX_SIG_BYTE_SIZE);
  printf ("          (2 HEX characters equals one byte!).\n");

  // fake ski
  printf ("  %s\n", P_CFG_FAKE_SKI);
  printf ("          This string contains the fake ski for not found keys.\n");
  printf ("          The SKI MUST consist of %i bytes.\n", 
          SKI_LENGTH);
  printf ("          (2 HEX characters equals one byte!).\n\n");

  // print... Portion
  printf ("  %s, %s\n", P_CFG_PRINT_ON_SEND, P_CFG_PRINT_ON_RECEIVE);
  printf ("          Each BGP update packet sen/received will be printed on\n");
  printf ("          standard output in WireShark form.\n");
  printf ("          Use this setting for debug only!!\n");  
  printf ("          Both settings can be used in two different forms:\n");
  printf ("          (1) Set =true|false to this for all message types.\n");
  printf ("          (2) Use as sub configuration to fine-tune each message.\n");
  printf ("              Using this form sets all message types to false and\n");
  printf ("              they must be individually set to true.\n");
  printf ("              = { msg-type = true|false; ... }; \n");
  printf ("              Valid message types are:\n");
  printf ("              %s\n", P_CFG_PRNFLTR_OPEN);
  printf ("                      Printing of bgp OPEN messages.\n");
  printf ("              %s\n", P_CFG_PRNFLTR_UPDATE);
  printf ("                      Printing of bgp UPDATE messages.\n");
  printf ("              %s\n", P_CFG_PRNFLTR_KEEPALIVE);
  printf ("                      Printing of bgp KEEPALIVE messages.\n");
  printf ("              %s\n", P_CFG_PRNFLTR_NOTIFICATION);
  printf ("                      Printing of bgp NOTIFICATION messages.\n");
  printf ("              %s\n", P_CFG_PRNFLTR_UNKNOWN);
  printf ("                      Printing of future bgp messages.\n");
  printf ("  %s\n", P_CFG_PRINT_SIMPLE);
  printf ("          Print BGP messages in simple format (true) of in\n");
  printf ("          Wireshark format (fasle).\n");  
  printf ("  %s\n", P_CFG_PRINT_POLL_LOOP);
  printf ("          Print information each time the poll loop runs.\n");  
  printf ("  %s\n", P_CFG_PRINT_CAPI_ON_INVALID);
  printf ("          Print status information on validation result invalid.\n");
  printf ("          This setting only affects the CAPI mode.\n");
  
  printf ("\n");
  printf ("%s Version %s\nDeveloped 2015-%s by Oliver Borchert ANTD/NIST\n", 
          PACKAGE_NAME, PACKAGE_VERSION, SRX_DEV_TOYEAR);
  printf ("Send bug reports to %s\n\n", PACKAGE_BUGREPORT);
}

/**
 * Display the version number.
 * 
 * @since 0.2.0.2
 */
void printVersion()
{
  printf ("%s Version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
}

/**
 * Translate the given parameter in a one character parameter if possible or 0 
 * if not known.
 * 
 * @param argument The argument
 * 
 * @return the one character replacement or 0 "zero"
 */
char getShortParam(char* argument)
{
  char retVal = 0;

  if (*argument == '-')
  {
    if (strlen(argument) == 2)
    {
      argument++;
      retVal = *argument;
    }  
    else if (strcmp(argument, P_HELP) == 0)        { retVal = P_C_HELP_1; }
    else if (strcmp(argument, P_VERSION) == 0)     { retVal = P_C_VERSION; }
    else if (strcmp(argument, P_SKI_FILE) == 0)    { retVal = P_C_SKI_FILE; }
    else if (strcmp(argument, P_SKI_LOC) == 0)     { retVal = P_C_SKI_LOC; }
    else if (strcmp(argument, P_TYPE) == 0)        { retVal = P_C_TYPE; }
    else if (strcmp(argument, P_BGP_IDENT) == 0)   { retVal = P_C_BGP_IDENT; }
    else if (strcmp(argument, P_MY_ASN) == 0)      { retVal = P_C_MY_ASN; }
    else if (strcmp(argument, P_PEER_AS) == 0)     { retVal = P_C_PEER_AS; }
    else if (strcmp(argument, P_PEER_IP) == 0)     { retVal = P_C_PEER_IP; }
    else if (strcmp(argument, P_CONFIG) == 0)      { retVal = P_C_CONFIG; }
    else if (strcmp(argument, P_UPD_PARAM) == 0)   { retVal = P_C_UPD_PARAM; }
    else if (strcmp(argument, P_BINFILE) == 0)     { retVal = P_C_BINFILE; }
    else if (strcmp(argument, P_OUTFILE) == 0)     { retVal = P_C_OUTFILE; }
    else if (strcmp(argument, P_APPEND_OUT) == 0)  { retVal = P_C_APPEND_OUT; }
    else if (strcmp(argument, P_NO_MPNLRI) == 0)   { retVal = P_C_NO_MPNLRI; }
    else if (strcmp(argument, P_NO_EXT_MSG_CAP) == 0) 
         { retVal = P_C_NO_EXT_MSG_CAP; }
    else if (strcmp(argument, P_NO_EXT_MSG_LIBERAL) == 0) 
         { retVal = P_C_NO_EXT_MSG_LIBERAL; }
    else if (strcmp(argument, P_NO_PL_ECKEY) == 0) { retVal = P_C_NO_PL_ECKEY; }
    else if (strcmp(argument, P_CAPI_CFG) == 0)    { retVal = P_C_CAPI_CFG; }
    else if (strcmp(argument, P_MAX_UPD) == 0)     { retVal = P_C_MAX_UPD; }
  }
  
  return retVal;
}

/**
 * This function duplicates the given update data object.
 * 
 * @param update The update to be duplicated.
 * 
 * @return The duplicate of the update 
 */
static UpdateData* _duplicateUpdate(UpdateData* update)
{
  UpdateData* copy = malloc(sizeof(UpdateData));
  memset (copy, 0, sizeof(UpdateData));
  copy->bgp4_only = update->bgp4_only;
  memcpy(&copy->prefixTpl, &update->prefixTpl, sizeof(BGPSEC_V6Prefix));
  if (update->pathStr != NULL)
  {
    copy->pathStr = malloc(strlen(update->pathStr)+1);
    memcpy(copy->pathStr, update->pathStr, strlen(update->pathStr)+1);
  }
  
  return copy;
}

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
void postProcessUpdateStack(PrgParams* params)
{
  int sessIdx;
  UpdateData* update = NULL;
  UpdateData* copy = NULL;

  // Add the program parameter stack to the first session stack
  if (!isStackEmpty(&params->paramUpdateStack))
  {
    if (params->sessionCount != 0)
    {
      // Here move the param update stack into the first session stack
      Stack* sStack = &params->sessionConf[0]->updateStack;
      Stack* pStack = &params->paramUpdateStack;
      if (pStack->count != 0)
      {
        sStack->count += pStack->count;
        pStack->count = 0;
        
        pStack->tail->next = sStack->head;
        if (sStack->head != NULL)
        {
          sStack->head->prev = pStack->tail;
        }
        sStack->head = pStack->head;
        // Removed teh following two lines, they caused a segmentation 
        // fault.
        // pStack->head = NULL;
        // sStack->head = NULL;
      }
    }
  }
  
  // Now pop each global update and push it into the session stacks.
  update = (UpdateData*)popStack(&params->globalUpdateStack);
  while (update != NULL)
  {
    for (sessIdx = 0; sessIdx < params->sessionCount; sessIdx++)
    {
      // create a copy for all stacks except the last one. Here we use the 
      // globally retrieved one.
      copy = sessIdx < (params->sessionCount-1)
             ? _duplicateUpdate(update)
             : update;
      fifoPush(&params->sessionConf[sessIdx]->updateStack, copy);
    }
    
    update = (UpdateData*)popStack(&params->globalUpdateStack);
  }
}

/**
 * This function verifies that all necessary data is provided to tun the BGP
 * daemon. It is expected that all session updates and global updates are 
 * properly distributes prior this call.
 * 
 * @param params The parameters / configurations.
 * 
 * @return true if BGP daemon can be started, false if not. 
 */
bool checkBGPConfig(PrgParams* params)
{
  bool bgpConf = params->sessionCount != 0;
  int sessIdx;
  BGP_SessionConf* config = NULL;
  
  for (sessIdx = 0; sessIdx < params->sessionCount; sessIdx++)
  {
    config = params->sessionConf[sessIdx];
    
    if (params->type == OPM_BGP)
    {
      bgpConf = bgpConf
                && config->bgpIdentifier && config->asn && config->peerAS 
                && config->peer_addr.sin_addr.s_addr 
                && config->peer_addr.sin_port
                && params->keyLocation && params->skiFName;       
    }
    if (!bgpConf)
    {
      break;
    }
  }

  return bgpConf;
}

/**
 * Writes an error message SESS_ERR or SESS_ERR_1. The later one is used in case
 * error is NOT NULL.
 * 
 * @param params The parameter to set the error in
 * @param session The session of the error
 * @param paramName The name of the parameter itself
 * @param error The error string itself - Uses SESS_ERR_1 if NOT NULL
 */
static void _setConfigSessErr(PrgParams* params, int session, 
                                   char* paramName, char* error)
{
  u_int8_t type = (paramName == NULL) ? 0 : 2;
  type +=         (error == NULL)     ? 0 : 1;
  
  switch (type)
  {
    case 1: // paramName == NULL && error != NULL
      sprintf((char*)&params->errMsgBuff, SESS_ERR_2, session, error);
      break;
    case 2: // paramName != NULL && error == NULL
      sprintf((char*)&params->errMsgBuff, SESS_ERR, session, paramName);      
      break;
    case 3: // paramName != NULL && error != NULL
      sprintf((char*)&params->errMsgBuff, SESS_ERR_1, session, paramName, error);      
      break;
    case 0: // paramName == NULL && error == NULL
    default:
      sprintf((char*)&params->errMsgBuff, SESS_ERR_3, session);
      break;
  }  
}

/**
 * Generate the UpdateData instance from the given string in the format given 
 * format prefix[,[as-path]]
 * 
 * @param prefix_path the given path
 * @param params the program params
 * 
 * @return the update data or NULL in case of an error. 
 */
UpdateData* createUpdate(char* prefix_path, PrgParams* params)
{  
  IPPrefix    prefix;
  UpdateData* update = NULL;
  char  pfxStr[IP_STRING];
  char* pathStr   = "\0";
  int   psStrLen  = 0;
  int   pfxStrLen = 0;
  bool  startProcess = true;
  bool  bgp4_only    = false;
  
  memset (&prefix, 0, sizeof(IPPrefix));
  
  // Only if the handed path is not null
  if (prefix_path != NULL)
  {
    // Now find separation of prefix and string
    char* sepPos = strchr(prefix_path, ',');
    
    // Separation found.
    if (sepPos != NULL)
    {
      pfxStrLen = (int)(sepPos - prefix_path);
      
      // Set the pointer to the beginning of the path
      pathStr = sepPos+1;
      // trim all leading tabls and spaces and check if this path is supposed to 
      // be a BGP4 only path
      while (pathStr != NULL && (pathStr[0] == ' ' || pathStr[0] == '\t'))
      {
        pathStr++;
        if (pathStr != NULL && pathStr[0] == 'B')
        {
          if (strlen(pathStr) >= 2)
          {
            if (pathStr[1] == '4')
            {
              pathStr   += 2;
              bgp4_only = true;
            }
          }
        }
      }
      psStrLen  = strlen(pathStr);
    }
    else
    {
      // BUGFIX #923
      if (strchr(prefix_path, ' ') != NULL)
      {
        // What this means is that it is very possible that the ',' is missing.
        // The update might be '1.2.3.4/32 10' but should be '1.2.3.4/32, 10'.
        // The downside is that blanks are only allowed if a separator is found. 
        // But it solves the issue if trying to figure out why updates are
        // not being delivered with the correct path because a comma is missing.
        startProcess = false;
        printf("WARNING: Update '%s' incomplete - separator between prefix and "
               "path is missing!\n", prefix_path);
      }
      pfxStrLen = strlen(prefix_path);
    }
  }
  
  if (startProcess)
  { 
    // BZ892: In case a "," is missing between the configuration of two 
    // independent updates within the configuration script, the pathStr will
    // contain a second prefix. Check for it and if it exists, trigger an error 
    // by setting pfxStrLen to 0 "zero"
    char* slash1 = index(prefix_path, '/');
    char* slash2 = rindex(prefix_path, '/');
    if (slash1 != slash2 || slash1 == NULL)
    {
      pfxStrLen = 0; // Trigger the error.
    }
      
    if (pfxStrLen != 0)  
    { 
      // set the path
      update = malloc(sizeof(UpdateData));
      memset (update, 0, sizeof(UpdateData));
      // Allocate memory for the path string and set the path
      update->pathStr = malloc(psStrLen+1);
      snprintf(update->pathStr, psStrLen+1, "%s", pathStr);
              
      // Now generate the prefix.
        // Copy the prefix into its own string
      memset(&pfxStr, '\0', IP_STRING);
      memcpy(&pfxStr, prefix_path, pfxStrLen);
      memset(&update->prefixTpl, 0, sizeof(BGPSEC_V6Prefix));      
      
      if (strToIPPrefix((char*)&pfxStr, &prefix))
      {
        // the required size to store the padded prefix.
        update->prefixTpl.prefix.safi   = SAFI_UNICAST;
        update->prefixTpl.prefix.length = prefix.length;

        switch (prefix.ip.version)
        {
          case ADDR_IP_V6:
          case AFI_V6:
            update->prefixTpl.prefix.afi = htons(AFI_V6);
            memcpy(update->prefixTpl.addr, prefix.ip.addr.v6.u8, 
                   sizeof(prefix.ip.addr.v6.u8));
            break;
          case ADDR_IP_V4:
          case AFI_V4:
          default:
            update->prefixTpl.prefix.afi = htons(AFI_V4);
            memcpy(update->prefixTpl.addr, prefix.ip.addr.v4.u8, 
                   sizeof(prefix.ip.addr.v4.u8));
            break;
        }        
      }
      else
      { 
        char str[STR_MAX];
        snprintf(str, STR_MAX, "Invalid prefix specification '%s'!", pfxStr);
        _setErrMsg(params, str); 
        freeUpdateData(update);
        update = NULL;
      }
    }
    else
    {
      char str[STR_MAX];
      snprintf(str, STR_MAX, "Invalid path specification '%s'!", prefix_path);
      _setErrMsg(params, str);
    }    
  }
  
  // Find if the AS Path contains an AS_SET in the path
  if (update != NULL)
  {
    char* as_set_start = strchr(update->pathStr, UPD_AS_SET_OPEN);
    char* as_set_stop  = strchr(update->pathStr, UPD_AS_SET_CLOSE);
    if (as_set_start != NULL)
    {
      if (as_set_stop != NULL)
      {
        size_t assetStrlen = (as_set_stop - as_set_start) - 1;
        update->asSetStr = malloc(assetStrlen+1);
        memset(update->asSetStr, '\0', assetStrlen+1);
        // Move over the open sign
        as_set_start++;
        memcpy(update->asSetStr, as_set_start, assetStrlen);
        // move back to original start
        as_set_start--;
        // now wipe the asset clean (including the open and close characters)
        memset (as_set_start, ' ', assetStrlen+2);
        
        
       // Now there should not be any additional AS_SET specification.
       as_set_start = strchr(update->pathStr, UPD_AS_SET_OPEN);
       as_set_stop  = strchr(update->pathStr, UPD_AS_SET_CLOSE);
       if ((as_set_start != NULL) || (as_set_stop != NULL))
       {
          // Should not happen
          char str[STR_MAX];
          snprintf(str, STR_MAX, "Invalid AS_SET specification '%s'!", pathStr);
          _setErrMsg(params, str);        
          freeUpdateData(update);
          update = NULL;
       }
        
      }
      else
      {
        char str[STR_MAX];
        snprintf(str, STR_MAX, "Invalid AS_SET specification '%s'!", pathStr);
        _setErrMsg(params, str);        
        freeUpdateData(update);
        update = NULL;
      }
    }
    else
    {
      if (as_set_stop != NULL)
      {
        char str[STR_MAX];
        snprintf(str, STR_MAX, "Invalid AS_SET specification '%s'!", pathStr);
        _setErrMsg(params, str);        
        freeUpdateData(update);
        update = NULL;        
      }
    }
  }
  
  
  // Find validation state of the update
  if (update != NULL)
  {
    // Initialize the updates validation state.
    update->validation = UPD_RPKI_NONE;
    
    // Check validation state
    char* valstate = strchr(update->pathStr, UPD_RPKI_VALID);
    if (valstate != NULL)
    {
      update->validation = UPD_RPKI_VALID;
      *valstate = ' ';
    }
    else
    {
      valstate = strchr(update->pathStr, UPD_RPKI_INVALID);
      if (valstate != NULL)
      {
        update->validation = UPD_RPKI_INVALID;
        *valstate = ' ';
      }
      else
      {
        valstate = strchr(update->pathStr, UPD_RPKI_NOTFOUND);
        if (valstate != NULL)
        {
          update->validation = UPD_RPKI_NOTFOUND;
          *valstate = ' ';
        }      
      }
    }    
  }
  
  if (update != NULL)
  {
        // Specify if this is a BGP4 only update
    update->bgp4_only = bgp4_only || update->asSetStr != NULL;
  }

  return update;  
}

/**
 * Read the updates from the given configuration list element and push them on
 * the stack. The updates read in are copied into newly allocates strings.
 * These strings will be pushed and need to be freed later by the consumer!!
 * 
 * @param list the configuration list
 * @param stack the stack where to add the updates to 
 * @param params the program parameters - mainly for the error string.
 * 
 * @return true if all updates could be read, otherwise false.
 */
bool _readUpdates(const config_setting_t* updates, Stack* stack, 
                       PrgParams* params)
{
  bool  retVal = updates != NULL && stack != NULL && params != NULL;  
  char* strVal = NULL;
  int   updCt = config_setting_length(updates);
  int   idx;
  
  for (idx = 0; (idx < updCt) && retVal; idx++)
  {
    strVal = (char*)config_setting_get_string_elem(updates, idx);
    if (strVal)
    {
      UpdateData* updateData = createUpdate(strVal, params);
      if (updateData)
      {
        printf ("\nUPATE: %s\n", strVal);
        if (updateData->asSetStr != NULL)
          printf("AS_SET: %s\n", updateData->asSetStr);
        if (updateData->pathStr != NULL)
          printf("AS_SEQUENCE: %s\n", updateData->pathStr);
        fifoPush(stack, updateData);      
      }
      else if (params->errMsgBuff[0] != '\0')
      {
        retVal = false;
      }
    }
  }
  
  return retVal;
}

/**
 * Fill the given address with the correct ip address and port. The port is
 * given in host format but will be stored in network format.
 * 
 * @param ipStr The IPv4 address - will only be set if not NULL
 * @param port The port in host form, will only be set if > 0
 * @param addr The sockaddr_in address that will be filled.
 */
void _setIPAddress(const char* ipStr, u_int16_t port, struct sockaddr_in* addr)
{
  addr->sin_family      = AF_INET;
  if (ipStr != NULL)
  {
    addr->sin_addr.s_addr = inet_addr(ipStr);
  }
  if (port > 0)
  {
    addr->sin_port = htons(port); 
  }
}

/**
 * Fill the given address with the correct IPv6 address and port. The port is
 * given in host format but will be stored in network format.sss
 * 
 * @param ip6Str The IPv6 address - will only be set if not NULL
 * @param port The IPv6 port in host form, will only be set if > 0
 * @param addr The IPv6 sockaddr_in address that will be filled.
 * 
 * @return true if successful, otherwise false.
 */
bool _setIP6Address(const char* ip6Str, u_int16_t port, struct sockaddr_in6* addr)
{
  int ret = 0;
  addr->sin6_family      = AF_INET6;
  if (ip6Str != NULL)
  {
    ret = inet_pton(AF_INET6, ip6Str, &addr->sin6_addr);
  }
  if (port > 0)
  {
    addr->sin6_port = htons(port); 
  }
  
  return ret != 0;
}

/**
 * Read the printer configuration settings.
 * 
 * @param prnFltr The filter configuration
 * @param printOnSR The array for printOnSend or printOnReceive
 */
static void _readPrintSetting(config_setting_t* prnFltr, bool* printOnSR)
{
  static config_setting_t* prnVal;
  
  if (prnFltr != NULL)
  {
    int idx   = 0;
    bool bVal = false;
    // Check if printOnReceive is a one for all setting or a section
    if (config_setting_is_scalar(prnFltr))
    {
      // printOnSend = true|false
      bVal = config_setting_get_bool(prnFltr);
      for (idx = 0; idx < PRNT_MSG_COUNT; idx++)
      {
        printOnSR[idx] = bVal;
      }
    }
    else if (config_setting_is_group(prnFltr))
    {              
      // printOnSend = { open = true|false; update = .... }
      // Initialize all as false then apply the filter setting.
      for (idx = 0; idx < PRNT_MSG_COUNT; idx++)
      {
        printOnSR[idx] = bVal;
      }
      prnVal = config_setting_get_member(prnFltr, P_CFG_PRNFLTR_UPDATE);
      if (prnVal != NULL)
      {
        bVal = config_setting_get_bool(prnVal);
        printOnSR[PRNT_MSG_UPDATE] = bVal;
      }              
      prnVal = config_setting_get_member(prnFltr, P_CFG_PRNFLTR_KEEPALIVE);
      if (prnVal != NULL)
      {
        bVal = config_setting_get_bool(prnVal);
        printOnSR[PRNT_MSG_KEEPALIVE] = bVal;
      }              
      prnVal = config_setting_get_member(prnFltr, P_CFG_PRNFLTR_OPEN);
      if (prnVal != NULL)
      {
        bVal = config_setting_get_bool(prnVal);
        printOnSR[PRNT_MSG_OPEN] = bVal;
      }              
      prnVal = config_setting_get_member(prnFltr, P_CFG_PRNFLTR_NOTIFICATION);
      if (prnVal != NULL)
      {
        bVal = config_setting_get_bool(prnVal);
        printOnSR[PRNT_MSG_NOTIFICATION] = bVal;
      }              
      prnVal = config_setting_get_member(prnFltr, P_CFG_PRNFLTR_UNKNOWN);
      if (prnVal != NULL)
      {
        bVal = config_setting_get_bool(prnVal);
        printOnSR[PRNT_MSG_UNKNOWN] = bVal;
      }              
    }
  }
  
}

/**
 * Read the given configuration file and set the params.
 * 
 * @param params The parameters
 * 
 * @return true if the configuration file could be read.
 */
bool readConfig(PrgParams* params)
{
  static config_t          cfg;
  static config_setting_t* cfgHlp;
  static config_setting_t* session;
  static config_setting_t* sessVal;
  static config_setting_t* updates;

  int sessIdx = 0;

  const char* strVal  = NULL;
  LCONFIG_INT intVal  = 0;
  
  PrgParams*  sParam  = params; // used to allows later on an easy transition to 
                             // multi sessions.
  
  struct stat st;
  if (stat(params->cfgFile, &st) != 0)
  {
    printf ("ERROR: Configuration file '%s' not found!\n", params->cfgFile);
    return false;
  }
 
  // Initialize libconfig
  config_init(&cfg);

  // Try to parse the configuration file
  int cfgFile = config_read_file(&cfg, params->cfgFile);
  if (cfgFile == CONFIG_TRUE)
  {    
    if (config_lookup_string(&cfg, P_CFG_SKI_FILE, &strVal) == CONFIG_TRUE)
    {
      snprintf((char*)&params->skiFName, FNAME_SIZE, "%s", strVal);
    }

    if (config_lookup_string(&cfg, P_CFG_SKI_LOC, &strVal) == CONFIG_TRUE)
    {
      snprintf((char*)params->keyLocation, FNAME_SIZE, "%s", strVal);
    }

    if (config_lookup_string(&cfg, P_CFG_CAPI_CFG, &strVal) == CONFIG_TRUE)
    {
      snprintf((char*)params->capiCfgFileName, FNAME_SIZE, "%s", strVal);
    }
    
    if (config_lookup_string(&cfg, P_CFG_BINFILE, &strVal) == CONFIG_TRUE)
    {
      snprintf((char*)params->binInFile, FNAME_SIZE, "%s", strVal);
    }
    
    if (config_lookup_string(&cfg, P_CFG_OUTFILE, &strVal) == CONFIG_TRUE)
    {
      snprintf((char*)params->binOutFile, FNAME_SIZE, "%s", strVal);
    }
    
    if (config_lookup_bool(&cfg, P_CFG_APPEND_OUT, (int*)&intVal) ==CONFIG_TRUE)
    {
      params->appendOut = (bool)intVal;
    }
    
    if (config_lookup_bool(&cfg, P_CFG_PL_ECKEY, (int*)&intVal) == CONFIG_TRUE)
    {
      params->preloadECKEY = (bool)intVal;
    }
    
    if (config_lookup_bool(&cfg, P_CFG_ONLY_EXTENDED_LENGTH, (int*)&intVal) == CONFIG_TRUE)
    {
      params->onlyExtLength = (bool)intVal;
    }
    
    if (config_lookup_int(&cfg, P_CFG_MAX_UPD, &intVal) == CONFIG_TRUE)
    {
      params->maxUpdates = intVal != 0 ? (u_int32_t)intVal : MAX_UPDATES;
    }
    
    if (config_lookup_bool(&cfg, P_CFG_ONLY_EXTENDED_LENGTH, (int*)&intVal) == CONFIG_TRUE)
    {
      params->onlyExtLength = (bool)intVal;
    }

    if (config_lookup_string(&cfg, P_CFG_TYPE, &strVal) == CONFIG_TRUE)
    {
      if (strcmp(strVal, P_TYPE_BGP) == 0)
      {
        params->type = OPM_BGP;
      } 
      else if (strcmp(strVal, P_TYPE_CAPI) == 0)
      {
        params->type = OPM_CAPI;
      } 
      else if (strcmp(strVal, P_TYPE_GENB) == 0)
      {
        params->type = OPM_GEN_B;
      }
      else if (strcmp(strVal, P_TYPE_GENC) == 0)
      {
        params->type = OPM_GEN_C;
      }
      else
      {
        sprintf(params->errMsgBuff, "Invalid 'type' %s", strVal);        
      }
    }
    
    cfgHlp = config_lookup(&cfg, P_CFG_SESSION);    
    BGP_SessionConf* bgpConf = NULL;
    
    if (cfgHlp && params->errMsgBuff[0] == '\0')
    {
      if (config_setting_is_list(cfgHlp))
      {        
        // Configure all sessions.
        sParam->sessionCount = config_setting_length(cfgHlp);        
        if (sParam->sessionCount > 1)
        {
          if (params->type == OPM_BGP)
          {
            // increase the array to allow holding all sessions
            int extraSize = (sParam->sessionCount-1) * sizeof(BGP_SessionConf*);
            int newSize = sizeof(BGP_SessionConf*) + extraSize;
            sParam->sessionConf = realloc(sParam->sessionConf, newSize);
            // Now allocate and initialize the configuration memory
            for (sessIdx = 1; sessIdx < sParam->sessionCount; sessIdx++)
            {
              sParam->sessionConf[sessIdx] = malloc(sizeof(BGP_SessionConf));
              initBGPSessionConfig(sParam->sessionConf[sessIdx]);
            }
          }
          else
          {
            sParam->sessionCount = 1;
            printf("WARNING: Multiple sessions are only supported in %s mode!\n"
                   "         Ignore all but first configured session!",
                   P_TYPE_BGP);
          }
        }
                
        for (sessIdx = 0; sessIdx < sParam->sessionCount; sessIdx++)
        {
          if (sParam->sessionConf[sessIdx] == NULL)
          {
            _setConfigSessErr(params, sessIdx, NULL,"Session configuration must"
                                                    " be initialized!");
            break;
          }
          bgpConf = sParam->sessionConf[sessIdx];
          
          session = config_setting_get_elem(cfgHlp, sessIdx);
          if (session == NULL)
          {
            _setConfigSessErr(params, sessIdx, NULL,"Session configuration must"
                                                    " not be empty!");
            break;
          }
          
          // My ASN
          sessVal = config_setting_get_member(session, P_CFG_MY_ASN);
          if (sessVal == NULL)
            { _setConfigSessErr(params, sessIdx, P_CFG_MY_ASN, NULL); break; }
          bgpConf->asn = (u_int32_t)config_setting_get_int(sessVal);
          
          // BGP Identifier
          strVal = NULL;
          sessVal = config_setting_get_member(session, P_CFG_BGP_IDENT);
          if (sessVal == NULL)
            { _setConfigSessErr(params, sessIdx, P_CFG_BGP_IDENT, NULL); break;}
          strVal = config_setting_get_string(sessVal);
          if (strVal != NULL)
          {
            struct sockaddr_in ipAddr;
            _setIPAddress(strVal, 0, &ipAddr);
            bgpConf->bgpIdentifier = ipAddr.sin_addr.s_addr;            
          }
          
          // IPv4 Next Hop (Optional - BGP identifier is used if not found)
          sessVal = config_setting_get_member(session, P_CFG_NEXT_HOP_IPV4);
          if (sessVal != NULL)
          {
            strVal = (char*)config_setting_get_string(sessVal);
            // Now set the next hop information (port and address)
            _setIPAddress(strVal, intVal, &bgpConf->nextHopV4);
          }
          else // Use the Own IP as nextHopIPv4
          {
            bgpConf->nextHopV4.sin_addr.s_addr = bgpConf->bgpIdentifier;
            bgpConf->nextHopV4.sin_family      = AF_INET;
            bgpConf->nextHopV4.sin_port        = 0;
          }
          
          // IPv6 Next Hop (Optional - BGP identifier is used if not found)
          sessVal = config_setting_get_member(session, P_CFG_NEXT_HOP_IPV6);
          if (sessVal != NULL)
          {
            strVal = (char*)config_setting_get_string(sessVal);
            // Now set the next hop information (port and address)
            if (!_setIP6Address(strVal, intVal, &bgpConf->nextHopV6))
            { 
              _setConfigSessErr(params, sessIdx, P_CFG_NEXT_HOP_IPV6, 
                                (char*)strVal); 
              break; 
            }
          }
          else
          {
            bgpConf->nextHopV6.sin6_addr.__in6_u.__u6_addr32[0] = 0;
            bgpConf->nextHopV6.sin6_addr.__in6_u.__u6_addr32[1] = 0;
            bgpConf->nextHopV6.sin6_addr.__in6_u.__u6_addr32[2] = 0xFFFF;
            bgpConf->nextHopV6.sin6_addr.__in6_u.__u6_addr32[3] = bgpConf->bgpIdentifier;
            bgpConf->nextHopV6.sin6_family = AF_INET6;
            bgpConf->nextHopV6.sin6_port   = 0;                  
          }
          
          // Session Address
          strVal = NULL;
          sessVal = config_setting_get_member(session, P_CFG_LOCAL_ADDR);
          if (sessVal != NULL)
          {
            strVal = config_setting_get_string(sessVal);
            if (strVal != NULL)
            {
              snprintf(bgpConf->localAddr, IPSTR_LEN, "%s", strVal);
            }
          }
          else
          {
            struct in_addr bgp_ident;
            bgp_ident.s_addr = bgpConf->bgpIdentifier;
            snprintf(bgpConf->localAddr, IPSTR_LEN, "%s", inet_ntoa(bgp_ident));
          }
          
          // The hold timer          
          sessVal = config_setting_get_member(session, P_CFG_HOLD_TIME);
          bgpConf->holdTime = (sessVal == NULL)
                              ? DEF_HOLD_TIME
                              : (u_int32_t)config_setting_get_int(sessVal);
                  
          // The disconnectTime
          sessVal = config_setting_get_member(session, P_CFG_DISCONNECT_TIME);
          bgpConf->disconnectTime = (sessVal == NULL)
                                   ? DEF_DISCONNECT_TIME
                                   : (u_int32_t)config_setting_get_int(sessVal);
          
          // Display convergence data
          sessVal = config_setting_get_member(session, P_CFG_CONVERGENCE);
          if (sessVal != NULL)
          {
            bgpConf->display_convergenceTime = config_setting_get_bool(sessVal);
          }
          
          // Peer AS
          sessVal = config_setting_get_member(session, P_CFG_PEER_AS);
          if (sessVal == NULL)
            { _setConfigSessErr(params, sessIdx, P_CFG_PEER_AS, NULL); break; }
          bgpConf->peerAS = (u_int32_t)config_setting_get_int(sessVal);
          
          // Peer Port 
          sessVal = config_setting_get_member(session, P_CFG_PEER_PORT);
          intVal = (sessVal == NULL) ? DEF_PEER_PORT
                                   : (u_int32_t)config_setting_get_int(sessVal);
          // Peer IP
          sessVal = config_setting_get_member(session, P_CFG_PEER_IP);
          if (sessVal == NULL)
            { _setConfigSessErr(params, sessIdx, P_CFG_PEER_IP, NULL); break; }
          strVal = (char*)config_setting_get_string(sessVal);
          // Now set the peer information (port and address)
          _setIPAddress(strVal, intVal, &bgpConf->peer_addr);

          // Read MPNLRI
          sessVal = config_setting_get_member(session, P_CFG_MPNLRI);
          if (sessVal != NULL)
          {
            bgpConf->useMPNLRI = config_setting_get_bool(sessVal);
            // Added with 0.2.0.2 - This caused invalid packets being send.
            if (!bgpConf->useMPNLRI)
            {
                printf("WARNING: Attribute deprecated!!!\n"
                       "Disabling useMPNLRI will produce invalid "
                       "BGPsec updates - This should only be used for "
                       "test purpose - if at all. This setting will be "
                       "removed in a later update!!\n");
            }
          }
          
          //Read prefixPacking
          sessVal = config_setting_get_member(session, P_CFG_PACKING);
          if (sessVal != NULL)
          {
            bgpConf->prefixPacking = config_setting_get_bool(sessVal);
          }
          
          // Read Ext Message Capability
          sessVal = config_setting_get_member(session, P_CFG_EXT_MSG_CAP);
          if (sessVal != NULL)
          {
            bgpConf->capConf.extMsgSupp = config_setting_get_bool(sessVal);
          }

          // Read Ext Message Capability Liberal Processing
          sessVal = config_setting_get_member(session, P_CFG_EXT_MSG_LIBERAL);
          if (sessVal != NULL)
          {
            bgpConf->capConf.extMsgLiberal = config_setting_get_bool(sessVal);
          }
          
          // Allows to enable forcing to send extended message regardless of
          // capability negotiation. For TESTING PEER ONLY
          sessVal = config_setting_get_member(session, P_CFG_EXT_MSG_FORCE);
          if (sessVal != NULL)
          {
            bgpConf->capConf.extMsgForce = config_setting_get_bool(sessVal);
          }
          
          // Configure the 4 Byte ASN
          sessVal = config_setting_get_member(session, P_CFG_CAP_AS4);
          if (sessVal != NULL)
          {
            bgpConf->capConf.asn_4byte = config_setting_get_bool(sessVal);
          }
          
          // Read BGPSEC Configuration
          // Enable and disable BGPSEC IPv4 Receive          
          sessVal = config_setting_get_member(session, P_CFG_BGPSEC_V4_R);
          if (sessVal != NULL)
          {
            bgpConf->capConf.bgpsec_rcv_v4 = config_setting_get_bool(sessVal);
          }
          // Enable and disable BGPSEC IPv4 Send
          sessVal = config_setting_get_member(session, P_CFG_BGPSEC_V4_S);
          if (sessVal != NULL)
          {
            bgpConf->capConf.bgpsec_snd_v4 = config_setting_get_bool(sessVal);
          }
          // Enable and disable BGPSEC IPv6 Receive
          sessVal = config_setting_get_member(session, P_CFG_BGPSEC_V6_R);
          if (sessVal != NULL)
          {
            bgpConf->capConf.bgpsec_rcv_v6 = config_setting_get_bool(sessVal);
          }
          // Enable and disable BGPSEC IPv6 Send
          sessVal = config_setting_get_member(session, P_CFG_BGPSEC_V6_S);
          if (sessVal != NULL)
          {
            bgpConf->capConf.bgpsec_snd_v6 = config_setting_get_bool(sessVal);
          }

          // Read Algorithm Settings
          // AlgoID
          sessVal = config_setting_get_member(session, P_CFG_ALGO_ID);
          intVal = sessVal == NULL ? DEF_ALGO_ID
                                   : (u_int32_t)config_setting_get_int(sessVal);
          bgpConf->algoParam.algoID = (u_int8_t)intVal;          
          
          sessVal = config_setting_get_member(session, P_CFG_SIG_GENERATION);
          if (sessVal != NULL)
          { // Here we do it a bit different, don't throw an error 
            strVal = (char*)config_setting_get_string(sessVal);
            if (strcmp(strVal, P_TYPE_SIGMODE_CAPI) == 0)
            {
              bgpConf->algoParam.sigGenMode = SM_CAPI;
            }
            else if (strcmp(strVal, P_TYPE_SIGMODE_BIO) == 0)
            {
              bgpConf->algoParam.sigGenMode = SM_BIO;
            }
            else if (strcmp(strVal, P_TYPE_SIGMODE_BIO_K1) == 0)
            {
              bgpConf->algoParam.sigGenMode = SM_BIO_K1;
            }
            else if (strcmp(strVal, P_TYPE_SIGMODE_BIO_K2) == 0)
            {
              bgpConf->algoParam.sigGenMode = SM_BIO_K2;
            }
            else
            {
              sprintf(params->errMsgBuff, "Invalid 'type' %s", strVal);        
            }
          }          
          
          sessVal = config_setting_get_member(session, P_CFG_NULL_SIGNATURE_MODE);
          if (sessVal != NULL)
          { // Here we do it a bit different, don't throw an error 
            strVal = (char*)config_setting_get_string(sessVal);
            if (strcmp(strVal, P_TYPE_NSM_DROP) == 0)
            {
              bgpConf->algoParam.ns_mode = NS_DROP;
            } else if (strcmp(strVal, P_TYPE_NSM_BGP4) == 0)
            {
              bgpConf->algoParam.ns_mode = NS_BGP4;
            } else if (strcmp(strVal, P_TYPE_NSM_BGP_4) == 0)
            { // Inofficial alternative setting for BGP4
              bgpConf->algoParam.ns_mode = NS_BGP4;
            }
            else if (strcmp(strVal, P_TYPE_NSM_FAKE) == 0)
            {
              bgpConf->algoParam.ns_mode = NS_FAKE;

              sessVal = config_setting_get_member(session, P_CFG_FAKE_SIGNATURE);
              if (sessVal == NULL)          
                { _setConfigSessErr(params, sessIdx, P_CFG_FAKE_SIGNATURE, NULL); break; }
              strVal = (char*)config_setting_get_string(sessVal);
              intVal = (u_int8_t)strlen(strVal);
              intVal = au_hexStrToBin((char*)strVal, 
                       bgpConf->algoParam.fake_signature, 
                       intVal < MAX_SIG_BYTE_SIZE ? intVal : MAX_SIG_BYTE_SIZE);
              bgpConf->algoParam.fake_sigLen = (u_int8_t)intVal;

              sessVal = config_setting_get_member(session, P_CFG_FAKE_SKI);
              if (sessVal == NULL)          
                { _setConfigSessErr(params, sessIdx, P_CFG_FAKE_SKI, NULL); break; }
              strVal = (char*)config_setting_get_string(sessVal);
              intVal = au_hexStrToBin((char*)strVal, 
                                      bgpConf->algoParam.fake_key.ski, 
                                      SKI_HEX_LENGTH);
            } 
            else
            {
              sprintf(params->errMsgBuff, "Invalid 'type' %s", strVal);        
            }
          }

          
          // Read print on receive and turn on or off all of them
          sessVal = config_setting_get_member(session, P_CFG_PRINT_ON_RECEIVE);
          _readPrintSetting(sessVal, bgpConf->printOnReceive);

          // Read print on send and turn on or off all of them
          sessVal = config_setting_get_member(session, P_CFG_PRINT_ON_SEND);
          _readPrintSetting(sessVal, bgpConf->printOnSend);
          
          // Read printSimple value
          sessVal = config_setting_get_member(session, P_CFG_PRINT_SIMPLE);
          if (sessVal != NULL)
          {
            bgpConf->printSimple = config_setting_get_bool(sessVal);
          }

          // Read print poll loop
          sessVal = config_setting_get_member(session, P_CFG_PRINT_POLL_LOOP);
          if (sessVal != NULL)
          {
            bgpConf->printPollLoop = config_setting_get_bool(sessVal);
          }

          // Read print status on invalid
          sessVal = config_setting_get_member(session, 
                                              P_CFG_PRINT_CAPI_ON_INVALID);
          if (sessVal != NULL)
          {
            bgpConf->printOnInvalid = config_setting_get_bool(sessVal);
          }
          
          // Read session Updates
          initStack(&bgpConf->updateStack);
          updates = config_setting_get_member(session, P_CFG_UPD_PARAM);
          if (updates)
          {
            if (config_setting_is_list(updates))
            {
              _readUpdates(updates, &bgpConf->updateStack, params);
            }
            else
            {
              _setConfigSessErr(params, sessIdx, P_CFG_UPD_PARAM, 
                              " must be a comma separated list!!!");
              break;
            }
          }
// TODO: Check if this is needed. It came from code merger
//       I believe the global updates are handled elsewhere in this version.          
          // Now check if global updates should be added to this session.
          // enabled by default.
          sessVal = config_setting_get_member(session,
                                              P_CFG_INCL_GLOBAL_UPDATES);
          if (sessVal != NULL)
          { bgpConf->inclGlobalUpdates = config_setting_get_bool(sessVal);           }
// END-TODO
        }
      }
    
      if (params->errMsgBuff[0] == '\0')
      {
        // Now read global updates
        updates = config_lookup(&cfg, P_CFG_UPD_PARAM);
        if (updates)
        {
          if (config_setting_is_list(updates))
          {
            // @TODO: (updateStack) This should be a global updateStack and then
            //        the stack must be copied into each session. (Maybe copy 
            //        into each session != session==0 and then moved into 
            //        session==0 
            _readUpdates(updates, &params->globalUpdateStack, params);
          }
          else
          {
            _setConfigSessErr(params, sessIdx, P_CFG_UPD_PARAM, 
                              " must be a comma separated list!!!");
          }
        }
      }
    }
  }
  else
  {
    sprintf(params->errMsgBuff, "Error in configuration[%i]: '%s'%c", 
            cfg.error_line, cfg.error_text, '\0');
  }

  config_destroy(&cfg);

  return true;
}

/**
 * Initialize the params and set default values. Here we also set the default 
 * capabilities we provide (such as send bgpsec V4 and V6)
 * 
 * @param params The parameters object.
 * 
 */
void initParams(PrgParams* params)
{
  int idx;
  memset(params, 0, sizeof(PrgParams));
  
  // Now initialize what should not be 0 - false - NULL
  snprintf((char*)&params->skiFName, FNAME_SIZE, "%s", DEF_SKIFILE);
  snprintf((char*)&params->keyLocation, FNAME_SIZE, "%s", DEF_KEYLOCATION);
  
  // The sessions will be generated in the read file function .
  params->sessionConf       = malloc(sizeof(BGP_SessionConf*));
  params->sessionConf[0]    = malloc(sizeof(BGP_SessionConf));
  params->sessionCount      = 1;
  initBGPSessionConfig(params->sessionConf[0]);
          
  params->preloadECKEY                = true;
  params->onlyExtLength               = true;
  params->appendOut                   = false;

// TODO: below is merger code - maybe not needed
//  params->bgpConf.printPollLoop       = false;
//  params->bgpConf.printOnInvalid      = false;
//  for (idx = 0; idx < PRNT_MSG_COUNT; idx++)
//  {
//    params->bgpConf.printOnSend[idx]    = false;
//    params->bgpConf.printOnReceive[idx] = false;
//  }
// TODO: END MERGER CODE
 
  params->maxUpdates = MAX_UPDATES;

// TODO: Also Check this merger code below
//  memset(&params->bgpConf.algoParam, 0, sizeof (AlgoParam)); 
//  // The following line is normally not needed, I just add it in case the SM_BIO
//  // value will be modified and SM_BIO is the default value.
//  params->bgpConf.algoParam.sigGenMode = SM_BIO;
//  
//  // Set all capabilities to true
//  memset(&params->bgpConf.capConf, 1, sizeof(BGP_Cap_Conf));
//  // Turn capabilities selectively off
//  params->bgpConf.capConf.route_refresh = false;
//  // Turn capabilities selectively off
//
//  // Turn off TEST setting for forcing ext message sending without ext 
//  // capability being negotiated
//  params->bgpConf.capConf.extMsgForce = false;
//  
// TODO: END
  
  // Needed for global scripted updates
  initStack(&params->globalUpdateStack);
}

/**
 * Parse the given program parameter
 * 
 * @param params Stores the settings found in the program arguments
 * @param argc The number of arguments
 * @param argv the array containing the program arguments
 * 
 * @return 1 for success, 0 for stop (help), -1 for error
 */
int parseParams(PrgParams* params, int argc, char** argv)
{
  // Set the default parameters.  
  // Read Parameters
  int idx = 1;
  UpdateData* update = NULL;
  int retVal = 1;
  bool loadCfgScript = false;
  BGP_SessionConf* bgpConf = NULL;

  // first check for help
  while (idx < argc && params->errMsgBuff[0] == '\0')
  {
    switch (getShortParam(argv[idx]))
    {
      case P_C_HELP:
      case P_C_HELP_1:
      case P_C_HELP_2:
        printSyntax();
        idx = argc;
        retVal = 0;
        break;
      case P_C_VERSION:
        printVersion();
        retVal = 0;
        break;
      case P_C_CONFIG:
        // check here speeds up the rest.
        if (++idx >= argc) 
          { _setErrMsg(params, "Configuration file not specified!"); break; }
        loadCfgScript = true;
        sprintf((char*)&params->cfgFile, "%s%c", argv[idx], '\0');
        idx = argc; // skip the rest of the loop.
        break;        
      default:
        break;
    }    
    idx++;
  }
  
  // first check for configuration file - skip all parameters except the 
  // configuration file.
  if (loadCfgScript && (retVal == 1))
  {
    // Load the configuration file.s
    if (!readConfig(params) && params->errMsgBuff[0] == '\0')
    {
      sprintf((char*)&params->errMsgBuff, 
              "Error while processing configuration file %s'%c", 
              params->cfgFile, '\0');        
    }
  }

  // Now parse again the parameters but skip the configuration file this time
  idx = 1;
  bgpConf = params->sessionConf[0];
  while (idx < argc && params->errMsgBuff[0] == '\0')
  {
    // First check the long letter parameters:
    update = NULL; // need to set to null to indicate a free in case of an error
    switch (getShortParam(argv[idx]))
    {
      case P_C_CONFIG:
        idx++; // needed to skip the configuration file name.
      case P_C_HELP:
      case P_C_HELP_1:
      case P_C_HELP_2:
      case P_C_VERSION:
        // skip this one, was already processed.
        break;
        
      case P_C_UPD_PARAM:
        if (++idx >= argc) 
          { _setErrMsg(params, "Not enough Parameters!"); break; }      

        update = createUpdate(argv[idx], params);
        if (update != NULL)
        {  
          // Use fifo put to allow the updates to be send in the order read. 
          fifoPush(&params->paramUpdateStack, update);
          update = NULL; // Update is stored in stack
        }
        break;

      case P_C_SKI_FILE:
        if (++idx >= argc) 
          { _setErrMsg(params, "SKI file not specified!"); break; }
        sprintf((char*)&params->skiFName, "%s\n", argv[idx]);
        break;

      case P_C_SKI_LOC:
        if (++idx >= argc) 
          { _setErrMsg(params, "Key location not specified!"); break; }
        sprintf((char*)&params->keyLocation, "%s%c", argv[idx], '\0'); 
        break;

      case P_C_CAPI_CFG:
        if (++idx >= argc) 
          { _setErrMsg(params, "SrxCryptoAPI configfile not specified!"); break; }
        sprintf((char*)&params->capiCfgFileName, "%s\n", argv[idx]);
        break;
        
      case P_C_TYPE:
        if (++idx >= argc) 
          { _setErrMsg(params, "Type missing!"); break; }
        if (strcmp(argv[idx], P_TYPE_BGP) == 0)
        {
          params->type = OPM_BGP;
        }
        else if (strcmp(argv[idx], P_TYPE_CAPI) == 0)
        {
          params->type = OPM_CAPI;          
        }
        else if (strcmp(argv[idx], P_TYPE_GENB) == 0)
        {
          params->type = OPM_GEN_B;          
        }
        else if (strcmp(argv[idx], P_TYPE_GENC) == 0)
        {
          params->type = OPM_GEN_C;          
        }
        else { _setErrMsg(params, "Invalid running type!"); break; }          
        break;
        
      case P_C_MAX_UPD:
        if (++idx >= argc) 
          { _setErrMsg(params, "Maximum number of updates missing!"); break; }
        params->maxUpdates = atoi(argv[idx]);
        if (params->maxUpdates == 0)
        {
          params->maxUpdates = MAX_UPDATES;
        }
        break;        

      case P_C_MY_ASN:
        if (++idx >= argc) 
          { _setErrMsg(params, "Own AS number missing!"); break; }
        bgpConf->asn = atoi(argv[idx]);
        break;

      case P_C_BGP_IDENT:
        if (++idx >= argc) 
          { _setErrMsg(params, "BGP Identifier missing!"); break; }
        struct sockaddr_in ipAddr;
        _setIPAddress(argv[idx], 0, &ipAddr);
        bgpConf->bgpIdentifier = ipAddr.sin_addr.s_addr;
        break;

      case P_C_PEER_AS:
        if (++idx >= argc) 
        { _setErrMsg(params, "Peer AS not specified!"); break; }
        bgpConf->peerAS = atoi(argv[idx]);
        break;

      case P_C_NEXT_HOP_IPV4:
        if (++idx >= argc) 
          { _setErrMsg(params, "Next Hop IPv4 not specified!"); break; }
        _setIPAddress(argv[idx], 0, &bgpConf->nextHopV4);
        break;
        
      case P_C_NEXT_HOP_IPV6:
        if (++idx >= argc) 
          { _setErrMsg(params, "Next Hop IPv6 not specified!"); break; }
        _setIP6Address(argv[idx], 0, &bgpConf->nextHopV6);
        break;
        
      case P_C_PEER_IP:
        if (++idx >= argc) 
          { _setErrMsg(params, "Peer IP not specified!"); break; }
        _setIPAddress(argv[idx], 0, &bgpConf->peer_addr);
        break;
        
      case P_C_PEER_PORT:
        if (++idx >= argc) 
        { _setErrMsg(params, "Peer port not specified!"); break; }
        _setIPAddress(NULL, atoi(argv[idx]), &bgpConf->peer_addr);
        break;
        
      case P_C_NO_MPNLRI:
        bgpConf->useMPNLRI = false;
        break;
        
      case P_C_NO_EXT_MSG_CAP:
        bgpConf->capConf.extMsgSupp = false;
        break;

      case P_C_NO_EXT_MSG_LIBERAL:
        bgpConf->capConf.extMsgLiberal = false;
        break;
        
      case P_C_NO_PL_ECKEY:
        params->preloadECKEY = false;
        break;
        
      case P_C_DISCONNECT_TIME:
        if (++idx >= argc) 
        { _setErrMsg(params, "Disconnect time not specified!"); break; }
        bgpConf->disconnectTime = atoi(argv[idx]);
        break;
        
      case P_C_CONVERGENCE:
        bgpConf->display_convergenceTime = true;
        break;
        
      case P_C_OUTFILE:
        if (++idx >= argc) 
          { _setErrMsg(params, "Filename for out file missing!"); break; }
        snprintf((char*)&params->binOutFile, FNAME_SIZE, "%s", argv[idx]);
        break;
        
      case P_C_APPEND_OUT:
        params->appendOut = true;
        break;        
        
      case P_C_BINFILE:
        if (++idx >= argc) 
          { _setErrMsg(params, "Filename for binary in-file missing!"); break; }
        snprintf((char*)&params->binInFile, FNAME_SIZE, "%s", argv[idx]);
        break;
        
      case P_C_CREATE_CFG_FILE:
        if (++idx >= argc) 
          { _setErrMsg(params, "Filename for config file missing!"); break; }
        snprintf((char*)&params->newCfgFileName, FNAME_SIZE, "%s", argv[idx]);
        params->createCfgFile = true;
        break;
        
      case P_C_IFACE:
        if (++idx >= argc) 
          { _setErrMsg(params, "Interface name missing!"); break; }
        snprintf((char*)&params->iface, IFACE_STRING, "%s", argv[idx]);
        break;
                   
      default:
        // Some parameters do only have a -- setting and no single char option
        if (strcmp(argv[idx], P_EXT_MSG_FORCE) == 0)
        {
          bgpConf->capConf.extMsgForce = true;
        }
        else
        {
          snprintf(params->errMsgBuff, PARAM_ERRBUF_SIZE, 
                   "Unknown Parameter '%s'!", argv[idx]);
          idx = argc; // stop further processing.
          printSyntax();
        }
    }
    
    // something went wrong during the update processing, free the leftover
    if (update != NULL)
    {
      freeUpdateData(update);
    }

    idx++;
  }

  // Assure that interface configuration is only set in combination with -C
  if ((strlen(params->iface) > 0) && !params->createCfgFile)
  {
    _setErrMsg(params, "The parameter -n is only allowed for configuration "
                       "file generation (-C <cfgFile>)!!");
  }

  if (params->errMsgBuff[0] != '\0')
  {
    retVal = -1;
  }
  
  return retVal;
}

/** 
 * free the Update data parsed from program parameters. 
 * 
 * @param update The update parameter that has to be freed.
 */
void freeUpdateData(void* upd)
{ 
  if (upd != NULL)
  {
    UpdateData* update = (UpdateData*)upd;
    if (update->pathStr != NULL)
    {
      free(update->pathStr);
      update->pathStr = NULL;
    }
    if (update->asSetStr != NULL)
    {
      free(update->asSetStr);
      update->asSetStr = NULL;
    }
    free(upd);
  }
}

/**
 * Remove all memory allocated within the params structure and set all 
 * allocated memory to "0". If desired free will be called on params as well. 
 * 
 * @param params the params instance
 * @param doFree if true the memory will be freed as well
 */
void cleanupParams(PrgParams* params, bool doFree)
{
  int sessionIdx;
  BGP_SessionConf* sessionConf = NULL;
  List* lst = NULL;
  
  // clean global update stack
  if (!isStackEmpty(&params->globalUpdateStack))
  {
    emptyList((List*)&params->globalUpdateStack, true, freeUpdateData);
  }
  // clean all session update stacks 
  for (sessionIdx = 0; sessionIdx < params->sessionCount; sessionIdx++)
  {
    sessionConf = params->sessionConf[sessionIdx];
    
    if (sessionConf != NULL)
    {
      lst = (List*)&sessionConf->updateStack;
      if (lst != NULL)
      {
        emptyList(lst, true, freeUpdateData);
      }
      memset (sessionConf, 0, sizeof(BGP_SessionConf));
      free(sessionConf);
      sessionConf = NULL;
      params->sessionConf[sessionIdx] = NULL;
    }
  }  
  free(params->sessionConf);
          
  // Set all parameter values to 0 'zero' / NULL
  memset(params, 0, sizeof(PrgParams));
  
  if (doFree)
  {
    free(params);
  }
}
