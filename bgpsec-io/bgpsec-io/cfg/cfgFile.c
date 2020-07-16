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
 * cfgFile allows to generate a fully functional sample configuration file
 * for BGPSEC-IO
 * 
 * @version 0.2.1.0
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.1.0 - 2018/11/29 - oborchert
 *            * Removed merge comments in version control.
 *          - 2018/01/16 - oborchert
 *            * Added prefix packing to configuration.
 *            * Added missing semicolons to second session in auto generated 
 *              configuration. 
 *          - 2018/01/09 - oborchert
 *            * Added minimum configuration to second session configuration.
 *          - 2017/12/13 - oborchert
 *            * Modified the parameter list of generateFile.
 *          - 2017/12/11 - oborchert
 *            * Modified function generateFile and added interface name to 
 *              parameter list.
 *            * Added function retrieveIPAddr(...)
 *            * Added capability to specify the interface to get the IP address
 *              configuration. 
 *            * Prepares capability to do the same with peer IP and AS numbers.
 *          - 2017/12/05 - oborchert
 *            * Replaced interface binding with outgoing IP address binding.
 *              (does not require elevated privileges - better solution)
 *            * Added example for BGP4 only update.
 *          - 2017/11/21 - oborchert
 *            * Added interface binding.
 * 0.2.0.21 - 2018/06/08 - oborchert
 *            * Added parameter "convergence" to the configuration.
 * 0.2.0.16 - 2018/04/21 - oborchert
 *            * Added regular expression as syntax helper for update scripting.
 * 0.2.0.13 - 2018/04/17 - oborchert
 *            * Fixed some minor issues like spelling and formatting in 
 *              configuration file generation.
 * 0.2.0.12 - 2018/04/15 - oborchert
 *            * Added P_CFG_PRINT_SIMPLE to configuration file generation.  
 * 0.2.0.11 - 2018/03/22 - oborchert
 *            * Added configuration to enable/disable as4 capability.
 *          - 2018/03/21 - oborchert
 *            * Added parameter to enable/disable adding global updates to 
 *              session.
 *  0.2.0.7 - 2017/03/17 - oborchert
 *            * Fixed speller in generated configuration.
 *          - 2017/03/15 - oborchert
 *            * BZ1114 : Removed extra empty lines
 *            * Modified print filter setting.
 *          - (branch) 2017/02/07 - oborchert
 *            * Added missing IPv6 next hop. Also added alternative IPv4 next 
 *              next hop in the same effort.
 *            * Added printout filter configuration.
 *  0.2.0.6 - 2017/02/15 - oborchert
 *            * Added switch to force sending extended messages regardless if
 *              capability is negotiated. This is a TEST setting only.
 *          - 2017/02/15 - oborchert
 *            * Added ext_msg_liberal to generation of example configuration
 *          - 2017/02/13 - oborchert
 *            * Renamed define from ..._EXTMSG_SIZE to EXT_MSG_CAP
 *            * BZ1111: Added liberal policy to extended message capability 
 *              processing
 *  0.2.0.5 - 2017/02/01 - oborchert
 *            * Removed quotes from true values. The configuration does not read
 *              understand quotes in boolean values.
 *          - 2017/01/31 - oborchert
 *            * Fixed some configuration documentation spellers.
 *            * Added missing extended message size capability configuration.
 *            * Added configuration to selectively enable/disable bgpsec
 *          - 2017/01/11 - oborchert
 *            * Fixed invalid type for signature_generation to use "BIO" 
 *              (P_TYPE_SIGMODE_BIO) as default type. (BZ:1066)
 *          - 2017/01/03 - oborchert
 *            * Adjusted fake signature in template generation to be 70 bytes 
 *              long.
 *            * Added switch to allow selecting the signature mode.
 *          - 2016/11/31 - oborchert
 *            * Updated the fake signature and fake SKI to a more readable hex 
 *              stream.
 *          - 2016/11/15 - oborchert
 *            * Added parameter onlyExtLength
 *  0.2.0.2 - 2016/06/29 - oborchert
 *            * Fixed usage of invalid algorithm ID in auto generation. (BZ997)
 *            * Added check if file exists already (BZ996)
 *          - 2016/06/28 - oborchert
 *            * Removed the generation of useMPNLRI  
 *  0.2.0.0 - 2016/05/13 - oborchert
 *            * Added maximum number of updates to be processed '-M'.
 *          - 2016/05/11 - oborchert
 *            * Removed duplicate syntax (copy past error)
 *            * Added missing semicolon in generated configuration file.
 *          - 2016/05/10 - oborchert
 *            * BZ955: Added generation of "asn" and "capi_cfg" to configuration
 *              generation.
 *          - 2016/05/06 - oborchert
 *            * Added generation of "capi_cfg" parameter.
 *  0.1.1.0 - 2016/05/03 - oborchert
 *            * Added appendOut.
 *          - 2016/04/29 - oborchert
 *            * Modified signature of function generateFile by removing the 
 *              program Parameters. The generated file is a sample configuration
 *              containing all possible settings.
 *            * Updated to reflect latest configuration settings.
 *  0.1.0.0 - 2015/11/29 - oborchert
 *            * Created File.
 */

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <ifaddrs.h>
#include "configuration.h"
#include "antd-util/prefix.h"
#include "cfg/cfgFile.h"
#include "cfg/configuration.h"

/**
 * This function stores the IP address assigned to the particular interface
 * to the given addrStr (0.0.0.0) if interface is not found.
 * 
 * @param iface The name of the interface
 * @param v4Addr An existing character buffer where the IPv4 address will be 
 *               written into.
 * @param v6Addr An existing character buffer where the IPv6 address will be 
 *               written into.
 * 
 * @return true if at least one address could be assigned, otherwise false.
 */
static bool retrieveIPAddr(char* iface, char* v4Addr, char* v6Addr)
{
  bool retVal = false;
  
  struct ifaddrs *ifAddr = NULL;
  struct ifaddrs *ifa    = NULL;
  void   *ptr            = NULL;
  
  if ((iface != NULL ) && (v4Addr != NULL) && (v6Addr != NULL))
  {
    // Set the strings to zero length
    v4Addr[0] = '\0';
    v6Addr[0] = '\0';
    
    getifaddrs(&ifAddr);
    
    for (ifa = ifAddr; ifa != NULL; ifa = ifa->ifa_next)
    {
      // check if the strings are same
      if (   (strlen(ifa->ifa_name) == strlen(iface)) 
          && (strcasecmp(ifa->ifa_name, iface) == 0))
      {
        // Check if IPv4
        switch (ifa->ifa_addr->sa_family)
        {
          case AF_INET:
            ptr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            inet_ntop(AF_INET, ptr, v4Addr, INET_ADDRSTRLEN);
            retVal = true;
            break;
          case AF_INET6:
            ptr = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
            inet_ntop(AF_INET6, ptr, v6Addr, INET6_ADDRSTRLEN);
            retVal = true;
            break;
          default:
            // Unsupported, move on...
            break;
        }
      }
    }
    
    if (ifAddr != NULL)
    {
      freeifaddrs(ifAddr);
      ifAddr = NULL;
    }
  }
  
  return retVal;
}

/**
 * Generate an example configuration file. In case no interface name "iface" is 
 * provided, the address used is CFG_DEF_IPV4 (10.0.1.64) otherwise the address 
 * bound to the interface.
 * 
 * @param fName The name of the configuration file.
 * @param iface The name of the local interface the file will be configured for.
 * @param localASN  The AS number of the local host (> 0).
 * @param peerIP The peer IP address (MUST NOT be NULL). 
 * @param peerASN The peer as number (> 0).
 * 
 * @return true if the file could be generated, false if no name was given or 
 *              the file already exists.
 */
bool generateFile(char* fName, char* iface, u_int32_t localASN, 
                  char* peerIP, u_int32_t peerASN)
{  
  if ((fName == NULL) || (peerIP == NULL) || (localASN == 0) || (peerASN == 0))
  {
    return false;
  }
  
  if ( access(fName, F_OK) != -1 )
  {
    // File exists
    return false;
  }
  
   // This variable will contain the IPv4 address used for the local address.
  char localIPv4Addr[IP_STRING];
  memset (&localIPv4Addr, 0, IP_STRING);
  
  // This variable will contain the IPv6 address used for the local address.  
  char localIPv6Addr[IP_STRING];
  memset (&localIPv6Addr, 0, IP_STRING);
      
  retrieveIPAddr(iface, localIPv4Addr, localIPv6Addr);
          
  // Verify if IPv4 Address is set, otherwise set it
  if (strlen(localIPv4Addr) == 0)
  {
    snprintf(localIPv4Addr, IP_STRING, "%s", DEF_IPV4);
  }
  
  // Verify if IPv6 Address is set, otherwise use IPv4 address to set it
  if (strlen(localIPv6Addr) == 0)
  {
    char* ptr = (char*)localIPv6Addr;
    ptr += snprintf(localIPv6Addr, IP_STRING, "%s", DEF_V4_V6_PREFIX);
    struct in_addr ipv4Addr;    
    inet_aton(localIPv4Addr, &ipv4Addr);
    u_int32_t  ipv4  = ntohl(ipv4Addr.s_addr);
    u_int16_t* words = (u_int16_t*)&ipv4;
    snprintf(ptr, IP_STRING-strlen(localIPv6Addr), "%x:%x", words[1], words[0]);
  }  

  FILE* file = fopen(fName, "w");
  if (file)
  {
    fprintf (file, "#BGPSEC-IO Configuration file. Auto generated by %s %s\n\n", 
                  PRG_NAME, PRG_VERSION);
    fprintf (file, "%s    = \"%s\";\n", P_CFG_SKI_FILE, DEF_SKIFILE);
    fprintf (file, "%s = \"%s\";\n\n", P_CFG_SKI_LOC, DEF_KEYLOCATION);

    fprintf (file, "%s = false;\n\n", P_CFG_PL_ECKEY);
    
    fprintf (file, "# Choose from the following types \"%s\", \"%s\", \"%s\", "
                   "and \"%s\"\n",
                   P_TYPE_BGP, P_TYPE_CAPI, P_TYPE_GENB, P_TYPE_GENC);
    fprintf (file, "%s = \"%s\";\n", P_CFG_TYPE, P_TYPE_BGP);
    // Max number up updates
    fprintf (file, "# Maximum combined number of updates to process. Script 0 "
                   "for MAX INT\n");
    fprintf (file, "%s = 0;\n\n", P_CFG_MAX_UPD);
    
    // Force Extended flag being set.
    fprintf (file, "# Allow to force the usage of the flag for extended length "
                   "being set. \n");
    fprintf (file, "%s = true;\n\n", P_CFG_ONLY_EXTENDED_LENGTH);    
    
    // infile
    fprintf (file, "# %s = \"<binary input file>\";\n", P_CFG_BINFILE);
    
    // Outfile
    fprintf (file, "# %s = \"<binary output file>\";\n", P_CFG_OUTFILE);
    
    // appendOut
    fprintf (file, "# Append data to the out file.\n");  
    fprintf (file, "%s = \"false\";\n\n", P_CFG_APPEND_OUT);
    
    // capi_cfg
    fprintf (file, "# Allow to specify a configuration file for srx-crypto-api,"
                   "If this is not specified,\n");
    fprintf (file, "# the default srx-crypto-api configuration (determined by "
                   "the API) will be used.\n");
    fprintf (file, "#%s = \"<configuration file>\";\n\n", P_CFG_CAPI_CFG);
       
    // Create the session information
    fprintf (file, "# Multiple sessions possible (at a later time)\n");
    fprintf (file, "session = (\n");
    fprintf (file, "  {\n");
    fprintf (file, "    %s        = %u;\n", P_CFG_MY_ASN, localASN);
    fprintf (file, "    %s  = \"%s\";\n", P_CFG_BGP_IDENT, localIPv4Addr);
    fprintf (file, "    %s = 180;\n\n", P_CFG_HOLD_TIME);
       
    fprintf (file, "    # Allows to specify specific session IP.\n");
    fprintf (file, "    # If not specified, the %s value is used!\n", 
             P_CFG_BGP_IDENT);
    fprintf (file, "    #%s = \"%s\";\n\n", P_CFG_LOCAL_ADDR, localIPv4Addr);    
    
    fprintf (file, "    # Allows to specify next hop address. If not,\n");
    fprintf (file, "    # specified the bgp identifier is used instead!\n");
    fprintf (file, "    #%s = \"%s\";\n", P_CFG_NEXT_HOP_IPV4, localIPv4Addr);
    fprintf (file, "    # Required for sending IPv6 updates.\n");     
    fprintf (file, "    #%s = \"%s\";\n\n", P_CFG_NEXT_HOP_IPV6, localIPv6Addr);

    fprintf (file, "    %s   = %u;\n", P_CFG_PEER_AS, peerASN);
    fprintf (file, "    %s    = \"%s\";\n", P_CFG_PEER_IP, peerIP);
    fprintf (file, "    %s  = 179;\n\n", P_CFG_PEER_PORT);

    fprintf (file, "    # Run forever or until the peer shuts down.\n");
    fprintf (file, "    %s = 0;\n\n", P_CFG_DISCONNECT_TIME);
    
    fprintf (file, "    # Enable BGP convergence measurement framework.\n");
    fprintf (file, "    %s = false;\n\n", P_CFG_CONVERGENCE);
    
    fprintf (file, "    # Allow to enable/disable extended message capability."
                          "\n");
    fprintf (file, "    %s = true;\n", P_CFG_EXT_MSG_CAP);
    fprintf (file, "    # Allow to enable/disable liberal behavior when \n");
    fprintf (file, "    # receiving extended message capability.\n");
    fprintf (file, "    %s = true;\n", P_CFG_EXT_MSG_LIBERAL);
    fprintf (file, "    # Overwrite draft / RFC specification and force.\n");
    fprintf (file, "    # sending extended message regardless if negotiated or "
                        "not.\n");
    fprintf (file, "    #%s = true;\n\n", P_CFG_EXT_MSG_FORCE);

    fprintf (file, "    # Configure BGP capabilities.\n");
    fprintf (file, "    #%s = true;\n\n", P_CFG_CAP_AS4);

    fprintf (file, "    # Configure BGPSEC capabilities.\n");
    fprintf (file, "    %s = true;\n", P_CFG_BGPSEC_V4_S);
    fprintf (file, "    %s = true;\n", P_CFG_BGPSEC_V4_R);
    fprintf (file, "    %s = true;\n", P_CFG_BGPSEC_V6_S);
    fprintf (file, "    %s = true;\n\n", P_CFG_BGPSEC_V6_R);
    
    fprintf (file, "    # Updates for this session only\n");
    fprintf (file, "    # (path prefix B4 specifies BGP4 only update!)\n");
    fprintf (file, "    # <prefix>[,[[B4]? <asn>[p<repitition>]]*[ ]*[I|V|N]?]\n");
    fprintf (file, "    %s = (  \"%s\"\n", P_CFG_UPD_PARAM, 
                                                    "10.0.0.0/24");
    fprintf (file, "              , \"%s, %s\"\n", "10.1.0.0/24", 
                                                               "B4 10 20p3 30");
    fprintf (file, "              , \"%s, %s\"\n", "10.0.1.0/24", "10 20p3 30");
    fprintf (file, "              , \"%s, %s\"\n", "10.0.2.0/24", "10 20 40 50");
    fprintf (file, "              , \"%s, %s\"\n", "10.0.3.0/24", "10 20 60 70V");
    fprintf (file, "             );\n\n");
    fprintf (file, "    # Enable/Disable adding global updates to this session."
                                                                          "\n");
    fprintf (file, "    %s = %s;\n\n", P_CFG_INCL_GLOBAL_UPDATES, 
                                       DEF_INCL_GLOBAL_UPDATE ? "true" 
                                                              : "false");
    
// Removed this parameter from being added in default configuration. It will 
// be completely removed in future revisions and was only needed during the 
// draft13 -> draft15 merger.  
//    fprintf (file, "    #%s = true;\n\n", P_CFG_MPNLRI);
    
    fprintf (file, "    # Allow prefix packing for BGP4 scripted updates\n");
    fprintf (file, "    # where ever possible.\n");
    fprintf (file, "    %s = false;\n\n", P_CFG_PACKING);
        
    fprintf (file, "    %s = %u;\n\n", P_CFG_ALGO_ID, P_CFG_ALGO_ID_DEF_VAL);
    
    fprintf (file, "    # Choose from the following signature modes (%s|%s|%s|"
                   "%s)\n", P_TYPE_SIGMODE_CAPI, P_TYPE_SIGMODE_BIO, 
                   P_TYPE_SIGMODE_BIO_K1, P_TYPE_SIGMODE_BIO_K2);
            
    fprintf (file, "    %s = \"%s\";\n\n", P_CFG_SIG_GENERATION, P_TYPE_SIGMODE_BIO);
    
    fprintf (file, "    #In case the signature generation does fail, the\n");
    fprintf (file, "    #following settings are possible (%s| %s| %s)\n",
             P_TYPE_NSM_DROP, P_TYPE_NSM_FAKE, P_TYPE_NSM_BGP4);
    fprintf (file, "    %s = \"%s\";\n", P_CFG_NULL_SIGNATURE_MODE, 
                                        P_TYPE_NSM_FAKE);

    char* fakeTab = "                          \0";
    char* fakeSig = "BADBEEFDEADFEED\0";    
    fprintf (file, "    %s      = \"1%s\" \"2%s\"\n", P_CFG_FAKE_SIGNATURE, 
             fakeSig, fakeSig);
      fprintf (file, "%s\"3%s\" \"4%s\"\n", fakeTab, fakeSig, fakeSig);
      fprintf (file, "%s\"5%s\" \"6%s\"\n", fakeTab, fakeSig, fakeSig);
      fprintf (file, "%s\"7%s\" \"8%s\"\n", fakeTab, fakeSig, fakeSig);
      fprintf (file, "%s\"ABADBEEFFACE\";\n", fakeTab);
    fprintf (file, "    %s            = \"0102030405060708\" "
                   "\"090A0B0C0D0E0F10\"\n", P_CFG_FAKE_SKI);
      fprintf (file, "%s\"11121314\";\n\n", fakeTab);
    
    // @TODO: This MUST be modified to each message type once it is 
    //        supported.
    fprintf (file, "    # Allow printout of send and received BGP/BGPsec "
                        "traffic.\n");
    fprintf (file, "    %s    = false;\n", P_CFG_PRINT_ON_SEND);
    fprintf (file, "    # Or more detailed as a filter\n");
    fprintf (file, "    #%s = {\n", P_CFG_PRINT_ON_SEND);
    fprintf (file, "    #  %s         = true;\n", P_CFG_PRNFLTR_OPEN);
    fprintf (file, "    #  %s       = true;\n", P_CFG_PRNFLTR_UPDATE);
    fprintf (file, "    #  %s    = true;\n", P_CFG_PRNFLTR_KEEPALIVE);
    fprintf (file, "    #  %s = true;\n", P_CFG_PRNFLTR_NOTIFICATION);
    fprintf (file, "    #  %s      = true;\n", P_CFG_PRNFLTR_UNKNOWN);
    fprintf (file, "    #};\n\n");
    fprintf (file, "    %s    = false;\n", P_CFG_PRINT_ON_RECEIVE);
    fprintf (file, "    # Or more detailed as a filter\n");
    fprintf (file, "    #%s = {\n", P_CFG_PRINT_ON_RECEIVE);
    fprintf (file, "    #  %s         = true;\n", P_CFG_PRNFLTR_OPEN);
    fprintf (file, "    #  %s       = true;\n", P_CFG_PRNFLTR_UPDATE);
    fprintf (file, "    #  %s    = true;\n", P_CFG_PRNFLTR_KEEPALIVE);
    fprintf (file, "    #  %s = true;\n", P_CFG_PRNFLTR_NOTIFICATION);
    fprintf (file, "    #  %s      = true;\n", P_CFG_PRNFLTR_UNKNOWN);
    fprintf (file, "    #};\n\n");

    fprintf (file, "    #%s     = false;\n\n", P_CFG_PRINT_SIMPLE);

    fprintf (file, "    %s  = false;\n\n", P_CFG_PRINT_POLL_LOOP);
    fprintf (file, "    # For CAPI Mode.\n");    
    fprintf (file, "    %s = false;\n\n", P_CFG_PRINT_CAPI_ON_INVALID);    
    
    fprintf (file, "  }\n");

    fprintf (file, "# Currently multi sessions are not supported, that is\n");
    fprintf (file, "# the reason the following section is commented out!\n");
    fprintf (file, "#  ,{\n");
    fprintf (file, "      # Here script another session\n");
    fprintf (file, "      # Minimum configuration\n");
    fprintf (file, "      # %s = %i;\n", P_CFG_MY_ASN, DEF_LOCAL_ASN);
    fprintf (file, "      # %s = %s;\n", P_CFG_BGP_IDENT, DEF_IPV4);
    fprintf (file, "      # %s = %i;\n", P_CFG_PEER_AS, DEF_PEER_ASN);
    fprintf (file, "      # %s = %s;\n", P_CFG_PEER_IP, DEF_PEER_IP);
    fprintf (file, "#  }\n\n");
    
    fprintf (file, ");\n\n");

    fprintf (file, "# global updates for all sessions\n");
    fprintf (file, "# <prefix>[,[[B4]? <asn>[p<repitition>]]*[ ]*[I|V|N]?]\n");
    fprintf (file, "%s = ( \n", P_CFG_UPD_PARAM);
    fprintf (file, "         );\n");
    fclose(file);
  }
  
  return true;
}
