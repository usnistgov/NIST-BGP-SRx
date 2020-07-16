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
 * Provides functionality to print a BGP Open message
 * 
 * @version 0.2.0.10
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 *  0.2.0.10- 2017/09/01 - oborchert
 *            * Removed not used variables.
 *            * Fixed mismatch in formating and variables within printout.
 *  0.2.0.7 - 2017/03/17 - oborchert
 *            * Combined RREFRESH_PRIV and RREFRESH. (Same as Wireshark)
 *          - 2017/01/10 - oborchert
 *            * Renamed ___printCapability into printCapability and moved it
 *              to the header file. Also added a 'more' parameter.
 *          - 2017/03/08 - oborchert
 *            * Added proper Capabilities printing. Not all yet but at least
 *              most are named. (MPLNRI, BGPSec, AS4, ExtendedMessage and all 
 *              that do have a length of 0)
 *          - 2017/03/02 - oborchert
 *            * Created file
 */

#include <stdio.h>
#include <string.h>
#include "bgp/BGPHeader.h"
#include "bgp/printer/BGPHeaderPrinter.h"
#include "bgp/printer/BGPPrinterUtil.h"
#include "bgp/printer/BGPOpenPrinter.h"

/**
 * Print the MPNLRI Capability
 * 
 * @param mpnlri The MPNLRI Capability
 * @param tabs The tabs to be prepended to each new line.
 */
static void ___printCAP_T_MPNLRI(BGP_Cap_MPNLRI* mpnlri, const char* tabs)
{
  printf ("Multiprotocol extensions capability\n");
  printf ("%s+--Type: Multiprotocol extensions capability (%u)\n", tabs, 
          mpnlri->capHdr.cap_code);
  printf ("%s+--Length: %u\n", tabs, mpnlri->capHdr.cap_length);
  printf ("%s+--AFI: ", tabs);
  u_int16_t afi = ntohs(mpnlri->afi);
  switch (afi)
  {
    case AFI_V4:
      printf ("IPv4"); break;
    case AFI_V6:
      printf ("IPv6"); break;
    default:
      printf ("Unknown");
  }
  printf (" (%u)\n", afi);
  printf ("%s+--Reserved: %02x\n", tabs, mpnlri->reserved);
  printf ("%s+--SAFI: ", tabs);
  switch (mpnlri->safi)
  {
    case SAFI_UNICAST: 
      printf ("Unicast"); break;
    case SAFI_MULTICAST:
      printf ("Multicast"); break;
    case SAFI_RESERVED: 
      printf ("Reserved"); break;
    case SAFI_MPLS: 
      printf ("MPLS"); break;
    default:              
      printf ("Unknown"); break;
  }
  printf (" (%u)\n", mpnlri->safi);
}

/**
 * Print the BGPsec Capability
 * 
 * @param bgpsec The BGPsec Capability
 * @param tabs The tabs to be prepended to each new line.
 */
static void ___printCAP_T_BGPSEC(BGP_Cap_BGPSEC* bgpsec, const char* tabs)
{
  const char bits[16][5] = { "0000\0", "0001\0", "0010\0", "0011\n",
                             "0100\0", "0101\0", "0110\0", "0111\n",
                             "1000\0", "1001\0", "1010\0", "1011\n",
                             "1100\0", "1101\0", "1110\0", "1111\n" };
  printf ("BGPsec capability\n");
  printf ("%s+--Type: BGPsec capability (%u)\n", tabs, 
          bgpsec->capHdr.cap_code);
  printf ("%s+--Length: %u\n", tabs, bgpsec->capHdr.cap_length);
  printf ("%s+--Flags: %s%s\n", tabs, bits[bgpsec->firstOctet >> 4], 
                                      bits[bgpsec->firstOctet & 0xFF]);
  printf ("%s|  +--Version: %u\n", tabs, (bgpsec->firstOctet >> 4));
  printf ("%s|  +--Dir: ", tabs);
  if ((bgpsec->firstOctet & 0x08) != 0)
  {
    printf ("Send (1)\n");
  }
  else
  {
    printf ("Receive (0)\n");
  }
  printf ("%s|  +--Reserved: %u\n", tabs, (bgpsec->firstOctet & 0x3));
  printf ("%s+--AFI: ", tabs);
  u_int16_t afi = ntohs(bgpsec->afi);
  switch (afi)
  {
    case AFI_V4:
      printf ("IPv4"); break;
    case AFI_V6:
      printf ("IPv6"); break;
    default:
      printf ("Unknown");
  }
  printf (" (%u)\n", afi);
}

/**
 * Print the AS4 Capability
 * 
 * @param as4 The AS4 Capability
 * @param tabs The tabs to be prepended to each new line.
 */
static void ___printCAP_T_AS4(BGP_Cap_AS4* as4, const char* tabs)
{
  printf ("Supprt for 4-octed AS number capability\n");
  printf ("%s+--Type: Supprt for 4-octed AS number capability (%u)\n", tabs, 
          as4->capHdr.cap_code);
  printf ("%s+--Length: %u\n", tabs, as4->capHdr.cap_length);
  u_int32_t asn = htonl(as4->myAS);
  printf ("%s+--AS: %u (%u.%u)\n", tabs, asn, (asn >> 16), (asn & 0xFFFF));
}

/** 
 * Print the Optional Parameter: Capability 
 * 
 * @param cap The Capability stream.
 * @param tabs The tab string to be prepended to each line printed.
 * @parma more Indicates if more capabilities are printed on the same level.
 * 
 * @return the number of bytes read from the capabilities stream.
 */
int printCapability(BGP_Capabilities* cap, const char* tabs, bool more)
{
  int retVal = cap->cap_length + sizeof(BGP_Capabilities);
  u_int8_t* capData = (u_int8_t*)cap;
  capData += sizeof(BGP_Capabilities);
  printf("%s+--Capability: ", tabs);
  char capLabel[STR_MAX];
  memset (capLabel, '\0', STR_MAX);

  // Prepare the new tab for the capability to be printed
  char capTabs[STR_MAX];
  memset (capTabs, '\0', STR_MAX);
  if (more)
  {
    snprintf (capTabs, STR_MAX, "%s|  ", tabs);
  }
  else
  {
    snprintf (capTabs, STR_MAX, "%s   ", tabs);
  }
  
  // Indicates if the capability has to be printed generic.
  bool printCap = true;
  switch (cap->cap_code)
  {
    case BGP_CAP_T_RESERVED:
      snprintf (capLabel, STR_MAX, "Reserved"); break;
// 1-63 IETF Review
    case BGP_CAP_T_MPNLRI:
      ___printCAP_T_MPNLRI((BGP_Cap_MPNLRI*)cap, capTabs);
      printCap = false;
      break;
    case BGP_CAP_T_RREFRESH:
    case BGP_CAP_T_RREFRESH_PRIV:
      snprintf (capLabel, STR_MAX, "Route refresh"); break;
    case BGP_CAP_T_OUT_FLTR:
      snprintf (capLabel, STR_MAX, "OUT FLTR"); break;
    case BGP_CAP_T_MULTI_ROUTES:
      snprintf (capLabel, STR_MAX, "Multi routes"); break;
    case BGP_CAP_T_EXT_NEXTHOPENC:
      snprintf (capLabel, STR_MAX, "NEXTHOPENC"); break;
    case BGP_CAP_T_EXT_MSG_SUPPORT:
      snprintf (capLabel, STR_MAX, "Extended message support"); break;
// unassigned 7-63
// 64-127 First Come First Served
    case BGP_CAP_T_GRACE_RESTART:
      snprintf (capLabel, STR_MAX, "Graceful restart"); break;
    case BGP_CAP_T_AS4:
      ___printCAP_T_AS4((BGP_Cap_AS4*)cap, capTabs);
      printCap = false;
      break;
    case BGP_CAP_T_DEPRECATED:
      snprintf (capLabel, STR_MAX, "Deprecated"); break;
    case BGP_CAP_T_SUPP_DYNCAP:
      snprintf (capLabel, STR_MAX, "Supp for dyncap"); break;
    case BGP_CAP_T_MULTI_SESS:
      snprintf (capLabel, STR_MAX, "Multi session support"); break;
    case BGP_CAP_T_ADD_PATH:
      snprintf (capLabel, STR_MAX, "Add path support"); break;
    case BGP_CAP_T_ENHANCED_RR:
      snprintf (capLabel, STR_MAX, "Enhanced route refresh"); break;
    case BGP_CAP_T_LLGR:
      snprintf (capLabel, STR_MAX, "LLGR"); break;
// 72 - Unassigned
// http://www.iana.org/assignments/capability-codes/capability-codes.xhtml
    case BGP_CAP_T_BGPSEC:
      ___printCAP_T_BGPSEC((BGP_Cap_BGPSEC*)cap, capTabs);
      printCap = false;
      break;
    case BGP_CAP_T_FQDN:
      snprintf (capLabel, STR_MAX, "FQDN"); break;
// Unassigned 74-127
// Private Usage 128-255 - IANA does not assign
    default:
      snprintf (capLabel, STR_MAX, "Unknown"); break;
  }
  
  if (printCap)
  {
    printf ("%s capability\n", capLabel);
    printf ("%s+--Type: %s capability (%u)\n", capTabs, capLabel, cap->cap_code);
    printf ("%s+--Length: %u\n", capTabs, cap->cap_length);
    if (cap->cap_length > 0)
    {
      char dataStr[STR_MAX];
      // write the text first in the variable to see how long it becomes. This 
      // will be the tab for the final print in case data is very large.
      snprintf(dataStr, STR_MAX, "%s+--data: ", capTabs);
      // Now print the tree leaf name
      printf("%s", dataStr);
      // Now generate the tab
      memset(dataStr, ' ', strlen(dataStr));
      // Now write the hex data (formatted)
      printHex(capData, cap->cap_length, dataStr);
    }
  }
  return retVal;
}

/** 
 * Print the optional parameter
 * 
 * @param param The optional parameter
 * @param more  Indicates if more optional parameters follow
 * 
 * @return the number of bytes read from the optional parameter.
 */
static int _printOptionalParameter(BGP_OpenMessage_OptParam* param, bool more)
{
  int read = sizeof(BGP_OpenMessage_OptParam) + param->param_len;
  u_int8_t* data = (u_int8_t*)param;
  data += sizeof(BGP_OpenMessage_OptParam);
  int capLen = 0;
  
  printf("%s%s+--Optional Parameter: ", TAB_2, TAB_3);
  
  // Generate the tabs for the optional parameter
  char tabs[STR_MAX];
  memset (tabs, '\0', STR_MAX);
  snprintf(tabs, STR_MAX, "%s%s%s", TAB_2, TAB_3, (more ? "|  " : "   "));
  
  int processed = 0;
  switch (param->param_type)
  {
    case BGP_T_CAP:
      printf("Capability\n");
      printf("%s+--Type: Capability (%u)\n", tabs, param->param_type);
      printf("%s+--Length: %u\n", tabs, param->param_len);
      processed = 0;
      // Now loop through the list of capabilities
      int minSize = sizeof(BGP_Capabilities);
      while (capLen < param->param_len)
      {
        // Check if additional capabilities are stored within this Optional
        // Parameter.
        more = (capLen + minSize + ((BGP_Capabilities *)data)->cap_length) 
               < param->param_len;
        processed = printCapability((BGP_Capabilities *)data, tabs, more);
        capLen += processed;
        data += processed;
      }
      break;
    default:
      printf("Unknown\n");
      printf("%s+--Type: Unknown (%u)\n", tabs, param->param_type);
      printf("%s+--Length: %u\n", tabs, param->param_len);
      char dataStr[STR_MAX];
      // write the text first in the variable to see how long it becomes. This 
      // will be the tab for the final print in case data is very large.

      snprintf(dataStr, STR_MAX, "%s+--data:   ", tabs);
      // Now print the tree leaf name
      printf("%s", dataStr);
      // Now generate the tab
      memset(dataStr, ' ', strlen(dataStr));
      // Now write the hex data (formatted)
      printHex(data, (read - param->param_len), dataStr);      
      break;   
  }
  
  return read;
}


/**
 * Print the BGP Open Message
 * 
 * @param openmsg The open message as complete BGP packet. 
 * @param simple If true, do not use the tree format as in wireshark
 */
void printOpenData(BGP_OpenMessage* openmsg, bool simple)
{
  u_int16_t openLength = ntohs(openmsg->messageHeader.length);
  u_int8_t* start = (u_int8_t*)openmsg;
  u_int8_t* data = start + sizeof(BGP_OpenMessage);  
  u_int8_t* end = start + openLength;  
  
  if (!simple)
  {          
    printf("%s+--Version: %u\n", TAB_2, openmsg->version);
    printf("%s+--My AS: %u\n", TAB_2, ntohs(openmsg->my_as));    
    printf("%s+--Hold Time: %u\n", TAB_2, ntohs(openmsg->hold_time));    
    u_int8_t* bgp_id = (u_int8_t*)&openmsg->bgp_identifier;

    printf("%s+--BGP Identifier: %u.%u.%u.%u\n", TAB_2, bgp_id[0], bgp_id[1], 
                                                        bgp_id[2], bgp_id[3]);
    printf("%s+--Optional Parameters Length: %u\n", TAB_2, openmsg->opt_param_len);

    if ((end - data) != openmsg->opt_param_len)
    {
      printf("%s+--MALEFORMED UPDATE - Remaining data != Optional param length!\n", 
             TAB_2);      

      char dataStr[STR_MAX];
      // write the text first in the variable to see how long it becomes. This 
      // will be the tab for the final print in case data is very large.

      snprintf(dataStr, STR_MAX, "%s+--data:   ", TAB_2);
      // Now print the tree leaf name
      printf("%s", dataStr);
      // Now generate the tab
      memset(dataStr, ' ', strlen(dataStr));
      // Now write the hex data (formatted)
      printHex(data, (end - data), dataStr);
    }
    else
    {
      if (openmsg->opt_param_len != 0)
      {
        // Parse the optional parameters.
        bool more = false;
        int hdrSize = sizeof(BGP_OpenMessage_OptParam);
        while (data < end)
        {
          BGP_OpenMessage_OptParam* optParam = (BGP_OpenMessage_OptParam*)data;
          more = ( data + optParam->param_len + hdrSize) < end;
          data += _printOptionalParameter(optParam, more);
        }
      }
      else
      {
        printf("%s+--data:   (no data)", TAB_2);
      }
    }
  }
  else
  {
    printf ("OPEN\n");
  } 
}
