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
 * Provides a printer for RPKI Router to Cache Protocol Packages. 
 * Supports RFC6810 and RFC8210 package formats.
 *
 * @version 0.6.2.1
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 *  0.6.2.1 - 2024/09/20 - oborchert
 *            * Fixed print bug in _doPrintHex and ERRON PDU printing.
 *          - 2024/09/10 - oborchert
 *            * Changed data types from u_int... to uint... which follows C99
 *            * Fixed printing of End Of Data depending on version.
 *          - 2021/09/03 - oborchert
 *            * Added RPKI_EC_ASPA_PROVIDER_LIST_ERROR
 *            * Removed isASPA from _printFlags.
 *            * USed RPKI_ECSTR_... defines rather than hard coded messages.
 *  0.6.0.0 - 2021/03/30 - oborchert
 *            * Renamed version labeled as version 0.5.2.0 to 0.6.0.0 
 *              (0.5.2.0 was skipped)
 *            * Cleaned up some merger left overs and synchronized with naming 
 *              used conventions.
 *          - 2021/02/16 - oborchert
 *            * Fixed a bug in printing ASPA objects.
 *            2021/02/08 - oborchert
 *            * Added ASPA processing.
 *  0.5.0.6 - 2018/11/20 - oborchert
 *            * Fixed incorrect printing of a string.
 *  0.5.0.4 - 2018/03/06 - oborchert
 *            * Fixed printout of IPv6 number.
 *            * Fixed formating error in error PDU printing.
 *  0.5.0.3 - 2018/02/26 - oborchert
 *            * File created.
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include "server/rpki_packet_printer.h"

/**
 * Do print the given data as hex string. Called by doPrintRPKI_to_RTR_PDU.
 * This function ends with "\n" as printout.
 * 
 * @param len The length in byte of the data
 * @param data the data
 * @param line2Tab A string for the line 2 tab.
 */
static void _doPrintHex(int len, uint8_t* data, char* line2Tab)
{
  char* tab = (line2Tab != NULL) ? line2Tab : "";
  int idx = 0;
  int row = 0;
  int col = 0;
  for (; idx < len; row++)
  {
    if (row != 0)
    {
      // new row
      printf ("%s", tab);
    }
    for (col = 1; idx < len; col++, idx++)
    {
      printf("%02X", data[idx]);
      if ((col % 16) == 0)
      {
        col = 0;
        row++;
        printf("\n");
        if (idx+1 < len)
        {
          printf ("%s", line2Tab);
        }
      } 
      else if ((col % 8) == 0)
      {  
        printf ("   ");
      }
      else if ((col % 4) == 0)
      {
        printf (" ");
      }
    }
  }
  // col != 0  -> Stuff was printed and '\n' was not called
  // idx == 0 -> Nothing at all was printed
  if (col != 0 || idx == 0)
  {
    // assure last print is '\n' as specified
    printf("\n");    
  }
}

/**
 * Read 4 bytes from the buffer and move the buffer pointer and decrease the 
 * length value.
 * 
 * @param ptr The buffer pointer (will be moved)
 * @param result32 Where the 4 byte number will be stored in. 
 * @param length The length of the buffer, will be modified according to the
 *               successful reading of the buffer.
 * @return 
 */
static bool _u32(uint8_t** ptr, uint32_t* result32, uint32_t* length)
{
  bool retVal = false;
  if (*length >= 4)
  {
    *result32 = *(uint32_t*)*ptr; 
    *ptr     += 4;
    *length  -= 4;
    retVal    = true;
  }
  return retVal;
}

/**
 * Read 2 bytes from the buffer and move the buffer pointer and decrease the 
 * length value.
 * 
 * @param ptr The buffer pointer (will be moved)
 * @param result16 Where the 2 byte number will be stored in. 
 * @param length The length of the buffer, will be modified according to the
 *               successful reading of the buffer.
 * @return 
 */

static bool _u16(uint8_t** ptr, uint16_t* result16, uint32_t* length)
{
  bool retVal = false;
  if (*length >= 2)
  {
    *result16 = *(uint16_t*)*ptr; 
    *ptr     += 2;
    *length  -= 2;
    retVal    = true;
  }
  return retVal;
}

/**
 * Read 1 byte from the buffer and move the buffer pointer and decrease the 
 * length value.
 * 
 * @param ptr The buffer pointer (will be moved)
 * @param result8 Where the 1 byte number will be stored in. 
 * @param length The length of the buffer, will be modified according to the
 *               successful reading of the buffer.
 * @return 
 */

static bool _u8(uint8_t** ptr, uint8_t* result8, uint32_t* length)
{
  bool retVal = false;
  if (*length >= 1)
  {
    *result8 = *(uint8_t*)*ptr; 
    *ptr    += 1;
    *length -= 1;
    retVal   = true;
  }
  return retVal;
}

/**
 * Print the flags attribute
 * 
 * @param tab The tab character to be used for each line
 * @param u8 The one octet flag value
 */
static void _printFlags(char* tab, uint8_t u8)
{
  #define  U_ZERO   (uint8_t)0
  #define  U_ONE    (uint8_t)1
  #define  _UNKNOWN_ZERO ""
  #define  _UNKNOWN_ONE  "(UNDEFINED)"

  tab = (tab != NULL) ? tab : " ";
  
  if ((u8 & 0x03) != 0)
  {
    switch (u8 & 0x03)
    {
      case 0:
        printf ("%s+---Flags: 0x00 (%s)\n", tab, "ann/IPv4");
        break;
      case 1:
        printf ("%s+---Flags: 0x01 (%s)\n", tab, "with/IPv4");
        break;
      case 2:
        printf ("%s+---Flags: 0x10 (%s)\n", tab, "ann/IPv6");
        break;
      case 3:
      default:
        printf ("%s+---Flags: 0x11 (%s)\n", tab, "with/IPv6");
        break;
    }
  }
  printf ("%s|     8421 8421\n", tab);
  printf ("%s|     %u... .... %s\n", tab, (u8 & 0x80) ? U_ONE : U_ZERO, 
                                    (u8 & 0x80) ? T4_FLAG_80_1 : T4_FLAG_80_0);
  printf ("%s|     .%u.. .... %s\n", tab, (u8 & 0x40) ? U_ONE : U_ZERO, 
                                    (u8 & 0x40) ? T4_FLAG_40_1 : T4_FLAG_40_0);
  printf ("%s|     ..%u. .... %s\n", tab, (u8 & 0x20) ? U_ONE : U_ZERO, 
                                    (u8 & 0x20) ? T4_FLAG_20_1 : T4_FLAG_20_0);
  printf ("%s|     ...%u .... %s\n", tab, (u8 & 0x10) ? U_ONE : U_ZERO, 
                                    (u8 & 0x10) ? T4_FLAG_10_1 : T4_FLAG_10_0);
  printf ("%s|     .... %u... %s\n", tab, (u8 & 0x08) ? U_ONE : U_ZERO, 
                                    (u8 & 0x08) ? T4_FLAG_08_1 : T4_FLAG_08_0);
  printf ("%s|     .... .%u.. %s\n", tab, (u8 & 0x04) ? U_ONE : U_ZERO, 
                                    (u8 & 0x04) ? T4_FLAG_04_1 : T4_FLAG_04_0);
  printf ("%s|     .... ..%u. %s\n", tab, (u8 & 0x02) ? U_ONE : U_ZERO, 
                                    (u8 & 0x02) ? T4_FLAG_02_1 : T4_FLAG_02_0);
  printf ("%s|     .... ...%u %s\n", tab, (u8 & 0x01) ? U_ONE : U_ZERO, 
                                    (u8 & 0x01) ? T4_FLAG_01_1 : T4_FLAG_01_0);
}

/**
 * Print the field and advances the pdu pointer and reduces the remaining 
 * counter. 
 * 
 * @param pduPtr Address of he buffer pointer.
 * @param octets Number of octets to be read.
 * @param remaining The number of remaining octets in the buffer. 
 * @param tab The tab string.
 * @param name Name of the field.
 * @param useHex Indicates if the value should be printed as a hex value.
 * @param convert Indicate if the value should be converted from network 
 *                presentation into host presentation.
 * 
 * @return false is an error occurred, otherwise true. 
 */
static bool _printField(uint8_t **pduPtr, uint8_t octets, uint32_t* remaining,
                        char* tab, char* name, bool useHex, bool convert)
{
  bool retVal = false;
  // Contains '+--name:'
  char text[255];
  // Contains the tab for hex printing.
  char dTab[255];
  // Used for the correct data retrieval
  uint8_t  u8;
  uint16_t u16;
  uint32_t u32;
  
  // prepare the tree element heading
  snprintf (text, 255, "%s+---%s: ", tab, name);
  
  switch (octets)
  {
    case 1:  // uint8_t
      retVal = _u8(pduPtr, &u8, remaining); if (!retVal) { break; }
      if (useHex)
        printf ("%s 0x%02x (%u)\n", text, u8, u8);
      else
        printf ("%s %u\n", text, u8);
      break;
    case 2:  // uint16_t
      retVal = _u16(pduPtr, &u16, remaining); if (!retVal) { break; }
      if (convert) u16 = ntohs(u16);
      if (useHex)
        printf ("%s 0x%04x (%u)\n", text, u16, u16);
      else
        printf ("%s %u\n", text, u16);
      break;
    case 4:  // uint4_t
      retVal = _u32(pduPtr, &u32, remaining); if (!retVal) { break; }
      if (convert) u32 = ntohs(u32);
      if (useHex)
        printf ("%s 0x%08x (%u)\n", text, u32, u32);
      else
        printf ("%s %u\n", text, u32);
      break;
    default: // stream      printf ("%s ");
      memset(&dTab, '\0', 255);
      memset(&dTab, ' ', strlen(text)+1);
      printf ("%s ", text);
      _doPrintHex(*remaining, *pduPtr, dTab);
      retVal = true;
      *remaining -= octets;
      *pduPtr    += octets;        
  }
  
  return retVal;
}

/**
 * Create a wireshark like printout of the received rpki-to-rtr PDU. This method
 * supports PDU types of RFC6810 and RFC 8210
 * 
 * @param user NOT USED, can be NULL.
 * @param pdu The rpki-to-rtr PDU to be printed.
 * 
 * @since 0.5.0.3
 */
bool doPrintRPKI_to_RTR_PDU(void* user, RPKICommonHeader* pdu)
{
  uint32_t length = ntohl(pdu->length);
  uint8_t* pduPtr = (uint8_t*)pdu;
  
  printf ("rpki-rtr-protocol\n");
  printf (" +---version: %u\n", pdu->version);
  // Move over pdu and type.
  pduPtr += 2;
  length -= 2;
  
  uint8_t  u8;
  uint16_t u16;
  uint32_t u32;
  uint16_t provASCount = 0;
  bool  retVal    = false;
  char* typeName  = NULL;
  char* mixedName = NULL;
  char* codeName  = NULL;
  bool  isIPv4    = true;
  int   idx       = 0;
  
  switch (pdu->type)
  {
    case PDU_TYPE_SERIAL_NOTIFY:
      typeName = "Serial Notify\0";
    case PDU_TYPE_SERIAL_QUERY:
      typeName = typeName != NULL ? typeName   : "Serial Query\0";
      printf (" +---type: %u (%s)\n", pdu->type, typeName);            
      retVal = _u16(&pduPtr, &u16, &length); if (!retVal) break;
      printf (" +---Session ID: 0x%04x (%u)\n", ntohs(u16), ntohs(u16));      
      retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
      printf (" +---Length: %u\n", ntohl(u32));      
      retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
      printf (" +---Serial Number: 0x%08x (%u)\n", ntohl(u32), ntohl(u32));
      break;
      
    case PDU_TYPE_RESET_QUERY:
      typeName  = "Reset Query\0";
    case PDU_TYPE_CACHE_RESET:
      typeName  = typeName != NULL ? typeName   : "Cache Reset\0";
      mixedName = "zero";
    case PDU_TYPE_CACHE_RESPONSE:
      typeName  = typeName != NULL ? typeName   : "Cache Response\0";
      mixedName = mixedName != NULL ? mixedName : "Session ID";
      printf (" +---type: %u (%s)\n", pdu->type, typeName);      
      retVal = _u16(&pduPtr, &u16, &length); if (!retVal) break;
      printf (" +---%s: 0x%04x (%u)\n", mixedName, ntohs(u16), ntohs(u16));      
      retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
      printf (" +---Length: %u\n", ntohl(u32));      
      break;
      
    case PDU_TYPE_IP_V6_PREFIX:
      isIPv4 = false;
    case PDU_TYPE_IP_V4_PREFIX:  
      printf (" +---type: %u (IPv%u Prefix)\n", pdu->type, isIPv4 ? 4 : 6);
      retVal = _u16(&pduPtr, &u16, &length); if (!retVal) break;
      printf (" +---zero: 0x%04x (%u)\n", ntohs(u16), ntohs(u16));
      retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
      printf (" +---Length: %u\n", ntohl(u32));      
      retVal = _u8(&pduPtr, &u8, &length); if (!retVal) break;
      _printFlags(" ", u8);
      retVal = _u8(&pduPtr, &u8, &length); if (!retVal) break;
      printf (" +---Prefix Length: %u\n", u8);
      retVal = _u8(&pduPtr, &u8, &length); if (!retVal) break;
      printf (" +---Max Length: %u\n", u8);
      retVal = _u8(&pduPtr, &u8, &length); if (!retVal) break;
      printf (" +---zero: %u\n", u8);
      if (isIPv4)
      {
        retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
        u32 = ntohl(u32);
        printf (" +---IPv4 Prefix: %u.%u.%u.%u (0x%08x)\n", 
                                                          (uint8_t)(u32 >> 24), 
                                                          (uint8_t)(u32 >> 16),
                                                          (uint8_t)(u32 >> 8),
                                                          (uint8_t)(u32), u32);
      }
      else
      {
        printf (" +---IPv6 Prefix: ");
        retVal = _u32(&pduPtr, &u32, &length);if(!retVal){printf ("\n");break;};
        u32 = ntohl(u32);
        printf ("%04x:%04x:", (uint16_t)(u32 >> 16), (uint16_t)u32);
        retVal = _u32(&pduPtr, &u32, &length);if(!retVal){printf ("\n");break;};
        u32 = ntohl(u32);
        printf ("%04x:%04x:", (uint16_t)(u32 >> 16), (uint16_t)u32);
        retVal = _u32(&pduPtr, &u32, &length);if(!retVal){printf ("\n");break;};
        u32 = ntohl(u32);
        printf ("%04x:%04x:", (uint16_t)(u32 >> 16), (uint16_t)u32);
        retVal = _u32(&pduPtr, &u32, &length);if(!retVal){printf ("\n");break;};
        u32 = ntohl(u32);
        printf ("%04x:%04x\n", (uint16_t)(u32 >> 16), (uint16_t)u32);
      }
      retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
      u32 = ntohl(u32);
      printf (" +---AS Number: %u (%u.%u)\n", u32, (uint16_t)(u32 >> 16), 
                                                   (uint32_t)u32);
      break;
      
    case PDU_TYPE_END_OF_DATA:
      printf (" +---type: %u (%s)\n", pdu->type, "End of Data");
      retVal = _u16(&pduPtr, &u16, &length); if (!retVal) break;
      printf (" +---Session ID: 0x%04x (%u)\n", ntohs(u16), ntohs(u16));      
      retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
      printf (" +---Length: %u\n", ntohl(u32));      
      retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
      printf (" +---Serial Number: %u (0x%08x)\n", ntohl(u32), ntohl(u32));
      if (pdu->version > 1)
      {
        retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
        printf (" +---Refresh Interval: %u (0x%08x)\n", ntohl(u32), ntohl(u32));
        retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
        printf (" +---Retry Interval: %u (0x%08x)\n", ntohl(u32), ntohl(u32));
        retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
        printf (" +---Expire Interval: %u (0x%08x)\n", ntohl(u32), ntohl(u32));
      }
      break;

    case PDU_TYPE_ROUTER_KEY:
      printf (" +---type: %u (%s)\n", pdu->type, "Router Key");
      retVal = _u8(&pduPtr, &u8, &length); if (!retVal) break;
      _printFlags(" ", u8);
      retVal = _u8(&pduPtr, &u8, &length); if (!retVal) break;
      printf (" +---zero: 0x%02x\n", u8);
      retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
      printf (" +---Length: %u\n", ntohl(u32));            
      printf (" +---SKI: ");
      if (length < 20)
      {
        printf ("(Malformed)\n");                
        retVal = false;
        break;
      }
      for (idx = 0; idx < 20; idx++)
      {
        retVal = _u8(&pduPtr, &u8, &length); if (!retVal){printf ("\n");break;};
        printf ("%02x", u8);
      }
      printf("\n");
      retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
      u32 = ntohl(u32);
      printf (" +---AS Number: %u (%u.%u)\n", u32, (uint16_t)(u32 >> 16), 
                                                   (uint32_t)u32);
      printf (" +---SPKI: ");
      _doPrintHex(length, pduPtr, "           ");
      // move pointer to the end
      pduPtr += length;
      length = 0;
      break;

    case PDU_TYPE_ERROR_REPORT:
      printf (" +---type: %u (%s)\n", pdu->type, "Error Report");
      retVal = _u16(&pduPtr, &u16, &length); if (!retVal) break;
      u16 = ntohs(u16);
      switch (u16)
      {
        case RPKI_EC_CORRUPT_DATA:
          codeName = RPKI_ESTR_CORRUPT_DATA;
          break;
        case RPKI_EC_INTERNAL_ERROR:
          codeName = RPKI_ESTR_INTERNAL_ERROR;
          break;
        case RPKI_EC_NO_DATA_AVAILABLE:
          codeName = RPKI_ESTR_NO_DATA_AVAILABLE;
          break;
        case RPKI_EC_INVALID_REQUEST:
          codeName = RPKI_ESTR_INVALID_REQUEST;
          break;
        case RPKI_EC_UNSUPPORTED_PROT_VER:
          codeName = RPKI_ESTR_UNEXPECTED_PROTOCOL_VERSION;
          break;
        case RPKI_EC_UNSUPPORTED_PDU:
          codeName = RPKI_ESTR_UNSUPPORTED_PDU;
          break;
        case RPKI_EC_UNKNOWN_WITHDRAWL:
          codeName = RPKI_ESTR_UNKNOWN_WITHDRAWL;
          break;
        case RPKI_EC_DUPLICATE_ANNOUNCEMENT:
          codeName = RPKI_ESTR_DUPLICATE_ANNOUNCEMENT;
          break;
        case RPKI_EC_ASPA_PROVIDER_LIST_ERROR:
          codeName = RPKI_ESTR_ASPA_PROVIDER_LIST_ERROR;
          break;
        case RPKI_EC_RESERVED:
          codeName = RPKI_ESTR_RESERVED;
          break;
        default:
          codeName = "N/A\0";
      }
      printf (" +---Error Code: %u (%s)\n", u16, codeName);            
      retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
      printf (" +---Length: %u\n", ntohl(u32));            
      retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
      u32 = ntohl(u32);
      printf (" +---Length of Encap PDU: %u\n", u32);            
      printf (" +---Erron PDU: ");
      if (u32 < length)
      {
        _doPrintHex(u32, pduPtr, " |              ");
        length -= u32;
        pduPtr += u32;
      }
      else
      {
        printf (" (Malformed)");
        retVal = false;
        break;
      }
      
      retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
      u32 = ntohl(u32);
      printf (" +---Length of Error Text: %u\n", u32);
      printf (" +---Message: ");
      if (u32 <= length)
      {
        for (idx = 0; idx < u32; idx++)
        {
          retVal = _u8(&pduPtr, &u8, &length); 
          if (!retVal) { printf("(Malformed)\n"); break;}
          printf ("%c", (char)u8);
        }
        printf ("\n");
      }
      else
      {
        printf("(Malformed)\n");
        retVal = false;
      }
      break;

    case PDU_TYPE_ASPA:
      printf (" +---type: %u (%s)\n", pdu->type, "ASPA");
      retVal = _u16(&pduPtr, &u16, &length); if (!retVal) break;
      printf (" +---Reserved: 0x%04x (%u)\n", ntohs(u16), ntohs(u16));      
      retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
      printf (" +---Length: %u\n", ntohl(u32));      
      // Flags
      retVal = _u8(&pduPtr, &u8, &length); if (!retVal) break;
      _printFlags(" ", u8);
      retVal = _u8(&pduPtr, &u8, &length); if (!retVal) break;
      printf (" +---zero: 0x%02x\n", u8);
      retVal = _u16(&pduPtr, &u16, &length); if (!retVal) break;
      provASCount = ntohs(u16);
      printf (" +---Provider AS Count: %u 0x%04x\n", provASCount, provASCount);      
      retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
      printf (" +---Customer ASN: %u (0x%08x)\n", ntohl(u32), ntohl(u32));
      while (provASCount > 0)
      {
        retVal = _u32(&pduPtr, &u32, &length); if (!retVal) break;
        printf (" +---Provider ASN: %u (0x%08x)\n", ntohl(u32), ntohl(u32));
        provASCount--;
      }
      break;
      
    case PDU_TYPE_RESERVED:
      mixedName = "Reserved";
    default:
      mixedName = mixedName != NULL ? mixedName : "unknown";
      printf (" +---type: %u (%s)\n", pdu->type, mixedName);
      retVal=false;
  }
  
  // deal with retVal = false
  
  // Print the remaining data (should be - though)
  if (length != 0)
  {
    printf (" +---remaining data: ");
    _doPrintHex(length, pduPtr, "                     \0");
  }
  
  return retVal;
}
