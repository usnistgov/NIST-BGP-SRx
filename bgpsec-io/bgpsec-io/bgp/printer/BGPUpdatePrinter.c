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
 * Provides functionality to print a BGP Update
 * 
 * @version 0.2.1.0
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 *  0.2.1.0 - 2018/11/29 - oborchert
 *            * Removed merge comments in version control.
 *  0.2.0.22- 2018/06/18 - oborchert
 *            * Fixed memory leak in __printAS_PATH_List by passing the correct
 *              method for freeing the data '_freeBGP_PRNT_AS_PATH'
 *            * Fixed memory leak in __printAS_PATH by freeing the allocated 
 *              asPath variable.
 *  0.2.0.21- 2018/06/07 - oborchert
 *            * Added missing simple print of MPNLRI and BGPsec_PATH
 *            * Added text prefix (BSP:) to simple printout
 *            * Performed right trim of the AS path for simple print
 *  0.2.0.20- 2018/05/02 - oborchert 
 *            * Fixed some issues in printing Community String and Extended 
 *              Community String          
 *  0.2.0.17- 2018/04/27 - oborchert
 *            * Modified AS_SET identifiers [ ] to use the defines specified in 
 *              configuration.h file (UPD_AS_SET_OPEN and UPD_AS_SET_CLOSE)
 *  0.2.0.13- 2018/04/17 - oborchert
 *            * Fixed printing of prefixes in _printNLRI when more than one
 *              prefix is packed in the update.
 *            * Fixed printing of Unfeasible routes (withdrawn routes).
 *  0.2.0.12- 2018/04/14 - oborchert
 *            * Added simple printout to MP_REACH_NLRI.
 *            * Fixed simple printout of AS_PATH.
 *            * Added text prefix (PFX:, ASP:, AS4P:) to simple 
 *              printout because the ordering cannot be guaranteed.
 *  0.2.0.11- 2018/03/23 - oborchert
 *            * Added AS_PATH printing (simple for now)
 *          - 2018/03/22 - oborchert
 *            * Added parameter isAS4 to printUdateData.
 *  0.2.0.10- 2017/09/01 - oborchert
 *            * Removed not used variables.
 *            * Fixed import of headers.
 *  0.2.0.9 - 2017/08/24 - oborchert
 *            * Fixed BZ1192, missing "Non-transitive" for Non-transitive 
 *              attributes.
 *  0.2.0.7 - 2017/02/16 - oborchert
 *            * Replaced hard coded value with defined value in function 
 *              __printMP_REACH_NLRI
 *          - 2017/02/07 - oborchert
 *            * Added complete printout of MP_REACH_NLRI
 *  0.2.0.5 - 2017/01/11 - oborchert
 *            * Added the correct label MP_REACH_NLRI to the printout of 
 *              attributes of that type (BZ1065).
 *          - 2016/11/01 - oborchert
 *            * Adjusted the signature of the method printBGPSEC_PathAttr to
 *              use BGP_PathAttr as parameter.
 *  0.2.0.1 - 2016/06/25 - oborchert
 *            * Fixed wrong format in printout of path attributes.
 *  0.2.0.0 - 2016/05/11 - oborchert
 *            * Fixed BZ960: Invalid next hop IP encoding
 *          - 2016/05/10 - oborchert
 *            * Fixed formating error in _printNLRI (BZ950)
 *  0.1.1.0 - 2016/03/25 - oborchert
 *            * Changed static function __printBGPSEC into function 
 *              printBGPSEC_PathAttr which is added to the header.
 *          - 2016/03/18 - oborchert
 *            * Created File.
 */

#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <math.h>
#include "antd-util/linked_list.h"
#include "bgp/BGPHeader.h"
#include "bgp/printer/BGPHeaderPrinter.h"
#include "bgp/printer/BGPUpdatePrinter.h"
#include "bgp/printer/BGPPrinterUtil.h"
#include "cfg/configuration.h"

////////////////////////////////////////////////////////////////////////////////
// Internal structure for AS_PATH attribute
////////////////////////////////////////////////////////////////////////////////
/** Helper struct to create an AS path printout. @since 0.2.0.11 */
typedef struct {
  /** Pointer to the original path segment. DO NOT FREE */
  BGP_Upd_AS_PathSegment* segment;
  /** The maximum size of the string buffer. */
  int strBuffSize;
  /** String containing the as-path. Must be freed. */
  char* path_str;
} _BGP_PRNT_AS_PATH;

/**
 * Free the allocated memory for the AS_PATH element.
 * 
 * @param elem The _BGP_PRNT_AS_PATH to be freed.
 * 
 * @since 0.2.0.11
 */
static void _freeBGP_PRNT_AS_PATH(void* elem)
{
  _BGP_PRNT_AS_PATH* e = (_BGP_PRNT_AS_PATH*)elem;
  free (e->path_str);
  free (e);
}

////////////////////////////////////////////////////////////////////////////////
// Default Path attribute Flags
////////////////////////////////////////////////////////////////////////////////

/**
 * Print the Flags info
 * 
 * @param flags the attribute flags
 * @param tab The tabulator of this attribute. (if NULL then it will be replaced 
 *            with TAB_2
 * 
 */
static void __printPathAttFlags(u_int8_t flags, char* tab)
{
  if (tab == NULL)
  {
    tab = TAB_2;
  }
  
  printf ("%s+--Flags: 0x%02X (", tab, flags);
  if (flags & BGP_UPD_A_FLAGS_OPTIONAL)   
  { 
    printf("Optional" ); 
  }
  else
  { 
    printf("Well-Known" );
  }
  
  if (flags & BGP_UPD_A_FLAGS_TRANSITIVE) 
  { 
    printf(", Transitive" ); 
  }
  else
  {    
    printf(", Non-transitive" );     
  }
  
  if (flags & BGP_UPD_A_FLAGS_PARTIAL)    
  { 
    printf(", Partial" );
  }
  else
  {
    printf(", Complete" );    
  }
  
  if (flags & BGP_UPD_A_FLAGS_EXT_LENGTH) 
  { 
    printf(", Extended Length"); 
  }
  printf (")\n");
}

/**
 * Return the string "bytes" or "byte" depending on the given length
 * 
 * @param length the number of bytes
 * 
 * @return the byte(s) text according to the length
 */
static char* __byteString(int length)
{
  char* retVal = NULL;

  if (length == 1)
  {
    retVal = BYTE_STR;
  }
  else
  {
    retVal = BYTES_STR;
  }
  
  return retVal;
}

/**
 * Print the default Path Attribute information.
 * 
 * @param pa The BGP Path Attribute
 * @param title The title for the attribute (most likely same as typeName)
 * @param attrLen The total length of the attribute (incl. header)
 * @param len the length of the attribute data
 * @param typeName the name of the attribute (if NULL than the title will used)
 * @param tab The tabulator of this attribute. (if NULL then it will be replaced 
 *            with TAB_2
 * @param more Indicates if more attributes are printed after this one. This is 
 *             needed for proper formating.
 * 
 * @return the number of bytes expected in the data section.
 */
static u_int16_t __printDefaultPAttrHdr(BGP_PathAttribute* pa, char* title, 
                                     int attrLen, int len, const char* typeName, 
                                     const char* tab, const bool more)
{
  if (typeName == NULL)
  {
    typeName = title;
  }
  if (tab == NULL)
  {
    tab = TAB_2;
  }
  
  char myTab[TAB_MAX];
  memset (myTab, '\0', TAB_MAX);
  if (more)
  {
    snprintf(myTab, TAB_MAX, "%s|%s", tab, TAB_2);
  }
  else
  {
    snprintf(myTab, TAB_MAX, "%s %s", tab, TAB_2);    
  }
  
  printf ("%s (%d %s)\n", title, attrLen, __byteString(attrLen));
  __printPathAttFlags(pa->attr_flags, myTab);
  printf ("%s+--Type Code: %s (%d)\n", myTab, typeName, pa->attr_type_code);
  printf ("%s+--Length: %d %s\n", myTab, len, __byteString(len));
  
  return len;
}

////////////////////////////////////////////////////////////////////////////////
// Path Attribute: ORIGIN
////////////////////////////////////////////////////////////////////////////////

/**
 * Print the ORIGIN information
 * 
 * @param pp The BGP Path Attribute ORIGIN
 * @param tab The tabulator of this attribute. (if NULL then it will be replaced 
 *            with TAB_2
 * @param more Indicates if more attributes are being printed. This is needed 
 *             for the formating
 * 
 * @return true if the attributes data was included in the print.
 */
static bool __printORIGIN(BGP_Upd_Attr_Origin* po, char* tab, bool more)
{
  const char* tName = "ORIGIN\0";
  char* code = NULL;
  if (tab == NULL)
  {
    tab = TAB_2;
  }
  char myTab[TAB_MAX];
  memset (myTab, '\0', TAB_MAX);
  if (more)
  {
    snprintf (myTab, TAB_MAX, "%s|%s", tab, TAB_2);
  }
  else
  {
    snprintf (myTab, TAB_MAX, "%s %s", tab, TAB_2);
  }

  switch (po->origin)
  {
    case BGP_UPD_A_FLAGS_ORIGIN_IGP:
      code = "IGP\0";
      break;
    case BGP_UPD_A_FLAGS_ORIGIN_EGP:
      code = "EGP\0";
      break;
    case BGP_UPD_A_FLAGS_ORIGIN_INC:
      code = "INCOMPLETE\0";
      break;
    default:
      code = "*****\0";
      break;
  }
  // here pass tab rather than myTab because the additional tabs will be 
  // added in __printDef...
  printf ("%s: ", tName);
  __printDefaultPAttrHdr((BGP_PathAttribute*)po, code, 
                         sizeof(BGP_Upd_Attr_Origin), po->length, tName, tab, 
                         more);
  printf ("%s+--Origin: %s (%d)\n", myTab, code, po->pathattr.attr_type_code);
  
  return true;  
}

////////////////////////////////////////////////////////////////////////////////
// Path Attribute: AS_PATH
////////////////////////////////////////////////////////////////////////////////

/**
 * Create a linked list with _BGP_PRNT_AS_PATH elements in order as found.
 *  
 * @param segBuff The buffer containing the segments
 * @param buffLen Length in bytes of the segment buffer. 
 * @param isAS4 Indicates if the AS numbers found are 4 byte ASNs
 * 
 * @return The list or NULL if Malformed.
 */
List* ___createAS_PATH_List(u_int8_t* segBuff, int buffLen, bool isAS4)
{
  List* list = createList();
  BGP_Upd_AS_PathSegment* segHdr = NULL;
  _BGP_PRNT_AS_PATH* pathSegment = NULL;
  int  hdrSize    = sizeof(BGP_Upd_AS_PathSegment);
  int  asTypeSize = isAS4 ? 4 : 2;
  int  maxDigits  = isAS4 ? (int)(log10((u_int32_t)0xFFFFFFFF)) + 2
                          : (int)(log10(0xFFFF)) + 2;              
                           // +2 => 1 round up, 1 blank
  int  idx;
  bool isAS_SET   = false;
  char* asPathStr = NULL;
  u_int32_t asn;
  
  while (buffLen > hdrSize)
  {
    segHdr   = (BGP_Upd_AS_PathSegment*)segBuff;
    isAS_SET = segHdr->segmentType == BGP_UPD_A_FLAGS_ASPATH_AS_SET;
    buffLen -= hdrSize;
    segBuff += hdrSize;
    if ((segHdr->segment_length * asTypeSize) > buffLen)
    {
      // Exit loop, not enough memory left - declare path list as malformed
      break;
    }
    
    pathSegment = malloc(sizeof(_BGP_PRNT_AS_PATH));
    pathSegment->segment     = segHdr;
    // AS_SET will be encapsulated in '[ ' and ']'
    pathSegment->strBuffSize = (maxDigits * segHdr->segment_length)
                               + (isAS_SET ? 4 : 0) + 1; // the last 1 for '\0'
    pathSegment->path_str    = malloc(pathSegment->strBuffSize);
    memset(pathSegment->path_str, '\0', pathSegment->strBuffSize);
    asPathStr = pathSegment->path_str;
    addListElem(list, pathSegment);
    
    if (isAS_SET)
    {
      asPathStr += sprintf(asPathStr, "%c ", UPD_AS_SET_OPEN);
    }
    for (idx = 0; (idx < segHdr->segment_length) && (buffLen >= asTypeSize); 
         idx++)
    {
      asn = isAS4 ? ntohl(*(u_int32_t*)segBuff)
                  : ntohs(*(u_int16_t*)segBuff);
      segBuff   += asTypeSize;
      buffLen   -= asTypeSize;
      asPathStr += sprintf(asPathStr, "%u ", asn);
    }
    if (isAS_SET)
    {
      asPathStr += sprintf(asPathStr, "%c ",UPD_AS_SET_CLOSE);
    }
  }
  
  if (buffLen > 0)
  {
    // The buffer seems malformed
    destroyListDeep(list, _freeBGP_PRNT_AS_PATH);
    list = NULL;
  }
  return list;
}

/**
 * Print the AS_PATH path attribute.
 * 
 * @param pa      The BGP Path Attribute
 * @param isAS4   Indicates if ASN number are 4 byte (true) or 2 byte (false)
 * @param simple  If true only the AS path is printed (without \n)
 * @param attrLen The total length of the attribute (incl. header)
 * @param len The length of the attribute data
 * @param tab The tabulator of this attribute. (if NULL then it will be replaced 
 *            with TAB_2
 * @param more Indicates if more attributes are printed after this one. This is 
 *             needed for proper formating.
 * 
 * @return true if the attributes data was included in the print.
 */
static bool __printAS_PATH(BGP_PathAttribute* pa, bool isAS4, bool simple,
                           int attrLen, int len, char* tab, const bool more)
{
  u_int8_t* data  = (u_int8_t*)pa + (attrLen - len);
  bool printedData = false;

  // Let us create all path string elements of all segments first.
  List* list = ___createAS_PATH_List(data, len, isAS4);
  
  char* hlpPtr = NULL;
  // Now lets get the PATH name
  const char* tName = (pa->attr_type_code == BGP_UPD_A_TYPE_AS4_PATH)
                      ? "AS4_PATH\0" : "AS_PATH\0";
  
  // Loop through the list
  int idx = 0;
  _BGP_PRNT_AS_PATH* segment = NULL;
  int pathStrLen = 0;
  char* asPath = NULL;
  
  if (list)
  {
    for (; idx < list->count; idx++)
    {
      segment = (_BGP_PRNT_AS_PATH*)getListElementAt(list, idx);
      if (segment != NULL)
      {
        pathStrLen += segment->strBuffSize;
      }
    }
    pathStrLen++;
    asPath = malloc(pathStrLen);
    memset(asPath, '\0', pathStrLen);
    hlpPtr = asPath;
    
    // Now write the path
    for (idx = 0; idx < list->count; idx++)
    {
      segment = (_BGP_PRNT_AS_PATH*)getListElementAt(list, idx);
      if (segment != NULL)
      {
        hlpPtr += sprintf(hlpPtr, "%s", segment->path_str);
      }
    }
  }
  // Quick Fix
  else
  {
    // @TODO: I believe the complete block below must be added in to the 
    //        if (list) loop. For now use this block as workaround.
    asPath = malloc(2);
    snprintf(asPath, 2, " ");
  }
  
  if (simple)
  {
    int strLen = strlen(asPath);
    // right trim of the path string
    while ((strLen-1 > 0) && asPath[--strLen] == ' ')
    {
      asPath[strLen] = '\0';
      strLen = strlen(asPath);
    }
    printf ("%s%s", (pa->attr_type_code == BGP_UPD_A_TYPE_AS4_PATH) 
                        ? PRN_SIMPLE_AS4PATH : PRN_SIMPLE_ASPATH, 
                    asPath);
    printedData = true;
  }
  else
  {    
    printf ("%s: ", tName);
    __printDefaultPAttrHdr(pa, asPath, attrLen, len, tName, tab, more);
    printf ("%s   +--AS path: %s\n", tab, asPath);
  }
  
  // Fixed memory leak, fixed the free method passed into the printer.
  destroyListDeep(list, _freeBGP_PRNT_AS_PATH);
  // Fixed memory leak
  if (asPath != NULL)
  {
    free(asPath);
  }

  return printedData;
}


////////////////////////////////////////////////////////////////////////////////
// Path Attribute: NEXT_HOP
////////////////////////////////////////////////////////////////////////////////

/**
 * Print the NEXT_HOP information
 * 
 * @param nh The BGP NEXT_HOP Path Attribute
 * @param tab The tabulator of this attribute. (if NULL then it will be replaced 
 *            with TAB_2
 * @param more Indicates if more attributes are being printed. This is needed 
 *             for the formating
 * 
 * @return true, the attributes data was included in the print.
 */
static bool __printNEXT_HOP(BGP_Upd_Attr_NextHop* nh, char* tab, bool more)
{
  u_int32_t nextHop = ntohl(nh->nextHop);
  u_int8_t* bytes = (u_int8_t*)&nextHop;
  char  title[STR_MAX];
  const char* tName="NEXT_HOP\0";
  snprintf (title, STR_MAX, "%s: %d.%d.%d.%d%c", tName, 
            bytes[3], bytes[2], bytes[1], bytes[0], '\0'); 
  
  __printDefaultPAttrHdr((BGP_PathAttribute*)nh, title, 
                         sizeof(BGP_Upd_Attr_NextHop), nh->length, tName, 
                         tab, more);
  char myTab[TAB_MAX];
  memset (myTab, '\0', TAB_MAX);
  if (more)
  {
    snprintf (myTab, TAB_MAX, "%s|%s", tab, TAB_2);
  }
  else
  {
    snprintf (myTab, TAB_MAX, "%s %s", tab, TAB_2);
  }
  printf ("%s+--Next hop: %d.%d.%d.%d (%08X)\n", myTab, bytes[3], bytes[2], 
                                               bytes[1], bytes[0], nh->nextHop);
    
  return true;  
}

////////////////////////////////////////////////////////////////////////////////
// Path Attribute: ORIGIN
////////////////////////////////////////////////////////////////////////////////

/**
 * Print the MP_REACH_NLRI information
 * 
 * @param mpnlri The BGP Path Attribute MP_REACH_NLRI
 * @param attrLen The complete length of the attribute
 * @param tab The tabulator of this attribute. (if NULL then it will be replaced 
 *            with TAB_2
 * @param simple indicates if the NLRI is printed in simple or wireshark mode.
 * @param more Indicates if more attributes are being printed. This is needed 
 *             for the formating
 * 
 * @return true, the attributes data was included in the print.
 */
static bool __printMP_REACH_NLRI(BGP_Upd_Attr_MPNLRI_1* mpnlri, int attrLen,
                                 char* tab, bool simple, bool more)
{
  char* tName   = "MP_REACH_NLRI\0";
  u_int16_t afi = ntohs(mpnlri->afi);
  int idx       = 0;

  char myTab[TAB_MAX];
  memset (myTab, '\0', TAB_MAX);
  char string[STR_MAX];
  memset(string, 0, STR_MAX);

  if (!simple)
  {
    if (tab == NULL)
    {
      tab = TAB_2;
    }
    if (more)
    {
      snprintf (myTab, TAB_MAX, "%s|%s", tab, TAB_2);
    }
    else
    {
      snprintf (myTab, TAB_MAX, "%s %s", tab, TAB_2);
    }

    // here pass tab rather than myTab because the additional tabs will be 
    // added in __printDef...  
    __printDefaultPAttrHdr((BGP_PathAttribute*)mpnlri, tName, attrLen, 
                           mpnlri->length, NULL, tab, more);

    snprintf (string, STR_MAX, (afi == AFI_V4) ? "IPv4" : "IPv6");

    printf ("%s+--Address family: %s (%d)\n", myTab, string, afi);
    switch (mpnlri->safi)
    {
      case SAFI_UNICAST: 
        snprintf (string, STR_MAX, "Unicast");
        break;
      default:
        snprintf (string, STR_MAX, "???");
        break;
    }

    printf ("%s+--Subsequent address family identifier: %s (%d)\n", myTab, string, 
            mpnlri->safi);
    printf ("%s+--Next hop network address: (%d bytes)\n", myTab, 
            mpnlri->nextHopLen);
    printf ("%s|  +--Next hop: ", myTab);
  }
  
  u_int8_t* buff = (u_int8_t*)mpnlri;
  // Now move the buffer to the next hop IP
  buff += sizeof(BGP_Upd_Attr_MPNLRI_1);
  // Use this for both, IPv4 as well as IPv6
  u_int8_t ipNum[4] = { 0, 0, 0, 0 };
  
  switch (mpnlri->nextHopLen)
  {
    case 4:
      ipNum[0] = *(buff++);
      ipNum[1] = *(buff++);
      ipNum[2] = *(buff++);
      ipNum[3] = *(buff++);
      if (!simple)
        printf("%u.%u.%u.%u\n", ipNum[0], ipNum[1], ipNum[2], ipNum[3]);
      break;
    case 16:
      for (idx = 0; idx < 8; idx ++)
      {
        ipNum[0] = *(buff++);
        ipNum[1] = *(buff++);
        if (!simple)
        {
          if (idx != 0)
          {
            printf(":");
          }
          printf("%02x%02x", ipNum[0], ipNum[1]);
        }
      }
      if (!simple)
        printf ("\n");
      break;
    default:
      printHex(buff, mpnlri->nextHopLen, NULL);
      buff += mpnlri->nextHopLen;
  }
    
  BGP_Upd_Attr_MPNLRI_2* mpnlri2 = (BGP_Upd_Attr_MPNLRI_2*)buff;
  buff += sizeof(BGP_Upd_Attr_MPNLRI_2);
  if (!simple)
    printf ("%s+--Subnetwork points of attachment: %u\n", myTab, 
            mpnlri2->reserved);
  
  u_int8_t octets = numBytes(mpnlri2->nlri.length);
  if (!simple)
    printf ("%s+--Network layer reachability information: (%u bytes)\n", myTab, 
            octets+1);
  
  // Re-initialize the string
  u_int8_t bytes[16];
  memset (bytes, 0, 16);
  // Copy the prefix into the byte buffer. (inet_ntop does not workwith buffer)
  for (idx = 0; idx < octets; idx++)
  {
    bytes[idx] = *(buff++);
  }
  int family   = (afi==AFI_V4) ? AF_INET : AF_INET6;
  memset (string, 0, STR_MAX);
  if (!inet_ntop(family, bytes, string, STR_MAX))
  {
    snprintf(string, STR_MAX, "ERROR in %s prefix address\n", string);
  }
  if (!simple)
  {
    printf ("%s   +--%s/%u\n", myTab, string, mpnlri2->nlri.length);
    printf ("%s   +--MP Reach NLRI prefix length: %u\n", myTab, mpnlri2->nlri.length);
    printf ("%s   +--MP Reach NLRI %s prefix: %s\n", myTab, 
            (afi == AFI_V4) ? "IPv4" : "IPv6", string);
  }
  
  if (simple)
  {
    printf ("%s%s/%u", PRN_SIMPLE_PREFIX_A, string, mpnlri2->nlri.length);    
  }
  
  return true;  
}

////////////////////////////////////////////////////////////////////////////////
// BGPSEC Path attribute
////////////////////////////////////////////////////////////////////////////////

/**
 * Process the secure path information
 * 
 * @param data The updates attribute buffer
 * @param tab The tabulator of this attribute. (if NULL then it will be replaced 
 *            with TAB_2
 * @param simple Indicate if the path has to be printed in simple form. 
 * 
 * @return the number of bytes processed
 */
static int __printBGPSEC_SecurePath(u_int8_t* data, char* tab, bool simple)
{
  if (tab == NULL)
  {
    tab = TAB_2;
  }
  
  char myTab[3][TAB_MAX];
  memset (myTab,  '\0', TAB_MAX*3);
  
  if (!simple)
  {
    snprintf (myTab[0], TAB_MAX, "%s|%s", tab, TAB_2);
    snprintf (myTab[1], TAB_MAX, "%s|%s", myTab[0], TAB_2);
    snprintf (myTab[2], TAB_MAX, "%s %s", myTab[0], TAB_2);
  }
  
  BGPSEC_SecurePath* sp = (BGPSEC_SecurePath*)data;
  data += sizeof(BGPSEC_SecurePath);
  int processed = sizeof(BGPSEC_SecurePath);
  int size = 0;
  int length = ntohs(sp->length);
  
  if (!simple)
  {
    printf("%s+--Secure Path (%d %s)\n", tab, length, __byteString(length));
    printf("%s+--Length: %d %s\n", myTab[0], length, __byteString(length));
  }
  
  BGPSEC_SecurePathSegment* seg = NULL;
  
  while (processed < length)
  {
    seg = (BGPSEC_SecurePathSegment*)data;
    size = sizeof(BGPSEC_SecurePathSegment);
    // Move to next segment
    data += size;
    processed += size;
    
    u_int32_t asn = ntohl(seg->asn);
    
    if (!simple)
    {
      tab = processed < length ? myTab[1] : myTab[2];
      printf("%s+--Secure Path Segment: (%d %s)\n", myTab[0], 
                                                    size, __byteString(size));
      printf("%s+--pCount: %d\n", tab, seg->pCount);
      printf("%s+--Flags: %d\n", tab, seg->flags);
      printf("%s+--AS number: %d (%d.%d)\n", tab, 
                                             asn, (asn >> 16), (asn & 0xFFFF));
    }
    else
    {
      // simple
      tab = processed < length ? " " : "";
      int idx = seg->pCount-1;
      printf ("%d", asn);
      while (idx-- != 0)
      {
        printf (" %d", asn);      
      }
      printf ("%s", tab);
    }
  }
  
  return length;
}

/**
 * Process the signature block information
 * 
 * @param data the updates attribute buffer.
 * @param buffSize The complete buffer size. If it is larger than the
 *                 space occupied by data itself than more attributes or
 *                 more signature blocks to follow.
 * @param simple Indicates if the printout has to be simple or not.
 * @param tab The tabulator of this attribute. (if NULL then it will be replaced 
 *            with TAB_2
 * 
 * @return the number of bytes processed
 */
static int __printBGPSEC_SignatureBlockPath(u_int8_t* data, int buffSize,
                                            bool simple, char* tab)
{
  if (tab == NULL)
  {
    tab = TAB_2;
  }
  
  char str[2][STR_MAX]; // used for data print
  memset (str, '\0', STR_MAX*2);

  BGPSEC_SignatureBlock* sigB = (BGPSEC_SignatureBlock*)data;
  data += sizeof(BGPSEC_SignatureBlock);
  int processed = sizeof(BGPSEC_SignatureBlock);
  int size = 0;
  int length = ntohs(sigB->length);

  char separator = (length < buffSize) ? '|' : ' ';
  
  char myTab[3][TAB_MAX];
  memset (myTab,  '\0', TAB_MAX*3);
  snprintf (myTab[0], TAB_MAX, "%s%c%s", tab, separator, TAB_2);
  snprintf (myTab[1], TAB_MAX, "%s|%s", myTab[0], TAB_2);
  snprintf (myTab[2], TAB_MAX, "%s %s", myTab[0], TAB_2);
  
  if (!simple)
  {
    printf("%s+--Signature Block (%d %s)\n", tab, length, __byteString(length));
    printf("%s+--Length: %d %s\n", myTab[0], length, __byteString(length));
    printf("%s+--Algo ID: %d\n", myTab[0], sigB->algoID);
  }
  
  BGPSEC_SignatureSegment* seg = NULL;
  
  while (processed < length)
  {
    seg = (BGPSEC_SignatureSegment*)data;
    size = sizeof(BGPSEC_SignatureSegment) + ntohs(seg->siglen);
    processed += size;
    
    tab = (processed < length) ? myTab[1] : myTab[2];
   
    if (!simple)
    {
      printf("%s+--Signature Segment: (%d %s)\n", myTab[0], size, __byteString(size));
      printf("%s+--SKI: ", tab);
      for (size = 0; size < sizeof(seg->ski); size++)
      {
        printf ("%02X", seg->ski[size]);
      }
      printf("\n");
    }
    size = ntohs(seg->siglen);
    
    if (!simple)
      printf("%s+--Length: %d %s\n", tab, size, __byteString(size));

    // Move data to the key
    data += sizeof(BGPSEC_SignatureSegment);
    
    snprintf (str[0], STR_MAX, "%s+--Signature: ", tab);
    snprintf (str[1], STR_MAX, "%s              ", tab);
    
    if (!simple)
    {
      printf("%s", str[0]);
      printHex(data, size, str[1]);
    }
    // Move data over the key
    data += size;
  }

  return length;
}

/**
 * Print the BGPSEC Path attribute information
 * 
 * @param pa The BGP Path Attribute
 * @param tab The tabulator of this attribute. (if NULL then it will be replaced 
 *            with TAB_2
 * @param simple Indicates if the simple printer has to be used.
 * @param more Identifies if more attributes re to come.
 * 
 * @return true if the attributes data was included in the print.
 */
bool printBGPSEC_PathAttr(BGP_PathAttribute* pa, char* tab, bool simple, 
                          bool more)
{
  bool extended = (pa->attr_flags & BGP_UPD_A_FLAGS_EXT_LENGTH) > 0;
  int length  = 0;
  int attrLen = 0;  
  
  if (extended)
  {
    length  = ntohs(((BGPSEC_Ext_PathAttribute*)pa)->attrLength);
    attrLen = length + sizeof(BGPSEC_Ext_PathAttribute);
  }
  else
  {
    length  = ((BGPSEC_Norm_PathAttribute*)pa)->attrLength;
    attrLen = length + sizeof(BGPSEC_Norm_PathAttribute);    
  }
  
  char myTab[TAB_MAX];
  memset(myTab, '\0', TAB_MAX);

  if (tab == NULL)
  {
    tab = "";
  }
  
  if (!simple)
  {
    if (more)
    {
      snprintf(myTab, TAB_MAX, "%s|%s", tab, TAB_2);
    }
    else
    {
      snprintf(myTab, TAB_MAX, "%s %s", tab, TAB_2);    
    }
  }
  
  // here pass tab rather than myTab because the additional tabs will be 
  // added in __printDef...
  if (!simple)
    __printDefaultPAttrHdr(pa, "BGPSEC Path Attribute", attrLen, length, NULL, 
                           tab, more);
  else
    printf("%s", PRN_SIMPLE_SECPATH);

  // Goto the beginning of the real data.
  u_int8_t* data = (u_int8_t*)pa + (attrLen - length);
  u_int8_t* end = (u_int8_t*)pa + attrLen;
  data += __printBGPSEC_SecurePath(data, myTab, simple);
  
  while (data < end)
  {
    data += __printBGPSEC_SignatureBlockPath(data, attrLen - length, simple, 
                                             myTab);
  }
  if (data != end)
  {
    printf ("%s+--Malformed Attribute!\n", myTab);
    printHex(data, (int)(end-data), "          ");     
  }
  
  return true;
}

////////////////////////////////////////////////////////////////////////////////
// Determine Path Attribute type
////////////////////////////////////////////////////////////////////////////////

/**
 * Determines if a parameter was printed prior and therefore sets the comma.
 * This function modifies the value firstToPrint and only applies to simple
 * mode.
 * 
 * @param simple If simple mode is requested.
 * @param firstToPrint Pointer to the bool variable containing the information 
 *                     if already parameters were printed.
 * 
 * @since 0.2.0.12
 */
static void __processFirstSimpleToPrint(bool simple, bool* firstToPrint)
{
  if (simple)
  {
    if (!*firstToPrint)
    {
      printf(", ");
    }
    else
    {
      *firstToPrint = false;
    }
  }
}

/**
 * Print the Path Attribute of the update message. 
 * 
 * @param data Data buffer pointing to the beginning of the attribute.
 * @param buffSize The total number of bytes in the buffer left.
 * @param isAS4 Indicates if AS numbers in AS_PATh are 4 byte numbers (true) or
 *              2 byte numbers (false)
 * @param simple Indicates if the data should be printed in wireshark like form 
 *               or as a simple AS path with all its prefixes.
 * @param tab The tabulator of this attribute. (if NULL then it will be replaced 
 *            with TAB_2
 * @param firstToPrint (IN/OUT) This parameter is used for simple mode to 
 *                determine if this path attribute is the first to be printed. 
 *                In this case do NOT print a leading ',' comma. If this 
 *                parameter is printed this value will be set to false and 
 *                returned.
 * 
 * @return the number of bytes for the complete attribute.
 */
static int _printPathAttr(u_int8_t* data, int buffSize, bool isAS4, bool simple,
                          char* tab, bool* firstToPrint)
{
  if (tab == NULL)
  {
    tab = TAB_2;
  }
  
  // Print each path attribute
  BGP_PathAttribute* pa = (BGP_PathAttribute*)data;
  u_int8_t* ptr = data + sizeof(BGP_PathAttribute);
  int length, attrLen = 0;
  bool printData = !simple;
  
  if (pa->attr_flags & BGP_UPD_A_FLAGS_EXT_LENGTH) 
  {
    u_int16_t* len = (u_int16_t*)ptr;
    length  = ntohs(*len);
    ptr += 2;
    attrLen = sizeof(BGP_PathAttribute) + 2 + length;
  }
  else
  {
    length  = *ptr;
    ptr++;
    attrLen = sizeof(BGP_PathAttribute) + 1 + length;    
  }
  
  // See how much bytes are left in the buffer after the attribute is printed.
  // This is important for the tab
  buffSize -= attrLen;

  char myTab[TAB_MAX];
  memset (myTab, '\0', TAB_MAX);
  snprintf(myTab, TAB_MAX, "%s%s", tab, TAB_2);
  
  if (!simple)
  {
    printf ("%s+--", myTab);
  }
  
  bool more = buffSize > 0;
  char* cAttrName   = "COMMUNITY\0";
  char* cSimpleName = PRN_SIMPLE_CA;
  
  switch (pa->attr_type_code)
  {
    case BGP_UPD_A_TYPE_ORIGIN:
      if (!simple)
      {
        printData = !__printORIGIN((BGP_Upd_Attr_Origin*)pa, myTab, more);
      }
      break;
    case BGP_UPD_A_TYPE_AS_PATH:
      __processFirstSimpleToPrint(simple, firstToPrint);
      printData = !__printAS_PATH(pa, isAS4, simple, attrLen, length, myTab, 
                                  more) && !simple;
      break;
    case BGP_UPD_A_TYPE_AS4_PATH:
      __processFirstSimpleToPrint(simple, firstToPrint);
      // The AS4_PATH attribute uses 4 byte SN numbers
      printData = !__printAS_PATH(pa, true, simple, attrLen, length, myTab, 
                                  more) && !simple; 
      break;
    case BGP_UPD_A_TYPE_NEXT_HOP:
      if (!simple)
      {
        printData = !__printNEXT_HOP((BGP_Upd_Attr_NextHop*)pa, myTab, more);
      }
      break;
    case BGP_UPD_A_TYPE_MED:
      if (!simple)
      {
        __printDefaultPAttrHdr(pa, "MULTI_EXIT_DISC\0", attrLen, length, NULL, 
                               myTab, more);
      }
      break;
    case BGP_UPD_A_TYPE_LOC_PREF:
      if (!simple)
      {
        __printDefaultPAttrHdr(pa, "LOCAL_PREF\0", attrLen, length, NULL, 
                               myTab, more);
      }
      break;
    case BGP_UPD_A_TYPE_ATOM_AGG:
      if (!simple)
      {
        __printDefaultPAttrHdr(pa, "ATOM_AGGR\0", attrLen, length, NULL,
                               myTab, more);
      }
      break;
    case BGP_UPD_A_TYPE_AGGR:
      if (!simple)
      {
        __printDefaultPAttrHdr(pa, "AGGR\0", attrLen, length, NULL,
                               myTab, more);
      }
      break;
    case BGP_UPD_A_TYPE_EXT_COMM:
      cAttrName   = "EXTENDED_COMMUNITIES\0";
      cSimpleName = PRN_SIMPLE_ECA;
    case BGP_UPD_A_TYPE_COMMUNITY:
      __processFirstSimpleToPrint(simple, firstToPrint);
      // @TODO: Create its own player for this.
      if (!simple)
      {
        __printDefaultPAttrHdr(pa, cAttrName, attrLen, length, NULL, myTab, more);
      }
      else
      {
        int idx1 = 0;
        int idx2 = 0; 
        while (idx1 < length)
        {
          printf ("%s", cSimpleName);
          for (idx2 = 0; (idx2 < 8) && (idx1 < length); idx2++, idx1++)
          {
            printf ("%02X", *ptr);
            ptr++;
          }
          //printf (" ");
          if (idx1 < length)
          {
            printf (", ");
          }
        }
      }
      break;
    case BGP_UPD_A_TYPE_MP_REACH_NLRI:
      __processFirstSimpleToPrint(simple, firstToPrint);
      printData = !__printMP_REACH_NLRI((BGP_Upd_Attr_MPNLRI_1*)pa, attrLen, 
                                        myTab, simple, more);
      break;
    case BGP_UPD_A_TYPE_BGPSEC:
      __processFirstSimpleToPrint(simple, firstToPrint);
      printData = !printBGPSEC_PathAttr(pa, myTab, simple, more);
      break;
    default: 
      if (!simple)
      {
        __printDefaultPAttrHdr(pa, "UNKNOWN\0", attrLen, length, NULL,
                               myTab, more);
      }
      break;
  }
  
  if (printData)
  {
    char str1[STR_MAX];
    char str2[STR_MAX];
    memset(str1, '\0', STR_MAX);
    memset(str2, '\0', STR_MAX);
    if (buffSize > 0)
    {
      snprintf(str1, STR_MAX, "%s|%s+--data: ", myTab, TAB_2);
    }
    else
    {
      snprintf(str1, STR_MAX, "%s %s+--data: ", myTab, TAB_2);
    }
    memset(str2, ' ', strlen(str1));
    printf ("%s", str1);
    printHex(ptr, length, str2);
  }
  
  return attrLen;
}

/**
 * Print the prefix NLRI using the provided title.
 * This function was originally part of _printNLRI.
 * 
 * @param title The title to be used (NLRI, Withdrawn route, ...).
 * @param data The data pointing to the prefix length.
 * @param length The length of data to be used.
 * @param tab The tab to be used.
 * @param simple Indicates if the printout is simple or tree.
 * @param isAnnounced (only for simple, determines the prefix type - announced 
 *                     or withdrawn - which is needed to determine the 
 *                     string prefix.
 * 
 * @sinec 0.2.0.13
 */
static void _printPrefix(char* title, u_int8_t* data, int length, char* tab, 
                         bool simple, bool isAnnounced)
{
  u_int8_t pLen   = 0;
  u_int8_t pBytes = 0;
  char     pIP[16]; // need to be memset for each loop
  char*    str    = NULL;
  
  while (length > 0)
  {
    // Initialize the prefix string
    char pIP[16];
    memset (pIP, '\0', 16);
    str = pIP;
    
    // Get the prefix length and determine the number of bytes used for the 
    // prefix.
    pLen = *data;
    
    data++;
    length--;
    
    pBytes = numBytes(pLen);
        
    if (length < pBytes)
    {
      snprintf (pIP, 16, "malformed"); 
    }
    else
    {
      // now generate the prefix
      int bytePos = 0;
      int byteVal = 0;
      while (bytePos < 4)
      {
        bytePos++;
        byteVal = 0;
        if (pBytes > 0)
        {
          byteVal = *data;
          length--;
          data++;
          pBytes--;
        }
        str += sprintf(str, "%d", byteVal);
        if (bytePos < 4)
        {
          str += sprintf(str, ".");
        }
      }
      
      if (!simple)
      {
        printf ("%s %s+--%s/%d\n", tab, TAB_2, pIP, pLen);

        printf ("%s %s %s+--%s prefix length: %d\n", tab, TAB_2, TAB_2, 
                                                     title, pLen);
        printf ("%s %s %s+--%s prefix: %s\n", tab, TAB_2, TAB_2, title, pIP);
      }
     else
     {
       printf ("%s%s/%d", isAnnounced ? PRN_SIMPLE_PREFIX_A
                                      : PRN_SIMPLE_PREFIX_W, 
                          pIP, pLen);
       if (length != 0)
       {
         printf (", ");
       }
     }
    }
  }  
}

/**
 * Print the NLRI
 * @param data the data stream
 * @param length The length of the buffer containing the NLRI
 * @param simple Indicates if the NLRI should be printed out as a simple
 *               string (true) or in wireshark form (false).
 * @param tab The tabulator for the NLRI
 */
static void _printNLRI(u_int8_t* data, int length, bool simple, char* tab)
{
  if (length > 0)
  {
    if (!simple)
    {
      printf ("%s+-- Network layer reachability information: %d %s\n", tab, 
              length, __byteString(length));
    }
  }

  _printPrefix("NLRI\0", data, length, tab, simple, true);
}

/**
 * Print the BGPS Update Message
 * 
 * @param update The update message as complete BGP packet. 
 * @param simple Indicates if the update has to be printed in a simple form,
 *               not Wireshark like.
 */
void printUpdateData(BGP_UpdateMessage_1* update, bool isAS4, bool simple)
{
  u_int16_t updateLength = ntohs(update->messageHeader.length);
  u_int8_t* start = (u_int8_t*)update;
  u_int8_t* data = start + sizeof(BGP_UpdateMessage_1);  
  u_int8_t* end = start + updateLength;  
  u_int16_t length = ntohs(update->withdrawn_routes_length);

  if (!simple)
  {
    printf ("%s+--Unfeasible routes length: %d\n", TAB_2, length);
    if (length != 0)
    {
      printf ("%s+--Withdrawn routes:\n", TAB_2);
    }
  }
  
  _printPrefix("Withdrawn route", data, length, TAB_2, simple, false);
  data += length;
  
  BGP_UpdateMessage_2* upd2 = (BGP_UpdateMessage_2*)data;
  data += sizeof(BGP_UpdateMessage_2);
  length = ntohs(upd2->path_attr_length);
  if (!simple)
  {
    printf ("%s+--total path attr length: %d\n", TAB_2, length);
  }
  
  // Now print all path attributes
  int processed = 0;
  u_int16_t dataLeft = (u_int16_t)(end-data);
  // Now determine the tab that is used show if data after the attributes is
  // available (e.g. the NLRI list)
  char* tab = (dataLeft - length) > 0 ? TAB_3W : TAB_3;
  // reset the dataLeft to only represent the path attribute data. This is 
  // important to determine the internal tab.
  dataLeft = length;
  // Needed to determine if a comma needs to be place prior the attribute.
  bool firstToPrint = true;
  while (length > processed && data < end)
  {
    dataLeft = length - processed;
//    processed += _printPathAttr(data+processed, dataLeft, tab);
    processed += _printPathAttr(data+processed, dataLeft, isAS4, simple, tab,
                                &firstToPrint);
  }
  data += processed;

  if (data < end)
  {
    length = (u_int16_t)(end - data);
    if (!firstToPrint)
    {
      // It might be the first one for iBGP originations where no AS PATH 
      // exists.
      printf(", ");
    }
    _printNLRI(data, length, simple, TAB_2);
  }
  
  // Simple does not print a CR
  if (simple)
  {
    printf ("\n");
  }
}
