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
 * @version 0.2.0.1
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 *  0.2.0.1 - 2016/06/25 - oborchert
 *            * Fixed wrong format in printout of path attributes.
 *  0.2.0.0 - 2016/05/11 - oborchert
 *            * Fixed BZ960: Invalid next hop IP encoding
 *          - 2016/05/10 - oborchert
 *            * Fixed formating error in _printNLRI (BZ950)
 *  0.1.1.0 - 2016/03/25 - oborchert
 *            * Changed static function __printBGPSEC into function 
 *              printBGPSEC_PathAttr which is added to the header.
 *          - 2016/03/18 - borchert
 *            * Created File.
 */

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include "bgp/BGPHeader.h"
#include "bgp/printer/BGPHeaderPrinter.h"
#include "bgp/printer/BGPUpdatePrinter.h"
#include "bgp/printer/BGPPrinterUtil.h"


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
 * @return true if the attributes data was included in the print.
 */
static bool __printNEXT_HOP(BGP_Upd_Attr_NextHop* nh, char* tab, bool more)
{
  u_int32_t nextHop = ntohl(nh->nextHop);
  u_int8_t* bytes = (u_int8_t*)&nextHop;
  char  title[STR_MAX];
  const char* tName="NEXT_HOP\0";
  snprintf (title, STR_MAX, "%s: %d.%d.%d.%d%c", tName, 
            bytes[3], bytes[2], bytes[1], bytes[0], '\0'); 
  
  printf ("%s:", tName);
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
// BGPSEC Path attribute
////////////////////////////////////////////////////////////////////////////////

/**
 * Process the secure path information
 * 
 * @param data the updates attribute buffer
 * @param tab The tabulator of this attribute. (if NULL then it will be replaced 
 *            with TAB_2
 * 
 * @return the number of bytes processed
 */
static int __printBGPSEC_SecurePath(u_int8_t* data, char* tab)
{
  if (tab == NULL)
  {
    tab = TAB_2;
  }
  
  char myTab[3][TAB_MAX];
  memset (myTab,  '\0', TAB_MAX*3);
  snprintf (myTab[0], TAB_MAX, "%s|%s", tab, TAB_2);
  snprintf (myTab[1], TAB_MAX, "%s|%s", myTab[0], TAB_2);
  snprintf (myTab[2], TAB_MAX, "%s %s", myTab[0], TAB_2);
  
  BGPSEC_SecurePath* sp = (BGPSEC_SecurePath*)data;
  data += sizeof(BGPSEC_SecurePath);
  int processed = sizeof(BGPSEC_SecurePath);
  int size = 0;
  int length = ntohs(sp->length);
  
  printf("%s+--Secure Path (%d %s)\n", tab, length, __byteString(length));
  printf("%s+--Length: %d %s\n", myTab[0], length, __byteString(length));
  
  BGPSEC_SecurePathSegment* seg = NULL;
  
  while (processed < length)
  {
    seg = (BGPSEC_SecurePathSegment*)data;
    size = sizeof(BGPSEC_SecurePathSegment);
    // Move to next segment
    data += size;
    processed += size;
    
    u_int32_t asn = ntohl(seg->asn);
    tab = processed < length ? myTab[1] : myTab[2];
    printf("%s+--Secure Path Segment: (%d %s)\n", myTab[0], 
                                                  size, __byteString(size));
    printf("%s+--pCount: %d\n", tab, seg->pCount);
    printf("%s+--Flags: %d\n", tab, seg->flags);
    printf("%s+--AS number: %d (%d.%d)\n", tab, 
                                           asn, (asn >> 16), (asn & 0xFFFF));
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
 * @param tab The tabulator of this attribute. (if NULL then it will be replaced 
 *            with TAB_2
 * 
 * @return the number of bytes processed
 */
static int __printBGPSEC_SignatureBlockPath(u_int8_t* data, int buffSize,
                                            char* tab)
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
  
  printf("%s+--Signature Block (%d %s)\n", tab, length, __byteString(length));
  printf("%s+--Length: %d %s\n", myTab[0], length, __byteString(length));
  printf("%s+--Algo ID: %d\n", myTab[0], sigB->algoID);
  
  BGPSEC_SignatureSegment* seg = NULL;
  
  while (processed < length)
  {
    seg = (BGPSEC_SignatureSegment*)data;
    size = sizeof(BGPSEC_SignatureSegment) + ntohs(seg->siglen);
    processed += size;
    
    tab = (processed < length) ? myTab[1] : myTab[2];
    
    printf("%s+--Signature Segment: (%d %s)\n", myTab[0], size, __byteString(size));
    printf("%s+--SKI: ", tab);
    for (size = 0; size < sizeof(seg->ski); size++)
    {
      printf ("%02X", seg->ski[size]);
    }
    printf("\n");
    size = ntohs(seg->siglen);
    printf("%s+--Length: %d %s\n", tab, size, __byteString(size));

    // Move data to the key
    data += sizeof(BGPSEC_SignatureSegment);
    
    snprintf (str[0], STR_MAX, "%s+--Signature: ", tab);
    snprintf (str[1], STR_MAX, "%s              ", tab);
    printf("%s", str[0]);
    printHex(data, size, str[1]);    
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
 * 
 * @return true if the attributes data was included in the print.
 */
bool printBGPSEC_PathAttr(BGPSEC_PathAttribute* pa, char* tab, bool more)
{
  int length = ntohs(pa->attrLength);
  int attrLen  = length + sizeof(BGPSEC_PathAttribute);
  char myTab[TAB_MAX];
  if (tab == NULL)
  {
    tab = "";
  }
  memset(myTab, '\0', TAB_MAX);
  if (more)
  {
    snprintf(myTab, TAB_MAX, "%s|%s", tab, TAB_2);
  }
  else
  {
    snprintf(myTab, TAB_MAX, "%s %s", tab, TAB_2);    
  }
  
  // here pass tab rather than myTab because the additional tabs will be 
  // added in __printDef...
  __printDefaultPAttrHdr((BGP_PathAttribute*)pa, "BGPSEC Path Attribute", 
                         attrLen, length, NULL, tab, more);

  // Goto the beginning of the real data.
  u_int8_t* data = (u_int8_t*)pa + (attrLen - length);
  u_int8_t* end = (u_int8_t*)pa + attrLen;
  data += __printBGPSEC_SecurePath(data, myTab);
  
  while (data < end)
  {
    data += __printBGPSEC_SignatureBlockPath(data, attrLen - length, myTab);
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
 * Print the Path Attribute of the update message.
 * 
 * @param data data buffer pointing to the beginning of the attribute.
 * @param buffSize The total number of bytes in the buffer left.
 * @param tab The tabulator of this attribute. (if NULL then it will be replaced 
 *            with TAB_2
 * 
 * @return the number of bytes for the complete attribute.
 */
static int _printPathAttr(u_int8_t* data, int buffSize, char* tab)
{
  if (tab == NULL)
  {
    tab = TAB_2;
  }
  
  // Print each path attribute
  BGP_PathAttribute* pa = (BGP_PathAttribute*)data;
  u_int8_t* ptr = data + sizeof(BGP_PathAttribute);
  int length, attrLen = 0;
  bool printData = true;
  
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
  
  printf ("%s+--", myTab);          
          
          
  switch (pa->attr_type_code)
  {
    case BGP_UPD_A_TYPE_ORIGIN:
      printData = !__printORIGIN((BGP_Upd_Attr_Origin*)pa, myTab, buffSize > 0);
      break;
    case BGP_UPD_A_TYPE_AS_PATH: 
      printData = __printDefaultPAttrHdr(pa, "AS_PATH\0", attrLen, length, NULL, 
                                         myTab, buffSize > 0) > 0;
      break;
    case BGP_UPD_A_TYPE_NEXT_HOP:
      printData = !__printNEXT_HOP((BGP_Upd_Attr_NextHop*)pa, myTab, 
                                   buffSize > 0);
      break;
    case BGP_UPD_A_TYPE_MED:
      __printDefaultPAttrHdr(pa, "MULTI_EXIT_DISC\0", attrLen, length, NULL, 
                             myTab, buffSize > 0);
      break;
    case BGP_UPD_A_TYPE_LOC_PREF:
      __printDefaultPAttrHdr(pa, "LOCAL_PREF\0", attrLen, length, NULL,
                             myTab, buffSize > 0);
      break;
    case BGP_UPD_A_TYPE_ATOM_AGG:
      __printDefaultPAttrHdr(pa, "ATOM_AGGR\0", attrLen, length, NULL,
                             myTab, buffSize > 0);
      break;
    case BGP_UPD_A_TYPE_AGGR:
      __printDefaultPAttrHdr(pa, "AGGR\0", attrLen, length, NULL,
                             myTab, buffSize > 0);
      break;
    case BGP_UPD_A_TYPE_EXT_COMM:
      __printDefaultPAttrHdr(pa, "EXTENDED_COMMUNITIES\0", attrLen, length, 
                             NULL, myTab, buffSize > 0);
      break;
    case BGP_UPD_A_TYPE_BGPSEC:
      printData = !printBGPSEC_PathAttr((BGPSEC_PathAttribute*)pa, myTab, 
                                        buffSize > 0);
      break;
    default: 
      __printDefaultPAttrHdr(pa, "UNKNOWN\0", attrLen, length, NULL,
                             myTab, buffSize > 0);
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
 * Print the NLRI
 * @param data the data stream
 * @param length The length of the buffer containing the NLRI
 * @param tab The tabulator for the NLRI
 */
static void _printNLRI(u_int8_t* data, int length, char* tab)
{
  if (length > 0)
  {
    u_int8_t pLen = *data;
    data++;

    char pIP[16];
    memset (pIP, '\0', 16);
    char* ptr = pIP;
    
    printf ("%s+-- Network layer reachability information: %d %s\n", tab, 
            length, __byteString(length));
    length--;
    
    // now generate the prefix
    int bytePos = 0;
    int byteVal = 0;
    while (bytePos < 4)
    {
      bytePos++;
      byteVal = (length != 0) ? *data : 0; 
      ptr += sprintf(ptr, "%d", byteVal);
      if (bytePos < 4)
      {
        ptr += sprintf(ptr, ".");
      }
      
      length--;
      data++;
    }
    printf ("%s %s+--%s/%d\n", tab, TAB_2, pIP, pLen);
    
    printf ("%s %s %s+--NLRI prefix length: %d\n", tab, TAB_2, TAB_2, pLen);
    printf ("%s %s %s+--NLRI prefix: %s\n", tab, TAB_2, TAB_2, pIP);
  }
}

/**
 * Print the BGPS Update Message
 * 
 * @param update The update message as complete BGP packet. 
 * 
 */
void printUpdateData(BGP_UpdateMessage_1* update)
{
  u_int16_t updateLength = ntohs(update->messageHeader.length);
  u_int8_t* start = (u_int8_t*)update;
  u_int8_t* data = start + sizeof(BGP_UpdateMessage_1);  
  u_int8_t* end = start + updateLength;
  
  u_int16_t length = ntohs(update->withdrawn_routes_length);
  printf ("%s+--withdrawn_routes_length: %d\n", TAB_2, length);          
  if (length > 0)
  {
    printf ("%s+--withdrawn_routes: ", TAB_2);
    printHex(data, length,"                       ");
    data += length;
  }
  
  BGP_UpdateMessage_2* upd2 = (BGP_UpdateMessage_2*)data;
  data += sizeof(BGP_UpdateMessage_2);
  length = ntohs(upd2->path_attr_length);
  printf ("%s+--total_path_attr_length: %d\n", TAB_2, length);
  
  // Now print all path attributes
  int processed = 0;
  u_int16_t dataLeft = (u_int16_t)(end-data);
  // Now determine the tab that is used show if data after the attributes is
  // available (e.g. the NLRI list)
  char* tab = (dataLeft - length) > 0 ? TAB_3W : TAB_3;
  // reset the dataLeft to only represent the path attribute data. This is 
  // important to determine the internal tab.
  dataLeft = length; 
  while (length > processed && data < end)
  {
    dataLeft = length - processed;
//    processed += _printPathAttr(data+processed, dataLeft, tab);
    processed += _printPathAttr(data+processed, dataLeft, tab);
  }
  data += processed;

  if (data < end)
  {
    length = (u_int16_t)(end - data);
    _printNLRI(data, length, TAB_2);
  }
}
