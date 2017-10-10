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
 * NOTE:
 * Functions starting with underscore are only to be called from within this
 * file. Therefore no additional checking is needed is some provided values
 * are NULL. entry functions specified in the header file do take cate of that.
 * 
 * 
 * This utility provides helper functions to convert a TCP BGP Hex dump into a 
 * binary stream or extract the BGPsec_PATH from a BGP UPDATE and possible
 * other functions related to BGPsec.
 * 
 * @version 0.5.0.1
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.5.0.1 - 2017/08/25 - 
 *           * Fixed compiler warnings.
 * 0.5.0.0 - 2017/06/27 - oborchert 
 *           * File created
 */
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "util/bgpsec_util.h"

/** The BGPsec_PATH attribute type value. (IANA assigned) */
#define UTIL_PAT_BGPsec 30

/**
 * Parse the given attribute and returns the BGPsec_PATH attribute if the 
 * UPDATE contains one. The returned memory is allocated using malloc and 
 * MUST be free'd by the consumer.
 * 
 * @param attr the BGP attribute to be parsed
 * @param parsed The number of parsed bytes.
 * 
 * @return The BGPsec_PATH attribute or NULL if not found.
 */
static u_int8_t* _parseBGP_PATHAttr(u_int8_t* bgpAttr, u_int16_t* parsed)
{
  *parsed = 0;
  u_int8_t*  bgpsec = NULL;
  u_int16_t* pWord  = NULL;
  u_int8_t*  ptr    = bgpAttr;
  
  // Read the attribute header
  u_int8_t  flags = *ptr;
  ptr++;
  u_int8_t  type  = *ptr;
  ptr++;
  u_int16_t length = 0;
  *parsed += 2;

  if ((flags & 0x10) != 0)
  {
    // Extended Length
    pWord  = (u_int16_t*)ptr;
    length   = ntohs(*pWord);
    ptr += 2;
    *parsed += 2;
  }
  else
  {
    // Normal Length
    length   = *ptr;
    ptr++;
    *parsed += 1;    
  }
  *parsed += length;
  
  if (type == UTIL_PAT_BGPsec)
  {    
    bgpsec = malloc(*parsed);
    memcpy(bgpsec, bgpAttr, *parsed);
  }
  
  return bgpsec;
}

/**
 * Use the given byte stream input (as hex string) and extract the 
 * BGPsec_PATH attribute out of it.
 * 
 * @param updateStr The HEX ASCII representation of the BGPsec UPDATE.
 * @param buffLen A pointer to an integer which will be filled with the 
 *                total length of the attribute. (Can be NULL)
 * 
 * @return  The buffer containing the BGPsec_PATH attribute. Must be frees 
 *          by caller.
 */
u_int8_t* util_getBGPsec_PATH(char* updateStr, u_int32_t* buffLen)
{
  int size = strlen(updateStr) / 2;
  u_int8_t* byteStream = malloc(size);
  u_int8_t* bgpsec     = NULL;
  u_int8_t* ptr        = byteStream;
  u_int16_t* pWord     = NULL;
  // Only used if buffLen is NULL
  u_int32_t tmpLen     = 0;
  if (buffLen == NULL)
  {
    buffLen = &tmpLen;
  }
  *buffLen = 0;

  // MUST be \0 terminated - Valgrind reported an error
  char num[3] = { '\0', '\0', '\0' }; 
  memset (byteStream, 0, size);
  int idx = 0;
  for (; idx < strlen(updateStr); ptr++)
  {
    num[0] = updateStr[idx++];
    num[1] = updateStr[idx++];
    *ptr = strtol(num, NULL, 16);
  }
  
  ptr = byteStream;
  // Jump over the marker
  ptr += 16;
  // Reached length field
  pWord = (u_int16_t*)ptr;
  u_int16_t updLen = ntohs(*pWord);
  u_int16_t remainder = updLen - 16;
  // Move to type field
  ptr += 2;
  remainder -= 2;
  u_int8_t type = *ptr;
  if (type == 2) // UPDATE TYPE
  {
    // Move to Withdrawn Routes Length
    ptr++;
    remainder--;
    pWord = (u_int16_t*)ptr;
    u_int16_t lenWithdrawnRoutes = ntohs(*pWord);
    // now move to the withdrawn routes
    ptr += 2;
    remainder -= 2;
    
    while (lenWithdrawnRoutes != 0)
    {
      u_int8_t length = *ptr != 0 ? ((*ptr / 8) + 1) : 0;            
      ptr++;
      remainder--;
      // Now jump over the prefix itself
      ptr       += length;
      remainder -= length;
      lenWithdrawnRoutes--;              
    }
    
    // Now read the total length pf the path attributes and then move to the 
    // first attribute.
    pWord = (u_int16_t*)ptr;
    u_int16_t totalPathAttrLen = ntohs(*pWord);
    ptr += 2;
    remainder -= 2;
       
    // If attributes are available 
    if (totalPathAttrLen <= remainder)
    {
      u_int16_t attrLen = 0;
      while (remainder > 0 && bgpsec == NULL)
      {
        bgpsec = _parseBGP_PATHAttr(ptr, &attrLen);
        *buffLen   = attrLen;
        ptr       += attrLen;
        remainder -= attrLen;
      }
      if (bgpsec == NULL)
      {
        printf ("ERROR: Given BGP update message does not contain a BGPsec_PATH!!!\n");              
      }
    }
    else
    {
      printf ("ERROR: Given BGP update message is malformed!!!\n");      
    }    
  } 
  else
  {
    printf ("ERROR: Given BGP update message is not of type UPDATE!!!\n");
  }
  
  memset (byteStream, 0, size);
  free (byteStream);
  
  return bgpsec;
}