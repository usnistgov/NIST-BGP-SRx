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
 * IPv4 and IPv6 address and prefix structures and functions.
 * log.h is used for error message handling.
 * 
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed unused variables in cpyPrefix  
 * 0.3.0    - 2013/01/28 - oborchert
 *            * Added method IPtoInt that allows to convert an IP string or 
 *              integer string into an unsigned integer.
 *            * Added version control.
 * 0.2.0    - 2011/11/01 - oborchert
 *            * Extended.
 * 0.1.0    - 2010/02/03 - pgleichm
 *            * Code Created
 * -----------------------------------------------------------------------------
 */
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "util/prefix.h"
#include "util/log.h"

bool strToIPv4Address(const char* str, IPv4Address* ipOut) {
  if (!inet_aton(str, &(ipOut->in_addr))) { 
    RAISE_ERROR("Invalid IPv4 address '%s'", str);
    return false;
  }
  return true;
}

bool strToIPv6Address(const char* str, IPv6Address* ipOut) {
  if (inet_pton(AF_INET6, str, (void*)ipOut) < 1) {
    RAISE_ERROR("Invalid IPv6 address '%s'", str);
    return false;
  }
  return true;
}

bool strToIPAddress(const char* str, IPAddress* ipOut) {
  if (str == NULL) {
    RAISE_ERROR("IP address is (null)");
    return false;
  }

  // v4
  if (strchr(str, '.') != NULL) {
    ipOut->version = 4;
    return strToIPv4Address(str, &(ipOut->addr.v4));
  }

  // v6
  ipOut->version = 6;
  return strToIPv6Address(str, &(ipOut->addr.v6));
}

bool strToIPPrefix(const char* str, IPPrefix* prefixOut) {
  char* spos;
  char  ipBuf[MAX_IP_V6_STR_LEN]; // We can't modify .data (r/o)
  int   ipLen;

  // Search for the slash
  spos = strchr(str, '/');
  if (spos == NULL) {
    RAISE_ERROR("Invalid prefix (missing '/') - '%s'", str);
    return false;
  }

  // Parse the IP
  ipLen = spos - str;
  memcpy(ipBuf, str, ipLen);
  ipBuf[ipLen] = '\0';

  if (!strToIPAddress((const char*)ipBuf, &(prefixOut->ip))) {
    return false;
  }

  // Parse the prefix length (CIDR)
  prefixOut->length = (uint8_t)atoi(spos + 1);
  
  // Does the prefix length make sense
  if ((prefixOut->length == 0) 
      || (prefixOut->length > GET_MAX_PREFIX_LEN(prefixOut->ip))) {
    RAISE_ERROR("Invalid prefix length '%s'", str);
    return false;  
  }
  
  return true;
}

const char* ipV4AddressToStr(IPv4Address* ip, char* dest, size_t size) {
  if (inet_ntop(AF_INET, (const void*)ip, dest, size) == NULL) {
    RAISE_SYS_ERROR("Invalid IPv4 address");
    return NULL;
  }
  return dest;
}

const char* ipV6AddressToStr(IPv6Address* ip, char* dest, size_t size) {
  if (inet_ntop(AF_INET6, (const void*)ip, dest, size) == NULL) {
    RAISE_SYS_ERROR("Invalid IPv6 address");
    return NULL;
  }
  return dest;
}

const char* ipAddressToStr(IPAddress* ip, char* dest, size_t size) {

  if ((ip == NULL) || inet_ntop(GET_AF_OF_IP(*ip), (const void*)&(ip->addr), 
                                dest, size) == NULL) {
    RAISE_SYS_ERROR("Invalid IP address");
    return NULL;
  }
  return dest;
}

const char* ipPrefixToStr(IPPrefix* prefix, char* dest, size_t size) {
  size_t  ipLen, plLen;

  // Convert the IP
  if (ipAddressToStr(&prefix->ip, dest, size) == NULL) {
    return NULL;
  }

  // Calculate the prefix length's number of characters
  plLen = (prefix->length < 10) ? 1 : ((prefix->length < 100) ? 2 : 3);

  // Enough space?
  ipLen = strlen(dest);
  if (ipLen + plLen + 2 > size) { // Slash and \0
    RAISE_ERROR("Resulting IP Prefix to long for the buffer");
    return NULL;
  }

  // Attach prefix length
  sprintf(&dest[ipLen], "/%d", prefix->length);
   
  return dest;
}


/**
 * Copy the contents of source prefix into destination prefix.
 * 
 * @param dst The destination prefix
 * @param src The source prefix
 * 
 * @return true if the prefix copy was successful.
 */
extern bool cpyPrefix(IPPrefix* dst, IPPrefix* src)
{
  bool retVal = (src != NULL) && (dst != NULL);
  
  if (retVal)
  {
    dst->length     = src->length;
    dst->ip.version = src->ip.version;
    memcpy(dst->ip.addr.v6.u8, src->ip.addr.v6.u8, 16);
  }  
  return retVal;
}

/**
 * Copy the contents of source IPv4Address into destination IPv4Address.
 * 
 * @param dst The destination IPv4Address
 * @param src The source IPv4Address
 * 
 * @return true if the IPv4Address copy was successful.
 */
extern bool cpyIPv4Address(IPv4Address* dst, IPv4Address* src)
{
  bool retVal = (src != NULL) && (dst != NULL);
  
  if (retVal)
  {
    dst->u32 = src->u32;    
  }  
  return retVal;  
}

/**
 * Copy the contents of source IPv6Address into destination IPv6Address.
 * 
 * @param dst The destination IPv6Address
 * @param src The source IPv6Address
 * 
 * @return true if the IPv6Address copy was successful.
 */
extern bool cpyIPv6Address(IPv6Address* dst, IPv6Address* src)
{
  bool retVal = (src != NULL) && (dst != NULL);
  
  if (retVal)
  {
    memcpy(dst->u8, src->u8, 16);
  }  
  return retVal;    
}

/**
 * This function converts a string IPv4 or String number into an unsigned
 * 32 bit integer.
 *
 * @param IPStr The integer number or IPv4 address as string
 * 
 * @return The integer value.
 * 
 * @since 0.3.0
 */
extern uint32_t IPtoInt(const char* IPStr)
{
  uint32_t ipInt = 0;
  IPAddress ipAddress;
  if (strchr(IPStr, '.') != NULL)
  {
    if (strToIPAddress(IPStr, &ipAddress))
    {
      // Regardless of type, only use the v4 part of it
      ipInt = ntohl(ipAddress.addr.v4.u32);
    }
    else
    {
      ipInt = (uint32_t)atoll(IPStr);
    }
  }
  else
  {
    ipInt = (uint32_t)atoll(IPStr);
  }
  
  return ipInt;  
}

