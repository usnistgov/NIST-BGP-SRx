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
 * @version 0.3.2
 *
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *   0.3.2 - 2017/02/16 - oborchert
 *           * Fixed BUG in strToIPv6Address.
 *   0.3.1 - 2015/09/09 - oborchert
 *           * Added defines ADDR_IP_V4/6 and replaced usage of integer values.
 *         - 2015/08/21 - oborchert
 *           * Changed source location from util to antd-util
 *           * Managed source moved into its own library
 *           * Copied function documentation into c file.
 *           * Activate / Deactivate logging using USE_LOGGING
 *           * Removed unused variable
 *   0.3.0 - 2013/01/28 - oborchert
 *           * Added method IPtoInt that allows to convert an IP string or 
 *             integer string into an unsigned integer.
 *           * Added version control.
 *   0.2.0 - 2011/11/01 - oborchert
 *           * Extended.
 *   0.1.0 - 2010/02/03 - pgleichm
 *           * Code Created
 * -----------------------------------------------------------------------------
 */
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "prefix.h"

#ifdef USE_LOGGING
#include "log.h"
#endif
/**
 * Parses textual representation of an IPv4 address.
 * 
 * @param str Character string ("a.b")
 * @param ipOut (out) Destination for the interpreted address
 * 
 * @return false = parsing failed - invalid format
 */
bool strToIPv4Address(const char* str, IPv4Address* ipOut) 
{
  if (!inet_aton(str, &(ipOut->in_addr))) 
  { 
#ifdef USE_LOGGING
    RAISE_ERROR("Invalid IPv4 address '%s'", str);
#endif
    return false;
  }
  return true;
}

/**
 * Parses textual representation of an IPv6 address.
 * 
 * @param str Character string ("a:b")
 * @param ipOut (out) Destination for the interpreted address
 * 
 * @return false = parsing failed - invalid format
 */
bool strToIPv6Address(const char* str, IPv6Address* ipOut) 
{
  if (!inet_pton(AF_INET6, str, &(ipOut->in_addr))) 
  {
#ifdef USE_LOGGING
    RAISE_ERROR("Invalid IPv6 address '%s'", str);
#endif
    return false;
  }
  return true;
}

/**
 * Parses textual representation of an IP address.
 * 
 * @param str Character string ("a.b" or "a:b")
 * @param ipOut (out) Destination for the interpreted address
 * 
 * @return false = parsing failed - invalid format
 */
bool strToIPAddress(const char* str, IPAddress* ipOut) 
{
  if (str == NULL) 
  {
#ifdef USE_LOGGING
    RAISE_ERROR("IP address is (null)");
#endif
    return false;
  }

  // v4
  if (strchr(str, '.') != NULL) 
  {
    ipOut->version = ADDR_IP_V4;
    return strToIPv4Address(str, &(ipOut->addr.v4));
  }

  // v6
  ipOut->version = ADDR_IP_V6;
  return strToIPv6Address(str, &(ipOut->addr.v6));
}

/**
 * Parses textual representation of an IP prefix
 * 
 * @param str Character string ("length")
 * @param prefixOut (out) Destination for the interpreted prefix
 * 
 * @return false = parsing failed - invalid format
 */
bool strToIPPrefix(const char* str, IPPrefix* prefixOut) 
{
  char* spos;
  char  ipBuf[MAX_IP_V6_STR_LEN]; // We can't modify .data (r/o)
  int   ipLen;

  // Search for the slash
  spos = strchr(str, '/');
  if (spos == NULL) 
  {
#ifdef USE_LOGGING
    RAISE_ERROR("Invalid prefix (missing '/') - '%s'", str);
#endif
    return false;
  }

  // Parse the IP
  ipLen = spos - str;
  memcpy(ipBuf, str, ipLen);
  ipBuf[ipLen] = '\0';

  if (!strToIPAddress((const char*)ipBuf, &(prefixOut->ip))) 
  {
    return false;
  }

  // Parse the prefix length (CIDR)
  prefixOut->length = (uint8_t)atoi(spos + 1);
  
  // Does the prefix length make sense
  if ((prefixOut->length == 0) 
      || (prefixOut->length > GET_MAX_PREFIX_LEN(prefixOut->ip))) 
  {
#ifdef USE_LOGGING
    RAISE_ERROR("Invalid prefix length '%s'", str);
#endif
    return false;  
  }
  
  return true;
}

/** 
 * Returns a textual representation of an IPv4 address.
 *
 * @param ip IPv4 address
 * @param dest (out) Buffer
 * @param size Size of the buffer
 * 
 * @return Resulting text (= dest), or \c NULL in case of an error
 */
const char* ipV4AddressToStr(IPv4Address* ip, char* dest, size_t size) 
{
  if (inet_ntop(AF_INET, (const void*)ip, dest, size) == NULL) 
  {
#ifdef USE_LOGGING
    RAISE_SYS_ERROR("Invalid IPv4 address");
#endif
    return NULL;
  }
  return dest;
}

/** 
 * Returns a textual representation of an IPv6 address.
 *
 * @param ip IPv6 address
 * @param dest (out) Buffer
 * @param size Size of the buffer
 * 
 * @return Resulting text (= dest), or \c NULL in case of an error
 */
const char* ipV6AddressToStr(IPv6Address* ip, char* dest, size_t size) 
{
  if (inet_ntop(AF_INET6, (const void*)ip, dest, size) == NULL) 
  {
#ifdef USE_LOGGING
    RAISE_SYS_ERROR("Invalid IPv6 address");
#endif
    return NULL;
  }
  return dest;
}

/** 
 * Returns a textual representation of an IP address.
 *
 * @param ip IP address
 * @param dest (out) Buffer
 * @param size Size of the buffer
 * 
 * @return Resulting text (= dest), or \c NULL in case of an error
 */
const char* ipAddressToStr(IPAddress* ip, char* dest, size_t size) 
{
  if ((ip == NULL) || inet_ntop(GET_AF_OF_IP(*ip), (const void*)&(ip->addr), 
                                dest, size) == NULL) 
  {
#ifdef USE_LOGGING
    RAISE_SYS_ERROR("Invalid IP address");
#endif
    return NULL;
  }
  return dest;
}

/** 
 * Returns a textual representation of an IP prefix.
 *
 * @param prefix IP prefix
 * @param dest (out) Buffer
 * @param size Size of the buffer
 * 
 * @return Resulting text (= dest), or \c NULL in case of an error
 */
const char* ipPrefixToStr(IPPrefix* prefix, char* dest, size_t size) 
{
  size_t  ipLen, plLen;

  // Convert the IP
  if (ipAddressToStr(&prefix->ip, dest, size) == NULL) 
  {
    return NULL;
  }

  // Calculate the prefix length's number of characters
  plLen = (prefix->length < 10) ? 1 : ((prefix->length < 100) ? 2 : 3);

  // Enough space?
  ipLen = strlen(dest);
  if (ipLen + plLen + 2 > size) 
  { // Slash and \0
#ifdef USE_LOGGING
    RAISE_ERROR("Resulting IP Prefix to long for the buffer");
#endif
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