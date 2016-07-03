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
 * @version 0.3.1
 *
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *   0.3.1 - 2015/09/09 - oborchert
 *           * Added defines ADDR_IP_V4/6 and replaced usage of integer values.
 *         - 2015/08/21 - oborchert
 *           * Changed source location from util to antd-util
 *           * Managed source moved into its own library
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
#ifndef __PREFIX_H__
#define __PREFIX_H__

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

/** An IPv4 address */
typedef union {
  struct in_addr in_addr;
  uint32_t       u32;
  uint8_t        u8[4];
} IPv4Address;

/** An IPv6 address */
typedef union {
  struct in6_addr in_addr;
  uint8_t         u8[16];
} IPv6Address;

/** An IP (4, 6) address */
typedef struct {
  uint8_t  version; // 4 or 6
  union {
    IPv4Address v4;
    IPv6Address v6;
  } addr;
} IPAddress;

/** An IP prefix */
typedef struct {
  IPAddress ip;
  uint8_t   length;
} IPPrefix;

/** Maximum length of the textual representation of an IPv4 address */
#define MAX_IP_V4_STR_LEN     16
/** Max length of the textual representation of an IPv6 address */
#define MAX_IP_V6_STR_LEN     40
/** Maximum prefix length of an IPv4 */
#define MAX_PREFIX_LEN_V4     32
/** Maximum prefix length of an IPv6 */
#define MAX_PREFIX_LEN_v6     128
/** Maximum length of the textual representation of an IPv4 prefix */
#define MAX_PREFIX_STR_LEN_V4 (MAX_IP_V4_STR_LEN + 4)
/** Maximum length of the textual representation of an IPv6 prefix */
#define MAX_PREFIX_STR_LEN_V6 (MAX_IP_V6_STR_LEN + 5)

/** Use this define going forward for IPv4 (Value == 4). */
#define ADDR_IP_V4 4
/** Use this define going forward for IPv4 (Value == 6). */
#define ADDR_IP_V6 6
/** 
 * Get the IP version for an address family.
 *
 * @param AF address family
 * 
 * @return \c 4 or \c 6
 */
#define GET_VERSION_OF_AF(AF) \
  (AF == AF_INET ? ADDR_IP_V4 : ADDR_IP_V6)

/**
 * Get the address family for an IP address.
 *
 * @param IP_ADDR An IPAddress
 * 
 * @return \c AF_INET or \c AF_INET6
 */
#define GET_AF_OF_IP(IP_ADDR) \
  (((IP_ADDR).version == ADDR_IP_V4) ? AF_INET : AF_INET6)

/**
 * Get the size in Bytes required for a specific IP version.
 *
 * @param VER \c 4 or \c 6
 * 
 * @return Size in Bytes
 */
#define GET_SIZEOF_IP_VERSION(VER) \
  (((VER) == ADDR_IP_V4) ? sizeof(IPv4Address) : sizeof(IPv6Address))

/**
 * Get the maximum prefix length for an IP address.
 *
 * @param IP_ADDR An IPAddress
 * 
 * @return Max. prefix length
 */
#define GET_MAX_PREFIX_LEN(IP_ADDR) \
  (((IP_ADDR).version == ADDR_IP_V4) ? MAX_PREFIX_LEN_V4 : MAX_PREFIX_LEN_v6)

/**
 * Parses textual representation of an IPv4 address.
 * 
 * @param str Character string ("a.b")
 * @param ipOut (out) Destination for the interpreted address
 * 
 * @return false = parsing failed - invalid format
 */
extern bool strToIPv4Address(const char* str, IPv4Address* ipOut);

/**
 * Parses textual representation of an IPv6 address.
 * 
 * @param str Character string ("a:b")
 * @param ipOut (out) Destination for the interpreted address
 * 
 * @return false = parsing failed - invalid format
 */
extern bool strToIPv6Address(const char* str, IPv6Address* ipOut);

/**
 * Parses textual representation of an IP address.
 * 
 * @param str Character string ("a.b" or "a:b")
 * @param ipOut (out) Destination for the interpreted address
 * 
 * @return false = parsing failed - invalid format
 */
extern bool strToIPAddress(const char* str, IPAddress* ipOut);

/**
 * Parses textual representation of an IP prefix
 * 
 * @param str Character string ("length")
 * @param prefixOut (out) Destination for the interpreted prefix
 * 
 * @return false = parsing failed - invalid format
 */
extern bool strToIPPrefix(const char* str, IPPrefix* prefixOut);

/** 
 * Returns a textual representation of an IPv4 address.
 *
 * @param ip IPv4 address
 * @param dest (out) Buffer
 * @param size Size of the buffer
 * 
 * @return Resulting text (= dest), or \c NULL in case of an error
 */
extern const char* ipV4AddressToStr(IPv4Address* ip, char* dest, size_t size);

/** 
 * Returns a textual representation of an IPv6 address.
 *
 * @param ip IPv6 address
 * @param dest (out) Buffer
 * @param size Size of the buffer
 * 
 * @return Resulting text (= dest), or \c NULL in case of an error
 */
extern const char* ipV6AddressToStr(IPv6Address* ip, char* dest, size_t size);

/** 
 * Returns a textual representation of an IP address.
 *
 * @param ip IP address
 * @param dest (out) Buffer
 * @param size Size of the buffer
 * 
 * @return Resulting text (= dest), or \c NULL in case of an error
 */
extern const char* ipAddressToStr(IPAddress* ip, char* dest, size_t size);

/** 
 * Returns a textual representation of an IP prefix.
 *
 * @param prefix IP prefix
 * @param dest (out) Buffer
 * @param size Size of the buffer
 * 
 * @return Resulting text (= dest), or \c NULL in case of an error
 */
extern const char* ipPrefixToStr(IPPrefix* prefix, char* dest, size_t size);

/**
 * Copy the contents of source prefix into destination prefix.
 * 
 * @param dst The destination prefix
 * @param src The source IPv4Address
 * 
 * @return true if the prefix copy was successful.
 */
extern bool cpyPrefix(IPPrefix* dst,IPPrefix* src);

/**
 * Copy the contents of source IPv4Address into destination IPv4Address.
 * 
 * @param dst The destination IPv4Address
 * @param src The source IPv4Address
 * 
 * @return true if the IPv4Address copy was successful.
 */
extern bool cpyIPv4Address(IPv4Address* dst, IPv4Address* src);

/**
 * Copy the contents of source IPv6Address into destination IPv6Address.
 * 
 * @param dst The destination IPv6Address
 * @param src The source IPv6Address
 * 
 * @return true if the IPv6Address copy was successful.
 */
extern bool cpyIPv6Address(IPv6Address* dst, IPv6Address* src);

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
extern uint32_t IPtoInt(const char* IPStr);

#endif // !__PREFIX_H__