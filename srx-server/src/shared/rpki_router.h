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
 * RPKI/Router definitions.
 *
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 * 0.3.0    - 2013/01/28 - oborchert
 *            * Update to be compliant to draft-ietf-sidr-rpki-rtr.26. This 
 *              update does not include the secure protocol section. The protocol
 *              will still use un-encrypted plain TCP
 *            * Removed invalid PDU type: PDU_TYPE_UNKNOWN.
 * 0.2.0    - 2011/03/03 - oborchert
 *            * Updated to comply with version draft-ietf-sidr-rpki-rtr.10
 *            * For better understanding created a struct for each
 * 0.1.0    - 01/05/2010 - pgleichm
 *            * Code Created according to  draft-ymbk-rtr-protocol-05
 * -----------------------------------------------------------------------------
 */
#ifndef __RPKI_ROUTER_H__
#define __RPKI_ROUTER_H__

#include "util/prefix.h"

/** 
 * PDU Types 
 */
typedef enum {
  PDU_TYPE_SERIAL_NOTIFY  = 0,  // 5.2
  PDU_TYPE_SERIAL_QUERY   = 1,  // 5.3
  PDU_TYPE_RESET_QUERY    = 2,  // 5.4
  PDU_TYPE_CACHE_RESPONSE = 3,  // 5.5
  PDU_TYPE_IP_V4_PREFIX   = 4,  // 5.6
  PDU_TYPE_IP_V6_PREFIX   = 6,  // 5.7
  PDU_TYPE_END_OF_DATA    = 7,  // 5.8
  PDU_TYPE_CACHE_RESET    = 8,  // 5.9
  PDU_TYPE_ERROR_REPORT   = 10, // 5.10
  PDU_TYPE_RESERVED       = 255
} RPKIRouterPDUType;

/**
 * ERROR codes of the RPKI protocol
 */
typedef enum {
    RPKI_EC_CORRUPT_DATA           = 0,
    RPKI_EC_INTERNAL_ERROR         = 1,
    RPKI_EC_NO_DATA_AVAILABLE      = 2,
    RPKI_EC_INVALID_REQUEST        = 3,
    RPKI_EC_UNSUPPORTED_PROT_VER   = 4,
    RPKI_EC_UNSUPPORTED_PDU        = 5,
    RPKI_EC_UNKNOWN_WITHDRAWL      = 6,
    RPKI_EC_DUPLICATE_ANNOUNCEMENT = 7,
    RPKI_EC_RESERVED               = 255
} RPKIErrorCode;

/** The lowest bit is set if the prefix PDU is an announcement */
#define PREFIX_FLAG_ANNOUNCEMENT  0x01

/** The current protocol implementation. */
#define RPKI_RTR_PROTOCOL_VERSION 0;

#pragma pack(1)

//
// The following types could be optimized but
//

/**
 * PDU SerialNotify
 */
typedef struct {
  uint8_t     version;     // Version - always '0'
  uint8_t     type;        // TYPE_SERIAL_NOTIFY
  uint16_t    sessionID;   // Session ID, former session id
  uint32_t    length;      // 12 Bytes
  uint32_t    serial;      // Serial number
} RPKISerialNotifyHeader;

/**
 * PDU SerialQuery
 */
typedef struct {
  uint8_t     version;     // Version - always '0'
  uint8_t     type;        // TYPE_SERIAL_QUERY
  uint16_t    sessionID;   // Session ID, former session id
  uint32_t    length;      // 12 Bytes
  uint32_t    serial;      // Serial number
} RPKISerialQueryHeader;

/**
 * PDU ResetQuery
 */
typedef struct {
  uint8_t     version;     // Version - always '0'
  uint8_t     type;        // TYPE_RESET_QUERY
  uint16_t    reserved;    // zero
  uint32_t    length;      // 8 Bytes
} RPKIResetQueryHeader;

/**
 * PDU Cache Response
 */
typedef struct {
  uint8_t     version;     // Version - always '0'
  uint8_t     type;        // TYPE_CACHE_RESPONSE
  uint16_t    sessionID;   // Session ID, former session id
  uint32_t    length;      // 8 Bytes
} RPKICacheResponseHeader;

/**
 * Defines a PDU for IPv4 Prefix.
 */
typedef struct {
  uint8_t     version;     // Version - always '0'
  uint8_t     type;        // TYPE_IP_V4_PREFIX
  uint16_t    reserved;    // Reserved
  uint32_t    length;      // 20 bytes
  uint8_t     flags;      
  uint8_t     prefixLen;   // 0..32
  uint8_t     maxLen;      // 0..32
  uint8_t     zero;        // zero
  IPv4Address addr;
  uint32_t    as;
} RPKIIPv4PrefixHeader;

/**
 * Defines a PDU for IPv6 Prefix
 */
typedef struct {
  uint8_t     version;     // Version - always '0'
  uint8_t     type;        // TYPE_IP_V6_PREFIX
  uint16_t    reserved;    // Reserved
  uint32_t    length;      // 32 bytes
  uint8_t     flags;
  uint8_t     prefixLen;   // 0..128
  uint8_t     maxLen;      // 0..128
  uint8_t     zero;        // zero
  IPv6Address addr;
  uint32_t    as;
} RPKIIPv6PrefixHeader;

/**
 * PDU EndOfData
 */
typedef struct {
  uint8_t     version;     // Version - always '0'
  uint8_t     type;        // TYPE_END_OF_DATA
  uint16_t    sessionID;   // Session ID, former session id
  uint32_t    length;      // 12 Bytes
  uint32_t    serial;      // Serial number
} RPKIEndOfDataHeader;

/**
 * PDU Cache Reset
 */
typedef struct {
  uint8_t     version;     // Version - always '0'
  uint8_t     type;        // TYPE_CACHE_RESET
  uint16_t    reserved;    // zero
  uint32_t    length;      // 8 Bytes
} RPKICacheResetHeader;

/**
 * PDU Error Report
 */
typedef struct {
  uint8_t     version;      // Version - always '0'
  uint8_t     type;         // TYPE_ERROR_REPORT
  uint16_t    error_number; // Error Code
  uint32_t    length;       // 16 + Bytes
  uint32_t    len_enc_pdu;
  // pdu
  // message size
  // message
} RPKIErrorReportHeader;

/**
 * A common structure used to determine the packet size and type while sending
 * and receiving.
 */
typedef struct {
  uint8_t     version;     // Version - always '0'
  uint8_t     type;        // type version
  uint16_t    mixed;       // some mixed useage field.
  uint32_t    length;      // 8 Bytes of length
} RPKICommonHeader;

#pragma pack()

#endif // !__RPKI_ROUTER_H__
