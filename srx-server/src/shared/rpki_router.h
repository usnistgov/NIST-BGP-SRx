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
 * @version 0.6.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.6.0.0  - 2021/03/30 - oborchert
 *            * Changed version label 0.5.2.0 to 0.6.0.0 (0.5.2.0 was skipped)
 *            * Cleaned up some merger left overs and synchronized with naming 
 *              used conventions.
 *          - 2021/02/30 - oborchert
 *            * Fixed Version control for 0.6.0.0
 *          - 2021/02/09 - oborchert
 *            * Added define PREFIX_FLAG_AFI_V6
 *          - 2020/11/24 - oborchert
 *            * Added Experimental ASPA (see RFC 8210bis-01)
 *              Enumeration value PDU_TYPE_ASPA as well as the 
 *              structure RPKIASPAHeader
 * 0.5.0.4  - 2018/03/07 - oborchert
 *            * Added new error code of RFC 8210
 *            * Added error string defines.
 * 0.5.0.3  - 2018/02/28 - oborchert
 *            * Modified RPKI_CONNECTION_TIMEOUT from 3 seconds to 10 seconds.
 *          - 2018/02/22 - oborchert
 *            * Updated the define RPKI_RTR_PROTOCOL_VERSION from 0 to 1
 *            * Added define RPKI_DEFAULT_CACHE_PORT 323
 *            * Added define RPKI_DEFAULT_CACHE "localhost"
 * 0.5.0.0  - 2017/07/09 - oborchert
 *            * Added include <srx/srxcryptoapi.h> and replaced hard coded 
 *              values with the appropriate defines
 *            * Removed documentation text " - always '0'" from protocol PDU
 *              version fields. For KEY PDU added "1 or greater"
 *          - 2017/06/16 - kyehwanl
 *            * Updated to follow RFC8210 (former 6810-bis-9)
 *          - 2017/06/16 - oborchert
 *            * Version 0.4.1.0 is trashed and moved to 0.5.0.0
 *          - 2016/08/26 - oborchert
 *            * Replaced global pragma statement with __attribute__((packed))
 *              statement for types that need it.
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

#include <srx/srxcryptoapi.h>
#include "util/prefix.h"

/** The lowest bit is set if the prefix PDU is an announcement */
#define PREFIX_FLAG_ANNOUNCEMENT  0x01

/** The current protocol implementation. */
#define RPKI_RTR_PROTOCOL_VERSION 2
/** Bit number 2 specifies the Address Family, 0 for IPv4, 1 for IPv6*/
#define PREFIX_FLAG_AFI_V6        0x02

/** The default RPKI server port */
#define RPKI_DEFAULT_CACHE_PORT 323
/** The default address for a RPKI validation cache */
#define RPKI_DEFAULT_CACHE "localhost"
/** The default connection attempt timeout after 10 seconds. */
#define RPKI_CONNECTION_TIMEOUT 10

#ifndef SRX_SERVER_PACKAGE
// Is provided by Makefile as CFLAGS -I
#define SRX_SERVER_PACKAGE  "NA"
#endif
// Some Macros to deal with the SRX_REVISION compiler parameter
#define SRX_TOOLS_STRINGIFY_ARG(ARG) " " #ARG
#define SRX_TOOLS_STRINGIFY_IND(ARG) SRX_TOOLS_STRINGIFY_ARG(ARG)

// Used version number -  make a string of the define
#define SRX_TOOLS_VERSION  SRX_TOOLS_STRINGIFY_IND(SRX_SERVER_PACKAGE)

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
  PDU_TYPE_ROUTER_KEY     = 9,  // 5.10
  PDU_TYPE_ERROR_REPORT   = 10, // 5.11
  PDU_TYPE_ASPA           = 11, // 5.12
  PDU_TYPE_RESERVED       = 255 // 14
} RPKIRouterPDUType;

/**
 * ERROR codes of the RPKI protocol
 */
typedef enum {
    RPKI_EC_CORRUPT_DATA                = 0,
    RPKI_EC_INTERNAL_ERROR              = 1,
    RPKI_EC_NO_DATA_AVAILABLE           = 2,
    RPKI_EC_INVALID_REQUEST             = 3,
    RPKI_EC_UNSUPPORTED_PROT_VER        = 4,
    RPKI_EC_UNSUPPORTED_PDU             = 5,
    RPKI_EC_UNKNOWN_WITHDRAWL           = 6,
    RPKI_EC_DUPLICATE_ANNOUNCEMENT      = 7,
    RPKI_EC_UNEXPECTED_PROTOCOL_VERSION = 8,   // NEW IN RFC8210
    RPKI_EC_RESERVED                    = 255  //
} RPKIErrorCode;

// Added error text with version 0.5.0.4
#define RPKI_ESTR_CORRUPT_DATA                "Corrupt Data\0"
#define RPKI_ESTR_INTERNAL_ERROR              "Internal Error\0"
#define RPKI_ESTR_NO_DATA_AVAILABLE           "No Data Available\0"
#define RPKI_ESTR_INVALID_REQUEST             "invalid Request\0"
#define RPKI_ESTR_UNSUPPORTED_PROT_VER        "Unsupported Protocol Version\0"
#define RPKI_ESTR_UNSUPPORTED_PDU             "Unsupported PDU\0"
#define RPKI_ESTR_UNKNOWN_WITHDRAWL           "Unknown Withdrawal\0"
#define RPKI_ESTR_DUPLICATE_ANNOUNCEMENT      "Duplicate Announcement\0"
#define RPKI_ESTR_UNEXPECTED_PROTOCOL_VERSION "Unexpected Protocol Version\0"
#define RPKI_ESTR_RESERVED                    "Reserved\0"

//
// The following types could be optimized but
//

/**
 * PDU SerialNotify
 */
typedef struct {
  uint8_t     version;     // Version
  uint8_t     type;        // TYPE_SERIAL_NOTIFY
  uint16_t    sessionID;   // Session ID, former session id
  uint32_t    length;      // 12 Bytes
  uint32_t    serial;      // Serial number
} __attribute__((packed)) RPKISerialNotifyHeader;

/**
 * PDU SerialQuery
 */
typedef struct {
  uint8_t     version;     // Version
  uint8_t     type;        // TYPE_SERIAL_QUERY
  uint16_t    sessionID;   // Session ID, former session id
  uint32_t    length;      // 12 Bytes
  uint32_t    serial;      // Serial number
} __attribute__((packed)) RPKISerialQueryHeader;

/**
 * PDU ResetQuery
 */
typedef struct {
  uint8_t     version;     // Version
  uint8_t     type;        // TYPE_RESET_QUERY
  uint16_t    reserved;    // zero
  uint32_t    length;      // 8 Bytes
} __attribute__((packed)) RPKIResetQueryHeader;

/**
 * PDU Cache Response
 */
typedef struct {
  uint8_t     version;     // Version
  uint8_t     type;        // TYPE_CACHE_RESPONSE
  uint16_t    sessionID;   // Session ID, former session id
  uint32_t    length;      // 8 Bytes
} __attribute__((packed)) RPKICacheResponseHeader;

/**
 * Defines a PDU for IPv4 Prefix.
 */
typedef struct {
  uint8_t     version;     // Version
  uint8_t     type;        // TYPE_IP_V4_PREFIX
  uint16_t    reserved;    // Reserved
  uint32_t    length;      // 20 bytes
  uint8_t     flags;
  uint8_t     prefixLen;   // 0..32
  uint8_t     maxLen;      // 0..32
  uint8_t     zero;        // zero
  IPv4Address addr;
  uint32_t    as;
} __attribute__((packed)) RPKIIPv4PrefixHeader;

/**
 * Defines a PDU for IPv6 Prefix
 */
typedef struct {
  uint8_t     version;     // Version
  uint8_t     type;        // TYPE_IP_V6_PREFIX
  uint16_t    reserved;    // Reserved
  uint32_t    length;      // 32 bytes
  uint8_t     flags;
  uint8_t     prefixLen;   // 0..128
  uint8_t     maxLen;      // 0..128
  uint8_t     zero;        // zero
  IPv6Address addr;
  uint32_t    as;
} __attribute__((packed)) RPKIIPv6PrefixHeader;


/**
 * Defines a PDU for Router Key
 */
typedef struct {
  uint8_t     version;     // Version - must '1' or greater
  uint8_t     type;        // TYPE_ROUTER_KEY
  uint8_t     flags;        //
  uint8_t     zero;        // zero
  uint32_t    length;      // 32 bytes
  uint8_t     ski[SKI_LENGTH];     // Subject Key Identifier 20 octets
  uint32_t    as;          // 4 bytes AS number
  uint8_t     keyInfo[ECDSA_PUB_KEY_DER_LENGTH]; // Subject Public Key Info 91 
                                                 // bytes DER
} __attribute__((packed)) RPKIRouterKeyHeader;



/**
 * PDU EndOfData
 */
typedef struct {
  uint8_t     version;     // Version
  uint8_t     type;        // TYPE_END_OF_DATA
  uint16_t    sessionID;   // Session ID, former session id
  uint32_t    length;      // 12 Bytes
  uint32_t    serial;      // Serial number
} __attribute__((packed)) RPKIEndOfDataHeader;

/**
 * PDU Cache Reset
 */
typedef struct {
  uint8_t     version;     // Version
  uint8_t     type;        // TYPE_CACHE_RESET
  uint16_t    reserved;    // zero
  uint32_t    length;      // 8 Bytes
} __attribute__((packed)) RPKICacheResetHeader;

/**
 * PDU Error Report
 */
typedef struct {
  uint8_t     version;      // Version
  uint8_t     type;         // TYPE_ERROR_REPORT
  uint16_t    error_number; // Error Code
  uint32_t    length;       // 16 + Bytes
  uint32_t    len_enc_pdu;
  // pdu
  // message size
  // message
} __attribute__((packed)) RPKIErrorReportHeader;

/**
 * PDU ASPA
 */
typedef struct {
  uint8_t     version;     // Version
  uint8_t     type;        // TYPE_ASPA
  uint16_t    zero_1;      // zero
  uint32_t    length;      // 160+ Bytes
  uint8_t     flags;
  uint8_t     zero_2;      // zero
  uint16_t    provider_as_count; // Must be at least 1
  uint32_t    customer_asn;
  // followed by list of provider_asn (4 * provider_as_count))
} __attribute__((packed)) RPKIASPAHeader;

/**
 * A common structure used to determine the packet size and type while sending
 * and receiving.
 */
typedef struct {
  uint8_t     version;     // Version
  uint8_t     type;        // type version
  uint16_t    mixed;       // some mixed usage field.
  uint32_t    length;      // 8 Bytes of length
} __attribute__((packed)) RPKICommonHeader;

#endif // !__RPKI_ROUTER_H__
