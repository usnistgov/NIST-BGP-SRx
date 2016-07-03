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
 * Some data definitions are moved into shared/srx_defs.h This makes it easier
 * for integrating into quagga. 
 *   
 * Packet types and constants.
 * 
 * This software might use libraries that are under GNU public license or
 * other licenses. Please refer to the licenses of all libraries required 
 * by this software.
 * 
 * @version 0.4.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.4.0.0  - 2016/06/19 - oborchert
 *            * Moved the proxy-srx-server protocol to version 2.
 *            * Split BGPSecValData into BGPSecValReqData and BGPSecValResData. 
 *            * Added structure to BGPSECValResData.
 *            * Removed pragma packed and replaced it with 
 *              __attribute__((packed)) for the package structure.
 * 0.3.0.10 - 2015/11/06 - oborchert
 *            * Removed types.h
 *            * Added Changelog
 * 0.1.0.0  - 2010/04/09 - pgleichm
 *            * Created code.
 * 
 * @note All structures are packed
 */
#ifndef __SRX_PACKETS_H__
#define __SRX_PACKETS_H__

#include <unistd.h>
#include <srx/srxcryptoapi.h>
#include "shared/srx_defs.h"
#include "util/prefix.h"

/** Version of the protocol listed in this document. */
#define SRX_PROTOCOL_VER  2

#define SRX_ALGORITHM_UNITTEST 0xFFFF

/** Flags Bits  */
#define SRX_PROXY_FLAGS_VERIFY_PREFIX_ORIGIN   1
#define SRX_PROXY_FLAGS_VERIFY_PATH            2
#define SRX_PROXY_FLAGS_VERIFY_RECEIPT       128

/** Block Type Bits */
#define SRX_PROXY_BLOCK_TYPE_LATEST_SIGNATURE  1

/** Peer Change Type */
#define SRX_PROXY_PEER_CHANGE_TYPE_REMOVE 0
#define SRX_PROXY_PEER_CHANGE_TYPE_ADD    1

/** The INdicates the request token value must not be used as token. */
#define DONOTUSE_REQUEST_TOKEN 0
/** The minimum transaction id for setting the sync validation data */
#define MIN_REQUEST_TOKEN 1
/** The maximum transaction id for setting the sync validation data */
#define MAX_REQUEST_TOKEN 1000000

/** Typedef for errors */
typedef enum {
  SRXERR_WRONG_VERSION      = 0,
  SRXERR_DUPLICATE_PROXY_ID = 1,
  SRXERR_INVALID_PACKET     = 2,
  SRXERR_INTERNAL_ERROR     = 3,
  SRXERR_ALGO_NOT_SUPPORTED = 4,
  SRXERR_UPDATE_NOT_FOUND   = 5
} SRxErrorType;

// DPU TYPES OF THE SRX-PROXY PROTOCOL
typedef enum {
  PDU_SRXPROXY_HELLO             =  0,
  PDU_SRXPROXY_HELLO_RESPONSE    =  1,
  PDU_SRXPROXY_GOODBYE           =  2,
  PDU_SRXPROXY_VERIFY_V4_REQUEST =  3,
  PDU_SRXPROXY_VERIFY_V6_REQUEST =  4,
  PDU_SRXPROXY_SIGN_REQUEST      =  5,
  PDU_SRXPROXY_VERI_NOTIFICATION =  6,
  PDU_SRXPROXY_SIGN_NOTIFICATION =  7,
  PDU_SRXPROXY_DELTE_UPDATE      =  8,
  PDU_SRXPROXY_PEER_CHANGE       =  9,
  PDU_SRXPROXY_SYNC_REQUEST      = 10,
  PDU_SRXPROXY_ERROR             = 11,
  PDU_SRXPROXY_UNKNOWN           = 12    // NOT IN SPEC
} SRxProxyPDUType;

////////////////////////////////////////////////////////////////////////////////
/**
 * Plain and simple void for better reading
 */
typedef void SRXPROXY_PDU;

/** The SRXPROXY header that */
typedef struct {
  // The type of the SRx packet.
  uint8_t  type;
  uint16_t reserved1;
  uint8_t  reserved2;
  // The total length of this header in bytes.
  uint32_t length;
  // MUCH MORE DATA FOLLOWS, SEE srx_packet.h
} __attribute__((packed)) SRXPROXY_BasicHeader;

// Just an empty struct that contains to the correct address within the data
// array
typedef struct {  
} __attribute__((packed)) PeerASList;

/**
 * This struct specifies the hello packet
 */
typedef struct {
  uint8_t    type;              // 0
  uint16_t   version;
  uint8_t    zero;
  uint32_t   length;            // Variable 20(+) Bytes
  uint32_t   proxyIdentifier;
  uint32_t   asn;
  uint32_t   noPeers;
  PeerASList peerAS;
} __attribute__((packed)) SRXPROXY_HELLO;

/**
 * This struct specifies the hello response packet
 */
typedef struct {
  uint8_t   type;              // 1
  uint16_t  version;
  uint8_t   zero;
  uint32_t  length;            // 12 Bytes
  uint32_t  proxyIdentifier;
} __attribute__((packed)) SRXPROXY_HELLO_RESPONSE;

/**
 * This struct specifies the goodbye packet
 */
typedef struct {
  uint8_t   type;              // 2
  uint16_t  keepWindow;
  uint8_t   zero;
  uint32_t  length;            // 8 Bytes
} __attribute__((packed)) SRXPROXY_GOODBYE;

typedef struct {
} BGPSEC_DATA_PTR;

/**
 * This struct is currently 0 bytes long but allows to store the address of
 * possible validation data. This is needed when the header is set on top of
 * a byte array.
 */
typedef struct {
  /** The number of hops in the bgp4 as path. */
  uint16_t   numHops;
  /** the bgpsec_path_attr as it is received (see BGPSEC RFC) */
  uint16_t   attrLen;
  /** The prefix as it is used in the validation. */
  SCA_Prefix valPrefix;
  // Data contains numHops integer values representing the bgp4 as path followed
  // by a bgpsec_path_attr (see BGPSEC RFC) of the length attrLen. In case the
  // bgpsec_path_attr is not provided then no path validation can be performed
  // but a bgp4 - bgpsec path match can be requested. For more information on
  // that see the attached documentation.
  // The provided bgp4 as path is provided in the order towards the originator,
  // the last ASN in the list is the originator.
  BGPSEC_DATA_PTR valData;
} __attribute__((packed)) BGPSECValReqData;

/**
 * This data will contain the BGPSEC validation result.
 */
typedef struct {
  // @TODO: Fill in the necessary data. Signature or all signatures or
  //        maybe a copmlete bgpsec_pathAttribute that can be send out as is.
} __attribute__((packed)) BGPSECValResData;

// @TODO V6 and V4 request can be combined once we use the SCA_PRefix instead
// of the IPPrefix structure. Maybe within the srx server we can move from 
// SCA_Prefix to IP-Prefix. This can be decided later.

/**
 * This struct is a helper to read validation requests easier.
 */
typedef struct {
  uint8_t       type;          // 3 and 4
  uint8_t       flags;
  uint8_t       roaResSrc;
  uint8_t       bgpsecResSrc;
  uint32_t      length;
  uint8_t       roaDefRes;
  uint8_t       bgpsecDefRes;
  uint8_t       zero;
  uint8_t       prefixLen;
  uint32_t      requestToken; // Added with protocol version 1.0
} __attribute__((packed)) SRXRPOXY_BasicHeader_VerifyRequest;

/**
 * This struct specifies the Verify request IPv4 packet
 */
typedef struct {
  SRXRPOXY_BasicHeader_VerifyRequest common; // type = 3
  IPv4Address      prefixAddress;
  uint32_t         originAS;
  uint32_t         bgpsecLength;
  BGPSECValReqData bgpsecValReqData;
} __attribute__((packed)) SRXPROXY_VERIFY_V4_REQUEST;

/**
 * This struct specifies the Verify request IPv6 packet
 */
typedef struct {
  SRXRPOXY_BasicHeader_VerifyRequest common; // type = 4
  IPv6Address      prefixAddress;
  uint32_t         originAS;
  uint32_t         bgpsecLength;
  BGPSECValReqData bgpsecValReqData;
} __attribute__((packed)) SRXPROXY_VERIFY_V6_REQUEST;

/**
 * This struct specifies the sign request packet
 */
typedef struct {
  uint8_t     type;            // 5
  uint16_t    algorithm;
  uint8_t     blockType;
  uint32_t    length;          // 20 Bytes
  uint32_t    updateIdentifier;
  uint32_t    prependCounter;
  uint32_t    peerAS;
} __attribute__((packed)) SRXPROXY_SIGN_REQUEST;

/**
 * This struct specifies the verification notification packet
 */
typedef struct {
  uint8_t     type;            // 6
  uint8_t     resultType;
  uint8_t     roaResult;
  uint8_t     bgpsecResult;
  uint32_t    length;          // 16 Bytes
  uint32_t    requestToken; // Added with protocol version 1.0
  SRxUpdateID updateID;
} __attribute__((packed)) SRXPROXY_VERIFY_NOTIFICATION;

/**
 * This struct specifies the signature notification packet
 */
typedef struct {
  uint8_t          type;            // 7
  uint16_t         reserved;
  uint8_t          zero;
  uint32_t         length;          // 16(+) Bytes
  uint32_t         updateIdentifier;
  uint32_t         bgpsecLength;
  BGPSECValResData bgpsecResData;
} __attribute__((packed)) SRXPROXY_SIGNATURE_NOTIFICATION;

/**
 * This struct specifies the delete update packet
 */
typedef struct {
  uint8_t     type;            // 8
  uint16_t    keepWindow;
  uint8_t     zero;
  uint32_t    length;          // 12 Bytes
  uint32_t    updateIdentifier;
} __attribute__((packed)) SRXPROXY_DELETE_UPDATE;

/**
 * This struct specifies the synchronisation request packet
 */
typedef struct {
  uint8_t     type;            // 9
  uint16_t    reserved;
  uint8_t     changeType;
  uint32_t    length;          // 8 Bytes
  uint32_t    peerAS;
} __attribute__((packed)) SRXPROXY_PEER_CHANGE;

/**
 * This struct specifies the synchronisation request packet
 */
typedef struct {
  uint8_t     type;            // 10
  uint16_t    reserved;
  uint8_t     zero;
  uint32_t    length;          // 8 Bytes
} __attribute__((packed)) SRXPROXY_SYNCH_REQUEST;

/**
 * This struct specifies the error packet
 */
typedef struct {
  uint8_t     type;            // 11
  uint16_t    errorCode;
  uint8_t     zero;
  uint32_t    length;          // 8 Bytes
} __attribute__((packed)) SRXPROXY_ERROR;

/**
 * Returns a string corresponding to the given \c type.
 *
 * @param type Packet type
 * @return string
 */
const char* packetTypeToStr(SRxProxyPDUType type);

#endif // !__SRX_PACKETS_H__
