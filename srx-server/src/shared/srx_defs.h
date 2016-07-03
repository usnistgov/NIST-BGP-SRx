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
 */
/**
 * Contains Constants and its definitions for SRX client/server and protocol.
 * 
 * @version 0.3.0
 *
 * SRx constant and type definitions.
 *
 * Change log:
 * -----------------------------------------------------------------------------
 *   0.4.0 - 2016/06/19 - oborchert
 *           * Modified the BGPSecData structure.
 *   0.3.0 - 2013/03/01 - oborchert
 *           * Added define for unusable ASN RFC6483, used ASN of number space
 *             for documentation examples RFC5398
 *         - 2012/12/07 - oborchert
 *           * Organized version control.
 *   0.2.0 - 2011/01/07 - oborchert
 *           * Change log added with version 0.2.0 and date 2011/01/07
 *           * Version tag added
 *           * Updated all
 *           * M0000722 fixed wrong declaration of SRxVerificationMethod.
 *           * Added SRX_RES_ERROR to allow error detection within validation.
 *   0.1.0 - 2010/08/04 - pgleichm
 *           * Code Created
 * -----------------------------------------------------------------------------
 *
 */

#ifndef __SRX_DEFS_H__
#define __SRX_DEFS_H__

#include <stdint.h>

// Borrow ASN of documentation examples (rfc5398)
#define UNKNOWN_ASN 65536
/** Result Type Bits  */
#define SRX_PROXY_RESTYPE_ROA       1
#define SRX_PROXY_RESTYPE_BGPSEC    2
#define SRX_PROXY_RESTYPE_RECEIPT 128

/** The time in which a handshake between proxy and SRx SHOULD be performed
 *  before the handshake is considered as failed.
 */
#define SRX_DEFAULT_HANDSHAKE_TIMEOUT 30

/** Use the 15 minute reboot time of a BGP server in seconds. */
#define SRX_DEFAULT_KEEP_WINDOW 900

// This structure is not used yet and might be removed or completely changed.
// It is just an idea.
typedef struct {
  uint32_t myAS;           // The current AS number
  uint32_t peerAS;         // Next Hop
  uint32_t prependCounter; // The amount of times myAS was prepended
  uint32_t timestamp;      // The timestamp if this is an origin announcement
  uint16_t algorithm;      // The algorithm used
  uint32_t signatureLen;   // The length of the signature
  uint8_t* signature;      // The signature block
} PeerSignature;

/** This structure is currently a dummy that is needed though for validation. 
 * The data in here - if available - will be used to generate an update ID.s
 */
typedef struct {
  /** Number of hops in the as path in host format. */
  uint16_t numberHops;
  /** Contains the AS path as an array of as numbers encoded in network format.
   * AS repetitions are expected */
  uint32_t* asPath;
  /** The length of the bgpsec path attribute in host format. Even though this 
   * length is also encoded within the attribute itself this value is in host 
   * format and is added for convenience. If bgpsec_path_attr is NULL this value
   * must be zero and vice versa.
   */
  uint16_t attr_length;
  /** Contains the bgpsec path attribute according to the RFC. If this value
   * is NULL only the as path will be used. */
  uint8_t* bgpsec_path_attr;
} BGPSecData;

// @TODO: Revisit and modify structure. It will contain the signature and maybe
//        the previous bgpsec path attribute is requested of maybe a complete
//        signature block etc. This will be decided at a later point.
/**
 * This is a temporary structure for Proxy returns to the caller. It will be 
 * changed later on.
 */
typedef struct {
  uint32_t length;
  uint8_t* data;
} BGPSecCallbackData;

/** The flag type used for verification. */
typedef uint8_t SRxVerifyFlag;

#define SRX_FLAG_ROA               1
#define SRX_FLAG_BGPSEC            2
#define SRX_FLAG_ROA_AND_BGPSEC  (SRX_FLAG_ROA | SRX_FLAG_BGPSEC)
#define SRX_FLAG_REQUEST_RECEIPT 128

/** Router specific, unique ID that identifies the RIB-in entry or update */
typedef uint32_t SRxUpdateID;
/** Key ID - defines which public/private key should be used */
typedef uint32_t SRxKeyID;
//typedef uint16_t SRxResult;

/**
 * This type is used to allow addressing either the roaResult, bgpResult or
 * both. See prefix_cache.c:notifyUpdateCache(...) for an example
 */
typedef enum {
  VRT_ROA    = SRX_FLAG_ROA,                  // 1
  VRT_BGPSEC = SRX_FLAG_BGPSEC,               // 2
  VRT_BOTH   = SRX_FLAG_ROA_AND_BGPSEC        // 3
} ValidationResultType;

/** Return value */
typedef struct {
  uint8_t roaResult;
  uint8_t bgpsecResult;
} SRxResult;

/** This struct contains the validation result. */
typedef struct {
  ValidationResultType valType;   // Indicates which data to use.
  SRxResult            valResult; // the result value provided by SRx
  SRxUpdateID          updateID;  // The identifier of the update.
} SRxValidationResult;

/** SRx Result Source (RS) Types */
typedef enum {
  SRxRS_SRX      = 0,
  SRxRS_ROUTER   = 1,
  SRxRS_IGP      = 2,
  SRxRS_UNKNOWN  = 3,
  SRxRS_DONOTUSE = 128
} SRxResultSource;

typedef struct {
  SRxResultSource resSourceROA;     // The source of the provided ROA result
  SRxResultSource resSourceBGPSEC;  // The source of the provided BGPSEC result
  SRxResult       result; // the default result value provided
} SRxDefaultResult;

/** SRx Default Result (DR) Types */
typedef enum {
  SRx_RESULT_VALID     = 0, // ROA & BGPSEC
  SRx_RESULT_NOTFOUND  = 1, // ONLY FOR ROA
  SRx_RESULT_INVALID   = 2, // ROA & BGPSEC
  SRx_RESULT_UNDEFINED = 3, // ROA & BGPSEC (if no result is available)
  SRx_RESULT_DONOTUSE  = 4  // ONLY FOR INTERNAL USE WITHIN SRx Server.
} SRxValidationResultVal;

#define NUM_TRANS 3

#endif // !__SRX_DEFS_H__
