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
 * This is the SRxCryptoAPI library. It provides the crypto operations for 
 * BGPSEC implementations. This library allows to switch the crypto 
 * implementation dynamically.
 *
 * @version 0.3.0.0
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *   0.3.0.0 - 2018/11/29 - oborchert
 *             * Removed all "merged" comments to make future merging easier
 *           - 2017/09/13 - oborchert
 *             * Added wording to the init method, when it has to return FAILURE
 *           - 2017/08/18 - oborchert
 *             * Modified description of cleanKeys to clean only public keys and
 *               added function cleanPrivateKeys.
 *             * Fixed speller in function name sca_generateOriginHashMessage
 *           - 2017/08/15 - oborchert
 *             * Added function sca_getAlgorithmIDs to allow retrieval of the 
 *               algorithm IDs within the signature block.
 *             * Changed define BGP_UPD_A_FLAGS_EXT_LENGTH into 
 *               SCA_BGP_UPD_A_FLAGS_EXT_LENGTH.
 *             * Added error code API_STATUS_ERR_SYNTAX
 *           - 2017/08/20 - oborchert
 *             * Modified the register and unregister functions to include
 *               a source identifier.
 *              * Added function cleanKeys
 *           - 2017/08/08 - oborchert
 *             * Modified the behavior of the API for validate and sign. 
 *             * Changed status flag from 16 to 32 bit
 *             * Modified function header of sign including the expected
 *               behavior. See function description for more detail.
 *             * Added function isAlgorithmSupported
 *   0.2.0.4 - 2017/09/15 - oborchert
 *             * Added more documentation.
 *   0.2.0.3 - 2017/07/09 - oborchert
 *             * Added define ECDSA_PUB_KEY_DER_LENGTH
 *           - 2017/04/20 - oborchert
 *             * Fixed error in version control.
 *             * Added IMPORTANT memory usage documentation to struct BGPSecKey
 *             * Slightly re-worded some of the parameter documentation to be 
 *               more precise on what the parameter MUST contain.
 *   0.2.0.2 - 2017/02/02 - oborchert
 *             * Corrected version number to 0.2.0.2 which was incorrect.
 *           - 2016/11/15 - oborchert
 *             * Fixed issue with one byte bgpsec path attribute (BZ1051)
 *   0.2.0.1 - 2016/07/02 - oborchert
 *             * Speller in variable name algorithID to algorithmID
 *             * Added missing hash generation for origin announcements.
 *   0.2.0.0 - 2016/07/01 - oborchert
 *             * Added function sca_getAlgorithmID and modified the validation 
 *               message buffer in SCA_BGPSecValidationData into a two buffer 
 *               array, one buffer per possible signature block.
 *           - 2016/06/26 - oborchert
 *             * Added algorithmID and ski to the generated signature 
 *           - 2016/06/20 - oborchert
 *             * Latest version used wrong algorithm id value. Moved it back 
 *               to 1
 *           - 2016/05/24 - oborchert
 *             * Remodeled the API for a more performant implementation.    
 *   0.1.3.0 - 2016/04/15 - oborchert
 *             * Added prefix structure SCA_Prefix
 *   0.1.2.1 - 2016/02/03 - oborchert
 *             * Fixed incorrect date in Changelog
 *             * Added version number
 *           - 2016/02/01 - oborchert
 *             * Added init(...) method
 *   0.1.2.0 - 2015/11/03 - oborchert
 *             * Removed ski and algoID from struct BGPSecSignData, both data 
 *               fields are part of the BGPSecKey structure. (BZ795)
 *             * modified function signature of sign_with_id (BZ788)
 *           - 2015/10/13 - oborchert
 *             * Fixed invalid method srxCryptoUnbind - previous interface did 
 *               not ask for api object.
 *             * Modified srxCrytpoInit to only return failure if binding of
 *               the library failed.
 *           - 2015/09/22 - oborchert
 *             * added functions:
 *               > sca_getCurrentLogLevel
 *               > sca_SetDER_Ext - For private key
 *               > sca_SetX90_ext - For public key
 *             * Removed term_debug
 *           - 2015/09/22 - oborchert
 *             * Added ChangeLog to file.
 *             * Return 0 for srxCryptoInit method when API is NULL.
 */
#ifndef _SRXCRYPTOAPI_H
#define _SRXCRYPTOAPI_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#include <sys/param.h>
#include <stdarg.h>
#include <stdbool.h>
#include <netinet/in.h>

/** The expected algorithm ID. officially still TBD with 0x0 and 0xF being 
 *  reserved. */
#define SCA_ECDSA_ALGORITHM 1

/** SCA Method return value */
#define API_SUCCESS          1
/** SCA Method return value */
#define API_FAILURE          0

/** The SKI length is defined in the protocol specification. */
#define SKI_LENGTH                 20
/** Twice the length of the SKI_LENGTH in binary form */
#define SKI_HEX_LENGTH             40
/** The length of an ECDSA public key in DER format. */
#define ECDSA_PUB_KEY_DER_LENGTH   91

/** Update validation returns VALID */
#define API_VALRESULT_VALID        1
/** Update validation returns INVALID */
#define API_VALRESULT_INVALID      0
/** Update validation algorithm not supported 
 * (e.g. no supported algorithm found) 
 * @since 0.3.0.0*/
#define API_VALRESULT_FAILURE     -1

/* Mask to detect errors in the status flag. */
#define API_STATUS_ERROR_MASK            0xFFFF0000
/* Mask to detect information in the status flag. */
#define API_STATUS_INFO_MASK             0x0000FFFF
/** All OK - no additional information */
#define API_STATUS_OK                    0x00000000
/** one or more signatures could failed validation */
#define API_STATUS_INFO_SIGNATURE        0x00000001
/** A key not found */
#define API_STATUS_INFO_KEY_NOTFOUND     0x00000002
/** A user defined status */
#define API_STATUS_INFO_USER1            0x00001000
/** A user defined status */
#define API_STATUS_INFO_USER2            0x00002000
/** A user defined status
 * @since 0.3.0 */
#define API_STATUS_INFO_USER3            0x00004000
/** A user defined status
 * @since 0.3.0 */
#define API_STATUS_INFO_USER4            0x00008000

// Error reports
/** Input update data / or precomputed hash is missing */
#define API_STATUS_ERR_NO_DATA           0x00010000
/** Input prefix data is missing */
#define API_STATUS_ERR_NO_PREFIX         0x00020000
/** Invalid key - e.g. RSA key and ECDSA key expected. */
#define API_STATUS_ERR_INVLID_KEY        0x00040000        //   <-- could this be an INFO value
/** General key I/O error . */
#define API_STATUS_ERR_KEY_IO            0x00080000
/** A hash buffer to small */
#define API_STATUS_ERR_INSUF_BUFFER      0x00100000
/** A Not enough storage for keys */
#define API_STATUS_ERR_INSUF_KEYSTORAGE  0x00200000
/** While signing, the requested algorithm id is supported, while validating,
 * none of the max 2 requested algorithm validations are supported. */
#define API_STATUS_ERR_UNSUPPPORTED_ALGO 0x00400000
/** Unexpected syntax error while parsing data. */
#define API_STATUS_ERR_SYNTAX            0x00800000
/** A user defined error */
#define API_STATUS_ERR_USER1             0x10000000
/** A user defined error */
#define API_STATUS_ERR_USER2             0x20000000
/** A user defined error
 * @since 0.3.0 */
#define API_STATUS_ERR_USER3             0x40000000
/** A user defined error
 * @since 0.3.0 */
#define API_STATUS_ERR_USER4             0x80000000

/** This flag specifies the length field in the BGP Path Attribute. */
#define SCA_BGP_UPD_A_FLAGS_EXT_LENGTH 0x10
/** Pre-defined source for use of internal source (e.g. dugin init etc) */
#define SCA_KSOURCE_INTERNAL 0

/** Maximum number of signature blocks within an UPDATE. */
#define SCA_MAX_SIGBLOCK_COUNT 2

////////////////////////////////////////////////////////////////////////////////
// BGPSEC Path Structures
////////////////////////////////////////////////////////////////////////////////

// MPNLRI

/* The next hop structure */
typedef struct {
  u_int8_t  flags;
  u_int8_t  type_code;
  u_int8_t  length;     // including this length field (no flags, no type code)
  u_int16_t afi;
  u_int8_t  safi;
  u_int8_t  nextHopLen; // length in bytes of the padded address
  //followed by next hop (variable))
} __attribute__((packed)) SCA_BGP_Path_Attr_MPNLRI_1;

typedef struct {
  u_int8_t reserved; // MUST be set to 0
  // Now the NLRI;
  u_int8_t length;   // in bits
  // the address (variable)
} __attribute__((packed)) SCA_BGP_Path_Attr_MPNLRI_2;

// BGPSEC

typedef struct {
  u_int8_t  flags;
  u_int8_t  type_code;    
} __attribute__((packed)) SCA_BGP_PathAttribute;

typedef struct {
  u_int8_t  flags;
  u_int8_t  type_code;
  u_int8_t attrLength;
} __attribute__((packed)) SCA_BGPSEC_NormPathAttribute;

typedef struct {
  u_int8_t  flags;
  u_int8_t  type_code;
  u_int16_t attrLength; // requires ext. length 0x10 set
} __attribute__((packed)) SCA_BGPSEC_ExtPathAttribute;

typedef struct {
  u_int16_t length;  // contains the length of the entire SecurePath
  // Secure Path Segments follow, each path segment is the size of 
  // sizeof(TplSecurePathSegment)
} __attribute__((packed)) SCA_BGPSEC_SecurePath;

typedef struct {
  u_int8_t  pCount;
  u_int8_t  flags;
  u_int32_t asn;
} __attribute__((packed)) SCA_BGPSEC_SecurePathSegment;

typedef struct {
  u_int16_t length;
  u_int8_t  algoID;
} __attribute__((packed)) SCA_BGPSEC_SignatureBlock;

typedef struct {
  u_int8_t  ski[20];
  u_int16_t siglen;  
  // Signature in byte stream of length (siglen) follows
} __attribute__((packed)) SCA_BGPSEC_SignatureSegment;

/** Same as sizeof(SCA_BGPSEC_SecurePath) */
#define LEN_SECPATH_HDR          2
/** Same as sizeof(SCA_BGPSEC_SecurePathSegment) */
#define LEN_SECPATHSEGMENT       6
/** Same as sizeof(SCA_BGPSEC_SignatureBlock) */
#define LEN_SIGBLOCK_HDR         3
/** Same as sizeof(SCA_BGPSEC_SignatureSegment) */
#define LEN_SIGSEGMENT_HDR      22

////////////////////////////////////////////////////////////////////////////////
// SRx Crypto API Structures
////////////////////////////////////////////////////////////////////////////////

/** Used for the status information. The upper two bytes are used for ERROR and
 * the lower two bytes are used for INFO values. All values are BIT coded. 
 * Modified from 16 bit to 32 bit with version 0.3.0.0*/
typedef u_int32_t sca_status_t;

/** Used to allow identifying the source for keys.
 * @see #SCA_KSOURCE_INTERNAL
 * @since 0.3.0.0 */
typedef u_int8_t sca_key_source_t;

// Crypto API types
/** The BGPSec Key wrapper. The stored key structure is in DER format.*/
typedef struct
{
  /** The id of the used algorithm suite (See RFC)*/
  u_int8_t  algoID;
  /** The ASN that uses the Key (network format)*/
  u_int32_t asn;
  /** The SKI of the key */
  u_int8_t  ski[SKI_LENGTH];
  /** The length of the key byte stream (host format). */
  u_int16_t keyLength;
  /** The key in DER format (MUST BE malloc'ed not OpenSSL_malloc'ed)*/
  u_int8_t* keyData;
} __attribute__((packed)) BGPSecKey;

/**
 * Prefix Structure used within the functions.
 */
typedef struct
{
  /** The Addreff Family Identifier (big-endian) network format*/
  u_int16_t afi;
  /** The safi */
  u_int8_t  safi;
  /** The prefix length in bits -> (length + 7) / 8 == bytes*/
  u_int8_t  length;
  /** The address portion of the prefix. */
  union
  {
    /** The ipv5 address portion */
    struct in_addr  ipV4;
    /** *The ipv6 address portion */
    struct in6_addr ipV6;
    /** The byte buffer */
    u_int8_t ip[16];
  } addr;
} __attribute__((packed)) SCA_Prefix;

/** 
 * This structure is used as a helper. It does have pointers into the 
 * hashMessage to quickly access the data within the digest.
 * if Provided, No parsing through the structure is necessary anymore.
 * 
 * The pointers are explained more in detail in the next data structure
 */
typedef struct 
{
  /** Points to the signature of the hash Message. Only the last element must
   * have a NULL pointer. All others must point to the signature corresponding 
   * to the hash message pointer. */
  u_int8_t* signaturePtr;
  /** Points to the hash Message (buffer) which is signed over.*/
  u_int8_t* hashMessagePtr;
  /** Contains the length of the buffer. */
  u_int16_t hashMessageLength;
} SCA_HashMessagePtr;

/** This structure will be generated during the digest generation. It can be
 * provided to the validate caller but the API is not required to use the 
 * hash input message (buffer) and can create it's own instead.
 * 
 * The hash message itself (input for the hash algorithm) has the following 
 * format (RFC 8205):
 * 
 * ------+===================================+
 *  S    || pCount             ( 1 Octet  ) ||
 *  e    |+---------------------------------+|
 *  g    || flags              ( 1 Octet  ) ||
 *       |+-----------------------------------<>===========(hashMessagePtr[N-1]==buffer)
 *  N-1  || ASN - target N-1 - ( 4 Octets ) ||           \
 * ------+===================================+           |
 *       ...                                             |
 * ------+===================================+<>===========(signaturePtr[1])
 *  S    || SKI                (20 octets)  ||           |
 *  i    |+---------------------------------+|           |
 *  g    || Sig Length         (2 octets)   ||           |
 *       |+---------------------------------+|           |
 *  1 /--|| Signature          (variable)   ||           |
 * ---|--+===================================+         h |
 *  S |  || pCount             ( 1 Octet  ) ||         a |
 *  e |  |+---------------------------------+|         s |
 *  g |  || flags              ( 1 Octet  ) ||         h |
 *    \->+------------------------------------<>===========(hashMessagePtr[1]==buffer)
 *  2    || ASN - target 2 -   ( 4 Octets ) ||       \   |
 * ------+===================================+<>===========(signaturePtr[0])
 *  S    || SKI                (20 octets)  ||       | M |
 *  i    |+---------------------------------+|       | e |
 *  g    || Sig Length         (2 octets)   ||       | s |
 *       |+---------------------------------+|       | s |
 *  0 /--|| Signature          (variable)   ||       | a |
 * ---|--+===================================+     h | g |
 *  S |  || pCount             ( 1 Octet  ) ||     a | e |
 *  e |  |+---------------------------------+|     s |   |
 *  g |  || flags              ( 1 Octet  ) ||     h | 2 |
 *    \->+------------------------------------<>===========(hashMessagePtr[0]==buffer)
 *  1    || ASN - target 1 - ( 4 Octets )   ||   \ M |   |  
 * ------+===================================+ h | e |   |
 *  S    || pCount             ( 1 Octet  ) || a | s |   |
 *  e    |+---------------------------------+| s | s |   |
 *  g    || flags              ( 1 Octet  ) || h | a |   |
 *       |+---------------------------------+|   | g |   |
 *  0    || ASN - origin 0 -   ( 4 Octets ) || M | e |   |
 * ------+===================================+ e |   |   |
 *       | Algorithm Suite Identifier        | s | 1 |   |
 * ------+===================================+ s |   |   |
 *  N    || AFI                             || a |   |   |
 *  L    |+---------------------------------+| g |   |   |
 *  R    || SAFI                            || e |   |   |
 *  I    |+---------------------------------+|   |   |   |
 *       || Prefix                          || 0 |   |   |
 * ------+===================================+---/---/---/
 *
 * The user must allocate and free the memory used for instances of this 
 * complete SCA_HashMessage struct. Handling of the buffer memory is either
 * done by the user (ownedByAPI=false) or by the API (ownedByAPI=true)
 */
typedef struct 
{
  /** Indicates if the memory of the hash message is maintained by the API. 
   * In this case it is required to call the freeHashMessage(...) function 
   * of the API instance. Otherwise the user must perform the a cleanup. 
   */
  bool      ownedByAPI;
  
  /** Size of the buffer. */
  u_int32_t bufferSize;
  
  /** The buffer itself. The first 4 bytes are reserved for the target AS (peer)
   * where the update will be send to.Then followed by the last Signature, 
   * followed by 2 reserved bytes to be used for this hosts flag and pCount 
   * value. Then the digest for the signature starts. Therefore the digest of 
   * each signature starts at signatureLength + 2 bytes. 
   * The digestLen is calculated as followed:
   * usedBuffer - (currAddr-bufferAddr) with currAddr the pointer address of
   * the ASN where the signature is signed to and bufferAddr the buffer pointer 
   * itself.*/
  u_int8_t* buffer;
  
  /** Number of path segments in this buffer. This value is same as the number
   * of hashMessageValPtr elements in the  hashMessageValPtr array. */
  u_int16_t segmentCount;
  
  /** This array contains one element for each secure path segment. The pointers 
   * reach into the buffer for easy access during validation. */
  SCA_HashMessagePtr** hashMessageValPtr;
  
} SCA_HashMessage;

/**
 * This structure contains the generated signature.
 */
typedef struct 
{
  /** Indicates if the internal signature buffer is maintained by the API. In 
   * this case the user is required to call the freeSignature of the API 
   * instance. Otherwise a cleanup of the internals must be performed by the 
   * user. The instance of SCA_Signature must be freed by the user as well.
   * . */  
  bool      ownedByAPI;
  /**
   * The algorithm suite identifier of the algorithm used to generate the 
   * particular signature.
   */
  u_int8_t  algoID;
  /** The SKI of the key used to generate the signature. */
  u_int8_t  ski[SKI_LENGTH];
  /* The length of the signature in host format. */
  u_int16_t sigLen;
  /** Pointer to the buffer containing the signature. */
  u_int8_t* sigBuff;
} SCA_Signature;

/** 
 * the memory for this structure must be allocated by the user of the API.
 * It is the input data into the validation process. The API itself will
 * create and allocate the HashMessages and assign them to the hashMessage 
 * array.
 * All fields except the hashMessage array fields are input fields. 
 * The array will be filled by the API and returned to the caller. The API is 
 * responsible to removing it. for this the caller uses the API's 
 * freeHashMessage function.
 */
typedef struct
{
  /** The last AS (own AS) this data is signed to in network format. */
  u_int32_t    myAS;
  /** Pointer to the variable that will contain the status information of this
   * validation call.*/
  sca_status_t status;
  /** The bgpsec path attribute to be validated. */
  u_int8_t*    bgpsec_path_attr;
  /** The prefix information required for validation. */
  SCA_Prefix*  nlri;
  /** The message that will be hashed. */
  SCA_HashMessage*  hashMessage[2];
} SCA_BGPSecValidationData;

/**
 * This structure is used as input for the sign message. The caller MUST provide
 * all data except the signature. This must be NULL when calling sign.
 */
typedef struct
{
  /** MUST NOT BE USED ANYMORE */
  __attribute__((deprecated))u_int32_t peerAS;
  /** MUST NOT BE USED ANYMORE */
  __attribute__((deprecated))SCA_BGPSEC_SecurePathSegment* myHost;
  /** MUST NOT BE USED ANYMORE */
  __attribute__((deprecated))SCA_Prefix* nlri;
  
  /* Needed to find the correct private key. */
  u_int32_t myASN; 
  /** The SKI for the private key. */
  u_int8_t* ski;      
  /** The algorithm ID. */
  u_int8_t algorithmID;
  
  /** The status of the sign operation. */
  sca_status_t status;
  
  /** Must not be null. IN case this data is not provided by a previous validate 
   * call then this API provides two generation functions 
   * sca_generateHashMessage for updates received that need to be forwarded or 
   * sca_generateOriginHashMessage for an update that will be originated. 
   * Also the pCount, Flags, and Peer MUST be set correctly. 
   * This DATA is READ ONLY and must not be altered as long as the sign function
   * has this data.
   */
  SCA_HashMessage*  hashMessage;
  
  /** OUT only. The signature segment - MUST BE NULL when passed into sign 
   * function. The memory is allocated within the API. */
  SCA_Signature* signature;
} SCA_BGPSecSignData;

#define MAX_CFGFILE_NAME 255

/* The SRxCryptoAPI wrapper object.*/
typedef struct
{
  /** The Library Handle. */
  void* libHandle;
  /** The configuration file name. */
  char* configFile;

  /**
   * Perform a Library initialization by passing a \0 terminated string. This 
   * value can also be NULL.
   * This function returns API_FAILURE in case of an error or failure the API 
   * cannot recover from - otherwise return a SUCCESS and ass an INFO flag to 
   * the status.
   * 
   * In case the function returns API_FAILURE, the API must not be used.
   * 
   * @param value A \0 terminated string or NULL.
   * @param debugLevel the debugging level - Follows the system debug levels.
   *                   -1 indicates to NOT modify the log level.
   * @param status The status variable that returns more information.
   * 
   * @return API_SUCCESS or API_FAILURE (check status)
   */
  int (*init)(const char* value, int debugLevel, sca_status_t* status);
  
  /**
   * This will be called prior un-binding the library. This allows the API 
   * implementation to perform a clean shutdown / cleanup.
   * 
   * @param status The status variable that returns more information.
   * 
   * @return API_SUCCESS or API_FAILURE (check status)
   */
  int (*release)(sca_status_t* status);
  
  /**
   * Perform BGPSEC path validation. This function required the keys to be 
   * pre-registered to perform the validation. 
   * The caller manages the memory and MUST assure the memory is intact until
   * the function returns.
   * This function returns API_VALRESULT_VALID, API_VALRESULT_INVALID, and
   * API_VALIDATION_ERROR.
   * 
   * In contrast to previous implementations beginning with version 0.3.0.0 the
   * result MUST be API_VALIDATION_ERROR as soon as one error bit is set in the
   * status. Otherwise the result must be either API_VALRESULT_VALID or 
   * API_VALRESULT_INVALID.
   * 
   * In case none of the provided signature blocks is supported the plug-in MUST
   * set the status flag API_STATUS_ERR_UNSUPPPORTED_ALGO and return 
   * API_VALIDATION_ERROR. This allows the caller to perform all necessary 
   * actions specified in the BGPsec draft validation section. 
   * 
   * Situations where the the correct key cannot be located are NOT considered
   * errors, these situations MUST result in API_VALRESULT_INVALID. Situations
   * of invalid keys cannot occur because keys MUST be checked of their validity
   * during registration.
   *
   * For validation results API_VALRESULT_VALID and API_VALRESULT_INVALID the
   * status flag can contain more detailed information about the reason for 
   * the validation status (why invalid, etc.). 
   * 
   * These are coded as API_STATUS_INFO_... types.
   *
   * @param data This structure contains all necessary information to perform
   *             the path validation. The status flag will contain more 
   *             information
   *
   * @return API_VALRESULT_VALID, API_VALRESULT_INVALID,
   *         or API_VALIDATION_ERROR (check status) and the status flag 
   *         contains further information - including errors.
   */
  int (*validate)(SCA_BGPSecValidationData* data);
   
  /**
   * Sign the given BGPsec data using the key information (ski, algo-id, asn)
   * provided within the BGPSecSignData object.
   * 
   * If all signings could be performed without any problems, the API MUST 
   * return API_SUCCESS. 
   * 
   * As soon as one signing encountered issues, the return value MUST be
   * API_FAILURE and the status flag indicates the error for each provided data
   * object. 
   * In case the status flag has one error bit set (use the bit arithmetic with 
   * the mask SCA_API_STATUS_ERROR_MASK). The signing is considered as failed 
   * and the signature values are not to be used. They MUST be NULL.
   * 
   * API_FAILURE must not be returned if none of the provided data objects has
   * no error bit(s) set. API_SUCCESS must not be returned if at least one
   * data object had an error bit set.
   * 
   * Unsupported algorithm results in the unsupported error bit being set and 
   * the return value API_FAILURE. 
   *
   * Here in contrast to verifications a missing key is considered an error.
   * 
   * @param count The number of bgpsec_data elements in the given array
   * @param bgpsec_data Array containing the data objects to be signed. This 
   *                    also includes the generated signature.
   *
   * @return API_SUCCESS or API_FAILURE (check status)
   * 
   */
  int (*sign)(int count, SCA_BGPSecSignData** bgpsec_data);

  /**
   * Register the private key. This method allows to register the
   * private key with the API object. The key must be internally copied. 
   * The memory is NOT shared for longer than the registration execution cycle.
   * NOTE: The key information MUST be copied within the API.
   * 
   * IMPORTANT:
   *   To detect duplicate keys only the ASN, SKI, and algoID are to be used.
   *
   * @param key The key itself - MUST contain the DER encoded key.
   * @param status Will contain the status information of this call.
   *
   * @return API_SUCCESS or API_FAILURE (check status)
   */
  u_int8_t (*registerPrivateKey)(BGPSecKey* Key, sca_status_t* status);

  /**
   * Remove the registration of a given key with the specified key ID. 
   *
   * @param asn The ASN of the private key (network format).
   * @param ski The 20 Byte ski
   * @param algoID The algorithm ID of the key.
   * @param status Will contain the status information of this call.
   *
   * @return API_SUCCESS or API_FAILURE (check status)
   */
  u_int8_t (*unregisterPrivateKey)(u_int32_t asn, u_int8_t* ski, 
                                   u_int8_t algoID, sca_status_t* status);

  /**
   * Register the public key.
   * All keys must be registered within the API. This will allow to call the 
   * verification without the need to determine the needed public keys by
   * the caller. The API will determine which key to be used.
   * 
   * NOTE: The key information MUST be copied within the API.
   * 
   * Also the DER format of the key MUST match the algorithm ID or an invalid
   * key error must be set in the status flag.
   * 
   * IMPORTANT:
   *   To detect duplicate keys the source, ASN, SKI, and the binary DER 
   *   formated key must match. (RFC 8210 - does not use specifically the 
   *   algorithm id but the algorithm ID is identified by the DER formated key.)
   *
   * @param key The key itself - MUST contain the DER encoded key.
   * @param source The source of the key.
   * @param status Will contain the status information of this call.
   *
   * @return API_SUCCESS or API_FAILURE (check status)
   */
  u_int8_t (*registerPublicKey)(BGPSecKey* key, sca_key_source_t source,
                                sca_status_t* status);

  /**
   * Remove the registered key with the same ski and asn. (Optional)
   * This method allows to remove a particular key that is registered for the
   * given SKI and ASN.
   *
   * IMPORTANT: If only the SKI and ASN are provided, all keys matching the ASN 
   *            and SKI will be deleted (from the given source). 
   *            This is important for cases of SKI collision.
   * 
   * @param key The key needs at least contain the ASN and SKI.
   * @param source The source of the key.
   * @param status Will contain the status information of this call.
   *
   * @return API_SUCCESS or API_FAILURE (check status)
   */
  u_int8_t (*unregisterPublicKey)(BGPSecKey* key, sca_key_source_t source,
                                  sca_status_t* status);
  
  /**
   * Remove all public keys from the internal storage that were provided by the 
   * given key source.
   * 
   * @param source The source of the keys.
   * @param status Will contain the status information of this call.
   * 
   * @return API_SUCCESS or API_FAILURE (check status)
   * 
   * @since 0.3.0.0
   */
  u_int8_t (*cleanKeys)(sca_key_source_t source, sca_status_t* status);

  /**
   * Remove all private keys from the internal storage.
   * 
   * @param status Will contain the status information of this call.
   * 
   * @return API_SUCCESS or API_FAILURE (check status)
   * 
   * @since 0.3.0.0
   */
  u_int8_t (*cleanPrivateKeys)(sca_status_t* status);
  
  /**
   * In case the validation method does return the generated hashMessage, this
   * function is used to free the allocated memory.
   * 
   * @param hashMessage The generated hash input data, must be generated by the 
   *                    API mapped library and retrieved using the validate 
   *                    call.
   * 
   * @return false if the API is not the owner of the memory and cannot release 
   *         the allocation, otherwise true
   */
  bool (*freeHashMessage)(SCA_HashMessage* hashMessage);
  
  /**
   * Signatures are generated by the API and also freed by the API module.
   * 
   * @param signature The signature element.
   * 
   * @return false if the API is not the owner of the memory and cannot release 
   *         the allocation, otherwise true
   * 
   */
  bool (*freeSignature)(SCA_Signature* signature);
  
  /**
   * Return the current debug level of -1 if not supported
   * 
   * @return the current debug level or -1
   */
  int (*getDebugLevel)();

  /**
   * Set the new debug level going forward. This method returns the previous set 
   * debug level or -1 if not supported.
   * 
   * @param debugLevel The debug level to be set - Follows system debug values.
   * 
   * @return the previous debug level or -1
   */
  int (*setDebugLevel)(int debugLevel);  
  
  /**
   * Allows to query if this plug-in supports the requested algorithm IDdd.
   * 
   * @param algoID The algorithm ID.
   * 
   * @return true if the algorithm is supported or not.
   * 
   * @since 0.3.0.0
   */
  bool (*isAlgorithmSupported)(u_int8_t algoID);
  
} SRxCryptoAPI;

/* Function Declaration */

/**
 * This function initialized the SRxCrypto API. the SRxCryptoAPI object must be
 * created and released by the user of the API. In case the configuration is not
 * set the default API located in ./ will be loaded.
 *
 * @param api the API object.
 * @param status an OUT variable that contains status information.
 * 
 * @return API_SUCCESS or API_FAILURE (see status) 
 */
int srxCryptoInit(SRxCryptoAPI* api, sca_status_t* status);

/**
 * This function unloads the library that is loaded and NULLs all attached 
 * methods.
 * 
 * @param api Unbind the SRxCryptoAPI
 *
 * @return API_SUCCESS or API_FAILURE (see status) 
 */
int srxCryptoUnbind(SRxCryptoAPI* api, sca_status_t* status);

////////////////////////////////////////////////////////////////////////////////
// Helper Functions
////////////////////////////////////////////////////////////////////////////////

/**
 * Generate the message digest from the given data.
 * It will return API_STATUS_ERR_USER1 if the signature block cannot be found in
 * the BGPSec Path Attribute data
 * 
 * The following status settings are returned:
 * 
 * API_STATUS_ERR_USER1: The data contains already a digest.
 * API_STATUS_ERR_USER2: No matching signature block could be found.
 * APU_STATUS_ERR_NO_DATA: Data of some kind is missing.
 * 
 * 
 * @param data Contains the BGPSec Path attribute as it is on the wire and all 
 *             the required information.
 * @param algoID Look for the signatures of the given algorithm suite id
 * @param status The status flag in case of 0 return value
 * 
 * @return the number of bytes used in the internal buffer or 0.
 */
int sca_generateHashMessage(SCA_BGPSecValidationData* data, u_int8_t algoID, 
                            sca_status_t* status);

/**
 * This function generates the Hash for a prefix origination. This is used for
 * signing.
 * 
 * @param targetAS The target AS
 * @param spSeg The Secure Path segment of the origin
 * @param nlri The NLRI information
 * @param algoID The algorithm site identifier.
 * 
 * @return Return the hash message.
 */
SCA_HashMessage* sca_generateOriginHashMessage(u_int32_t targetAS, 
                                            SCA_BGPSEC_SecurePathSegment* spSeg, 
                                            SCA_Prefix* nlri, u_int8_t algoID);

/**
 * This function will free only the internal digest structure and only if the 
 * flag 
 * 
 * @param data The validation data that contain the validation digest that
 *             has to be deleted.
 */
bool sca_freeHashInput(SCA_HashMessage* data);

/**
 * This function sets the key path.
 *
 * @return API_SUCCESS or API_FAILURE 
 *
 */
int sca_SetKeyPath (char* key_path);

/**
 * This method generates a filename out of the given SKI.
 *
 * @param filenamebuf The pre-allocated filename buffer which will be filled
 *                    with the filename.
 * @param filenamebufLen Maximum length of the buffer.
 * @param ski       The SKI where the filename will be generated from
 *
 * @return The filename buffer that was handed over.
 */
char* sca_FindDirInSKI (char* filenamebuf, size_t filenamebufLen, u_int8_t* ski);

/**
 * Load the key from the key vault location configured within the API. The key
 * needs the SKI specified in binary format.
 * The returned key is in DER format. The parameter fPrivate is used to
 * indicate if the private or public key will be returned. This is of importance
 * in case both keys exist. Both keys will have the same SKI.
 *
 * @param key Pre-allocated memory where the ley will be loaded into.
 * @param fPrivate indicates if the key is private or public.
 * @param status The status information - The status flag will NOT be 
 *                                        initialized.
 *
 * @return API_SUCCESS or API_FAILURE (see status) 
 */
int sca_loadKey(BGPSecKey* key, bool fPrivate, sca_status_t* status);

/**
 * Set the file extension for DER encoded private key.
 * 
 * @param key_ext The file extension
 * 
 * @return API_SUCCESS or API_FAILURE 
 * 
 * @since 0.1.2.0
 */
int sca_setDER_ext (char* key_ext);

/**
 * Set the file extension for the DER encoded x509 certificate containing the 
 * public key.
 * 
 * @param x509_ext The file extension
 * 
 * @return API_SUCCESS or API_FAILURE 
 * 
 * @since 0.1.2.0
 */
int sca_setX509_ext (char* x509_ext);

/**
 * Writes the logging information.
 *
 * @param level The logging level
 * @param format The format of the logging info
 * @param ...
 */
void sca_debugLog(int level, const char *format, ...);

/**
 * Return the configured log level.
 * 
 * @return the logLevel configured.
 * 
 * @since 0.1.2.0
 */
long sca_getCurrentLogLevel();

/**
 * Print the status information in human readable format
 * 
 * @param status The status to be printed
 * 
 * @since 0.2.0.0
 */
void sca_printStatus(sca_status_t status);

/**
 * Return the algorithm ID used for this hashMEssage
 * 
 * @param hashMessage The hash Message.
 * 
 * @return The algorithm ID for this hash Message or 0 if none can be found.
 * 
 * @since 0.2.0.0
 */
u_int8_t sca_getAlgorithmID(SCA_HashMessage* hashMessage);

/**
 * Return the algorithm ID's from the BGPsec_PATH attribute. It is possible 
 * that no signature block can be found within a iBGP announced update.
 * 
 * The pointers algoID1 and algoID2 are return values if not NULL.
 * 
 * @param attr the bgpsec algorithm ID
 * @param status The status information - The status flag will NOT be 
 *                                        initialized.
 * @param algoID1 The algorithm ID of signature block one or 0 if not found. 
 * @param algoID2 The algorithm ID of signature block two or 0 if not found.
 * 
 * @return API_SUCCESS or API_FAILURE
 * 
 * @since 0.3.0.0
 */
u_int8_t sca_getAlgorithmIDs(SCA_BGP_PathAttribute* attr, sca_status_t* status,
                             u_int8_t* algoID1, u_int8_t* algoID2);
#endif /* _SRXCRYPTOAPI_H*/