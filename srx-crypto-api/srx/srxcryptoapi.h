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
 * @version 0.2.0.1
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
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
#define SKI_LENGTH     20
/** Twice the length of the SKI_LENGTH in binary form */
#define SKI_HEX_LENGTH 40

/** Update validation returns VALID */
#define API_VALRESULT_VALID    1
/** Update validation returns INVALID */
#define API_VALRESULT_INVALID  0

/* Mask to detect errors in the status flag. */
#define API_STATUS_ERROR_MASK           0xFF00
/* Mask to detect information in the status flag. */
#define API_STATUS_INFO_MASK            0x00FF
/** All OK - no additional information */
#define API_STATUS_OK                   0x0000
/** one or more signatures could failed validation */
#define API_STATUS_INFO_SIGNATURE       0x0001
/** A key not found */
#define API_STATUS_INFO_KEY_NOTFOUND    0x0002
/** A user defined status */
#define API_STATUS_INFO_USER1           0x0040
/** A user defined status */
#define API_STATUS_INFO_USER2           0x0080

// Error reports
/** Input update data / or precomputed hash is missing */
#define API_STATUS_ERR_NO_DATA          0x0100
/** Input prefix data is missing */
#define API_STATUS_ERR_NO_PREFIX        0x0200
/** Invalid key - e.g. RSA key and ECDSA key expected. */
#define API_STATUS_ERR_INVLID_KEY       0x0400
/** General key I/O error . */
#define API_STATUS_ERR_KEY_IO           0x0800
/** A hash buffer to small */
#define API_STATUS_ERR_INSUF_BUFFER     0x1000
/** A Not enough storage for keys */
#define API_STATUS_ERR_INSUF_KEYSTORAGE 0x2000
/** A user defined error */
#define API_STATUS_ERR_USER1            0x4000
/** A user defined error */
#define API_STATUS_ERR_USER2            0x8000


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
  u_int16_t attrLength; // requires ext. length 0x10 set
} __attribute__((packed)) SCA_BGPSEC_PathAttribute;

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
#define LEN_SECPATH_HDR         2
/** Same as sizeof(SCA_BGPSEC_SecurePathSegment) */
#define LEN_SECPATHSEGMENT      6
/** Same as sizeof(SCA_BGPSEC_SignatureBlock) */
#define LEN_SIGBLOCK_HDR        3
/** Same as sizeof(SCA_BGPSEC_PathAttribute) */
#define LEN_BGPSECPATHATTR_HDR  4
/** Same as sizeof(SCA_BGPSEC_SignatureSegment) */
#define LEN_SIGSEGMENT_HDR      22

////////////////////////////////////////////////////////////////////////////////
// SRx Crypto API Structures
////////////////////////////////////////////////////////////////////////////////

/** Used for the status information - Use this instead of u_int_16_t to allow
 * future type change if more codes are required. */
typedef u_int16_t sca_status_t;

// Crypto API types
/** The BGPSec Key wrapper. The stored key structure is in DER format.*/
typedef struct
{
  /** The id of the used algorithm suite (See RFC)*/
  u_int8_t  algoID;
  /** The ASN that uses the Key */
  u_int32_t asn;
  /** The SKI of the key */
  u_int8_t  ski[SKI_LENGTH];
  /** The length of the key byte stream. */
  u_int16_t keyLength;
  /** The key in DER format */
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
 * This structure is used as a helper to quickly access the data within the 
 * digest for the hash calculation. No parsing through the structure is 
 * necessary anymore.
 */
typedef struct 
{
  u_int8_t* signaturePtr;
  u_int8_t* hashMessagePtr;
  u_int16_t hashMessageLength;
} SCA_HashMessagePtr;

/** This structure will be generated during the digest generation. It can be
 * provided to the validate caller but the API is not required to use the 
 * hash input message (buffer) and can create it's own instead. */
typedef struct 
{
  /** Indicates if the memory of the signature buffer is maintained by the API. 
   * In this case it is required to call the freeHashMessage(...) function of 
   * the API instance. Otherwise a cleanup by the user can be performed. The 
   * instance of SCA_HashMessage must be freed by the user as well.
   */
  bool      ownedByAPI;
  /** number of segments in this buffer. */
  u_int16_t segmentCount;
  /** maximum size of the buffer. */
  u_int32_t bufferSize;
  /** The buffer itself. The first 4 bytes are reserved for the target AS used
   * for signing. Then followed by the last Signature, followed by 2 reserved 
   * bytes to be used for this hosts flag and pCount value. Then the digest for 
   * the signature starts. Therefore the digest of each signature starts at 
   * signatureLength + 2 bytes. The digestLen is calculated as followed:
   * usedBuffer - (currAddr-bufferAddr) with currAddr the pointer address of
   * the ASN where the signature is signed to and bufferAdd the buffer pointer 
   * itself.*/
  u_int8_t* buffer;
  /** This array contains one element for each segment. The pointers reach into 
   * the buffer for easy access during validation. */
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
 * This structure has to be filled by the user of the API. all fields except 
 * the digest field is an input field. It might be returned to the caller
 * but the API is responsible to removing it.
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


typedef struct
{
  /** The peer to whom to send the data to (network format). */
  u_int32_t peerAS;
  /** The information of this host (network format) */
  SCA_BGPSEC_SecurePathSegment* myHost;
  /** The prefix information - will only be used if the digest or digest buffer 
   * is empty (NULL)*/
  SCA_Prefix* nlri;
  /** The SKI for the private key. */
  u_int8_t* ski;      
  /** The algorithm ID. */
  u_int8_t algorithmID;
  /** The status */
  sca_status_t status;
  /** The message digest (IF NULL an internal one will be generated, if not null
   * it is expected it contains enough space to fill in the peerAS and myHost 
   * information. */
  SCA_HashMessage*  hashMessage;
  /** The signature segment. The memory is allocated within the API. */
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
   * This function returns 0 in case of an error. In this case the library 
   * cannot be used.
   * 
   * @param value A \0 terminated string or NULL.
   * @param debugLevel the debugging level - Follows the system debug levels.
   *                   -1 indicates to NOT modify the log level.
   * @param status The status variable that returns more information.
   * 
   * @return API_SUCCESS(1) or API_FAILURE (0 - check status)
   */
  int (*init)(const char* value, int debugLevel, sca_status_t* status);
  
  /**
   * This will be called prior un-binding the library. This allows the API 
   * implementation to perform a clean shutdown / cleanup.
   * 
   * @param status The status variable that returns more information.
   * 
   * @return API_SUCCESS(1) or API_FAILURE (0 - check status)
   */
  int (*release)(sca_status_t* status);
  
  /**
   * Perform BGPSEC path validation. This function required the keys to be 
   * pre-registered to perform the validation. 
   * The caller manages the memory and MUST assure the memory is intact until
   * the function returns.
   * This function only returns API_VALRESULT_VALID and API_VALRESULT_INVALID.
   * In case of erorrs API_VALRESULT_INVALID will be returned with an error code
   * passed in the status flag. This flag also contains more details about the 
   * validation status (why invalid, etc.)
   *
   * @param data This structure contains all necessary information to perform
   *             the path validation. The status flag will contain more 
   *             information
   *
   * @return API_VALRESULT_VALID (1) or API_VALRESULT_INVALID (0) and the status 
   *         flag contains further information - including errors.
   *         
   */
  int (*validate)(SCA_BGPSecValidationData* data);
   
  /**
   * Sign the given BGPSecSign data using the given key. This method fills the
   * key into the BGPSecSignData object.
   *
   * @param bgpsec_data The data object to be signed. This also includes the
   *                    generated signature.
   * @param ski The ski of the key to be used.
   *
   * @return API_SUCCESS (0) or API_FAILURE (1)
   * 
   */
  int (*sign)(SCA_BGPSecSignData* bgpsec_data);

  /**
   * Register the private key. This method allows to register the
   * private key with the API object. The key must be internally copied. 
   * The memory is NOT shared for longer than the registration execution cycle.
   * NOTE: The key information MUST be copied within the API.
   *
   * @param key The key itself - MUST contain the DER encoded key.
   * @param status Will contain the status information of this call.
   *
   * @return API_SUCCESS(1) or API_FAILURE(0 - check status)
   */
  u_int8_t (*registerPrivateKey)(BGPSecKey* Key, sca_status_t* status);

  /**
   * Remove the registration of a given key with the specified key ID. 
   *
   * @param key The key needs at least contain the ASN and SKI.
   * @param status Will contain the status information of this call.
   *
   * @return API_SUCCESS(1) or API_FAILURE(0 - check status)
   */
  u_int8_t (*unregisterPrivateKey)(BGPSecKey* ski, sca_status_t* status);

  /**
   * Register the public key.
   * All keys must be registered within the API. This will allow to call the 
   * verification without the need to determine the needed public keys by
   * the caller. The API will determine which key to be used.
   * 
   * NOTE: The key information MUST be copied within the API.
   *
   * @param key The key itself - MUST contain the DER encoded key.
   * @param status Will contain the status information of this call.
   *
   * @return API_SUCCESS(1) or API_FAILURE(0 - check status)
   */
  u_int8_t (*registerPublicKey)(BGPSecKey* key, sca_status_t* status);

  /**
   * Remove the registered key with the same ski and asn. (Optional)
   * This method allows to remove a particular key that is registered for the
   * given SKI and ASN.
   *
   * @param key The key itself.
   * @param status Will contain the status information of this call.
   *
   * @return API_SUCCESS(1) or API_FAILURE(0 - check status)
   */
  u_int8_t (*unregisterPublicKey)(BGPSecKey* key, sca_status_t* status);
  
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
   * Set the new debug level going forward. This methid returns the previous set 
   * debug level or -1 if not supported.
   * 
   * @param debugLevel The debug level to be set - Follows system debug values.
   * 
   * @return the previous debug level or -1
   */
  int (*setDebugLevel)(int debugLevel);  
  
} SRxCryptoAPI;

/* Function Declaration */

/**
 * This function initialized the SRxCrypto API. the SRxCryptoAPI object must be
 * created and released by the user of the API. In case the configuration is not
 * set the default API located in ./ will be loaded.
 *
 * @param api the api object.
 * @param status an OUT variable that contains status information.
 * 
 * @return API_SUCCESS(1) or API_FAILURE(0 - see status) 
 */
int srxCryptoInit(SRxCryptoAPI* api, sca_status_t* status);

/**
 * This function unloads the library that is loaded and NULLs all attached 
 * methods.
 * 
 * @param api Unbind the SRxCryptoAPI
 *
 * @return API_SUCCESS(1) or API_FAILURE(0 - see status) 
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
SCA_HashMessage* sca_gnenerateOriginHashMessage(u_int32_t targetAS, 
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
 * @return API_SUCCESS(1) or API_FAILURE(0) 
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
 * Load the key from the key volt location configured within the API. The key
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
 * @return API_SUCCESS(1) or API_FAILURE(0 - see status) 
 */
int sca_loadKey(BGPSecKey* key, bool fPrivate, sca_status_t* status);

/**
 * Set the file extension for DER encoded private key.
 * 
 * @param key_ext The file extension
 * 
 * @return API_SUCCESS(1) or API_FAILURE(0) 
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
 * @return API_SUCCESS(1) or API_FAILURE(0) 
 * 
 * @since 0.1.2.0
 */
int sca_setX509_ext (char* x509_ext);

/**
 * Writes the loging information.
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
 * @param status
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
#endif /* _SRXCRYPTOAPI_H*/