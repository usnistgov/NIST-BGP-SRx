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
 * This plug-in provides an OpenSSL ECDSA implementation for BGPSEC.
 *
 * @version 0.3.0.0
 *
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *   0.3.0.0 - 2017/09/13 - oborchert
 *             * Modified init in such that not finding the ski-list file during
 *               init does NOT return an ERROR, it returns a USER INFO instead. 
 *               This is a recoverable error, the caller can register the keys
 *               in this case afterwards. -> Recoverable.
 *           - 2017/09/06 - oborchert
 *             * Fixed syntax error in return value of init method
 *             * Added missing mappings to function comptest.
 *           - 2017/08/18 - oborchert
 *             * BZ1141: Fixed speller in API function name. Now reference to 
 *               fixed name sca_generateOriginHashMessage
 *           - 2017/08/17 - oborchert
 *             * Added function comptest to allow compiler warnings if 
 *               implementation does not match specification.
 *           - 2017/08/16 - oborchert
 *             * Update to comply with API version 0.3.0.0
 *             * Added missing functions and modified implementation of existing 
 *               one to include some functionality (except crypto)
 *   0.2.0.3 - 2017/06/05 - oborchert
 *             * Modified getDebugLevel to return the current used debug level.
 *             * Moved some LOG_WARNING and LOG_INFO to LOG_DEBUG
 *           - 2017/04/21 - oborchert
 *             * Slightly remodeled the register key functions.
 *             * modified _readKeyFile.
 *             * Added some more documentation.
 *           - 2017/04/20 - oborchert
 *             * Fixed error in version control date.
 *             * Added some clarifying in-line documentation.
 *             * Updated function documentation
 *   0.2.0.2 - 2017/01/12 - oborchert
 *             * Fixed bug 1068, hash memory allocated by this API did not get
 *               freed upon freeHashMessage call.
 *           - 2016/11/16 - oborchert
 *             * Added some more documentation regarding the error reporting.
 *   0.2.0.1 - 2016/07/03 - oborchert
 *             * Fixed bug in while signing. The Sign method did not sign over
 *               hash, it signed over the hash message from which the hash is
 *               generated.
 *   0.2.0.0 - 2016/06/30 - oborchert
 *             * Cleaned up unused code and removed compiler warnings
 *           - 2016/06/26 - oborchert
 *             * Added algorithmID and ski used to the signature.
 *             * Marked signature to be owned by API
 *           - 2016/06/20 - oborchert
 *             * Added required modifications regarding the hashMessage and
 *               signature release.
 *           - 2016/05/24 - oborchert
 *             * Moved code to validation draft 15
 *   0.1.3.0 - 2016/04/29 - oborchert
 *             * Additional modification in ERROR reporting as well as
 *               logging of results.
 *           - 2016/04/28 - kyehwanl
 *             * Modified reporting of ERROR, SUCCESS and FAILURE during
 *               validation
 *   0.1.2.1 - 2016/03/11 - kyehwanl
 *             * Complement ExtBgpsecVerify function with using pubkey ids
 *           - 2016/02/09 - oborchert
 *             * Removed key loading functions, code is provided by srxcryptoapi
 *           - 2016/02/04 - kyehwanl
 *             * deprecated codes removed
 *           - 2016/02/02 - oborchert
 *             * Added init method.
 *   0.1.2.0 - 2016/01/05 - kyehwanl
 *             * Provide extValidate function
 *           - 2016/01/04 - oborchert
 *             * Changed return value if isExtended from 1 to 0
 *           - 2015/12/03 - oborchert
 *             * Fixed location of bgpsec_openssl.h
 *           - 2015/09/25 - oborchert
 *             * Resolved compiler warnings.
 *           - 2015/09/22 - oborchert
 *             * Added ChangeLog to file.
 *   0.1.0.0 - 2015 - kyehwanl
 *             * Created File.
 */
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdio.h>
#include <setjmp.h>


/* general API header which will be public to the customer side */
#include "../srx/srxcryptoapi.h"
#include "key_storage.h"

/** This define is used in init() to specify if configured keys should
 * immediately be converted into EC_KEYs*/
#define DO_CONVERT true
#define DEBUG_TBD

/** indicates if the library is initialized */
static bool BOSSL_initialized = false;
/** contains the public key storage. */
static KeyStorage* BOSSL_pubKeys = NULL;
/** contains the private key storage. The more keys the slower signing. */
static KeyStorage* BOSSL_privKeys = NULL;
inline void printHex(int , unsigned char* );

/**
 * Read the given file and pre-load all keys. The following non error status
 * can be set:
 * 
 *   API_STATUS_INFO_KEY_NOTFOUND: One or more keys are not found
 *   API_STATUS_ERR_KEY_IO: The key-list file was not found. The logging is set 
 *                          to WARNING.
 *
 * This function is mainly used during initialization to allow pre-loading of
 * keys.
 * 
 * This function uses SCA_KSOURCE_INTERNAL as source value.
 *
 * @param fName The name of the file ('\0' terminated String)
 * @param isPrivate indicate if the keys are private or public
 * @param status Set the status flag in case of an ERROR of for INFO
 * @param convert Try to immediately convert the keys into EC_KEY
 */
static void _readKeyFile(char* fName, bool isPrivate, sca_status_t* status,
                         bool convert)
{
  // Took Coding from BGPSEC-IO::ASList
  FILE *fPtr = fopen(fName, "r");
  char line[1024];
  int read = 0;

  BGPSecKey    key;
  sca_status_t myStatus = API_STATUS_OK;

  u_int32_t idx = 0;
  u_int8_t* ptr;
  bool      skipLine = false;

  if (fPtr)
  {
    memset (&key, 0, sizeof(BGPSecKey)); // initialize to prevent security issues

    while (fgets(line, 1024, fPtr) != NULL)
    {
      // Initialize the key
      if (key.keyData != NULL)
      {
        free(key.keyData);
        key.keyData   = NULL;
        key.keyLength = 0;
      }
      memset (&key, 0, sizeof(BGPSecKey));
      key.algoID = SCA_ECDSA_ALGORITHM;

      skipLine = false;
      read = strlen(line);
      if (read > SKI_HEX_LENGTH)
      {
        key.asn = 0;
        memset(&key.ski, 0, SKI_LENGTH);

        for (idx = 0; idx < read; idx++)
        {
          switch (line[idx])
          {
            case '0' ... '9':
              key.asn = (key.asn * 10) + (line[idx] - '0');
              break;
            case ' ':
              ptr = (u_int8_t*)line;
              ptr += idx + 1;
              char* valStr = (char*)ptr;
              // hexBuff is a \0 terminated string, - thats why it needs 5 bytes
              // to represent '0' 'x' 'A' 'B' '\0' for the string 0xAB
              char hexBuff[5] = {'0', 'x', 0, 0, 0};
              for (idx=0; idx < SKI_LENGTH; idx++)
              {
                hexBuff[2] = valStr[0];
                hexBuff[3] = valStr[1];
                key.ski[idx] = (u_int8_t)strtol(hexBuff, NULL, 0);
                valStr += 2;
              }
              idx = read;
              break;
            case '#':
              if (idx == 0)
              {
                // Skipp Line if # occurs as first character
                idx = read;
                skipLine = true;
                continue; // the for loop
              }
            default:
              break;
          }
        }
        if (!skipLine)
        {
          // Transform ASN into network format.
          key.asn = htonl(key.asn);

          // Now load the DER key
          if (sca_loadKey(&key, isPrivate, &myStatus) == API_FAILURE)
          {
            sca_debugLog(LOG_ERR, "Could not load key (status=0x%X)\n", myStatus);
            sca_printStatus(myStatus);
            if (key.keyData != NULL)
            {
              free(key.keyData);
              key.keyData = NULL;
            }
            key.keyLength = 0;
            break;
          }

          if (!isPrivate)
          {
            if (ks_storeKey(BOSSL_pubKeys, &key, SCA_KSOURCE_INTERNAL, 
                            &myStatus, convert)
                != API_SUCCESS)
            {
              sca_debugLog(LOG_ERR, "Could not store private key!\n");
              sca_printStatus(myStatus);
              break;
            }
          }
          else
          {
            ks_storeKey(BOSSL_privKeys, &key, SCA_KSOURCE_INTERNAL, &myStatus, 
                        convert);
          }
        }
      }
    }
    fclose(fPtr);
    if (key.keyData != NULL)
    {
      free (key.keyData);
      key.keyData   = NULL;
      key.keyLength = 0;
    }
  }
  else
  {
    sca_debugLog(LOG_WARNING, "Cannot find key-list file '%s'\n", fName);
    myStatus |= API_STATUS_ERR_KEY_IO;
  }

  if (status != NULL)
  {
    *status = myStatus;
  }
}

/**
 * The init method initialized the API. Only one failure can be imagined here,
 * a consecutive call of the init method. Next to the specified error status
 * values the following user values are provided:
 * 
 * API_STATUS_ERR_USER1:         The init method is called twice or more.
 * API_STATUS_ERR_USER2:         The value parameter has invalid syntax.
 * 
 * API_STATUS_INFO_KEY_NOTFOUND: One or more public keys not found
 * API_STATUS_INFO_USER1: the private key init keyfile cannot be found.
 * API_STATUS_INFO_USER2: the public key init keyfile cannot be found.
 *
 * In case value is not NULL it can contain the following string:
 * <type>:<filename>[;<type>:<filename>;]
 * with type == PRIV for private keys and PUB == public keys.
 * Each file must have the following content structure:
 * <ASN>-SKI: <SKI HEX VALUE>
 *
 * This values are parsed and used to load the keys using the srxcryptoapi
 * function sca_loadKeys.
 *
 * @param value Allows to pass a filenames containing private / public keys.
 * @param logLevel Ignored - Uses the loglevel of srxcryptoapi!
 * @param status An out parameter that will contain information in case of
 *               failures.
 *
 * @return API_SUCCESS or API_FAILURE (see status)
 *
 * @since 0.1.2.0
 */
int init(const char* value, int logLevel, sca_status_t* status)
{
  sca_setCurrentLogLevel(logLevel);

  int retVal = API_SUCCESS;
  
  // Just to be compliant with the specification
  char* warning = \
        "+--------------------------------------------------------------+\n" \
        "| API: libBGPSec_OpenSSL.so                                    |\n" \
        "| WARNING: This API provides a reference implementation for    |\n" \
        "| BGPSec crypto processing. The key storage provided with this |\n" \
        "| API does not provide a 'secure' key storage which protects   |\n" \
        "| against malicious side attacks. Also it is not meant to be   |\n" \
        "| a FIBS certified key storage.                                |\n" \
        "| This API uses open source OpenSSL functions and checks, keys |\n" \
        "| for their correctness and once done, uses it repeatedly!     |\n" \
        "+--------------------------------------------------------------+\n";
  printf ("%s", warning);

  sca_status_t myStatus = API_STATUS_OK;

  if (!BOSSL_initialized)
  {
    BOSSL_pubKeys  = malloc(sizeof(KeyStorage));
    BOSSL_privKeys = malloc(sizeof(KeyStorage));
    ks_init(BOSSL_pubKeys,  SCA_ECDSA_ALGORITHM, false);
    ks_init(BOSSL_privKeys, SCA_ECDSA_ALGORITHM, true);
    // used to determine which keys are contained in a possible file.
    bool isPrivate = false;

    char  string[MAX_CFGFILE_NAME];
    char* tmpValue = (char*)value;
    int   strLen = (value != NULL) ? strlen(value) : 0;

    while (strLen > 0 && ((myStatus & API_STATUS_ERROR_MASK) == 0 ))
    {
      // Check for either value, PUB: or PRIV:
      int typeLen = strspn(tmpValue, "PUBRIV:");
      if (typeLen != 0)
      {
        memset (&string, '\0', MAX_CFGFILE_NAME);
        memccpy(&string, tmpValue, MAX_CFGFILE_NAME-1, typeLen);
        if (strcmp("PUB:\0", string) == 0)
        {
          isPrivate = false;
        }
        else if (strcmp("PRIV:\0", string) == 0)
        {
          isPrivate = true;
        }
        else
        {
          // Invalid init string
          myStatus |= API_STATUS_ERR_USER2;
          continue;
        }
        tmpValue += typeLen;
        strLen   -= typeLen;

        // Now get the filename
        int fNameLength = strcspn(tmpValue, ";");
        if (fNameLength != 0)
        {
          memset (&string, '\0', MAX_CFGFILE_NAME);
          memccpy(&string, tmpValue, MAX_CFGFILE_NAME-1, fNameLength);

          strLen   -= fNameLength;
          tmpValue += fNameLength;

          sca_status_t tmpStatus = API_STATUS_OK;
          // Load the file and all the keys.
          _readKeyFile(string, isPrivate, &tmpStatus, DO_CONVERT);
          if ((tmpStatus & API_STATUS_ERROR_MASK) != 0)
          {
            // Check if the error is recoverable
            if ((tmpStatus & API_STATUS_ERR_KEY_IO) > 0)
            {
              // Add the info setting
              tmpStatus |= isPrivate ? API_STATUS_INFO_USER1
                                     : API_STATUS_INFO_USER2;
              // REmove the error
              tmpStatus = tmpStatus & ~API_STATUS_ERR_KEY_IO;              
            }
            myStatus |= tmpStatus;
          }

          if (strLen > 0)
          {
            // Jump over the ';'
            tmpValue++;
            strLen--;
          }
        }
        else
        {
          myStatus |= API_STATUS_ERR_USER2;;
        }
      }
      else
      {
        myStatus |= API_STATUS_ERR_USER2;;
      }
    }
  }
  else
  {
    myStatus |= API_STATUS_ERR_USER1;
    sca_debugLog(LOG_ERR, "Internal key storage already initialized.\n", value);
  }

  if ((myStatus & API_STATUS_ERR_USER2) != 0)
  {
    sca_debugLog(LOG_ERR, "Invalid initialization parameter value='%s'\n", value);
  }

  if (status != NULL)
  {
    *status = myStatus;
  }

  if ((myStatus & API_STATUS_ERROR_MASK) == API_STATUS_OK)
  {
    BOSSL_initialized = true;
    sca_debugLog(LOG_INFO, "The internal key initialized storage holds (%u "
                           "private and %u public keys)!\n",
                           BOSSL_privKeys->size, BOSSL_pubKeys->size);
  }
  else
  {
    retVal = API_FAILURE;
    ks_release(BOSSL_privKeys);
    ks_release(BOSSL_pubKeys);
    BOSSL_initialized = false;
  }

  return retVal;
}

/**
 * Return the actively used debug level
 *
 * @return the debug level used within the API
 */
int getDebugLevel()
{
  return (int)sca_getCurrentLogLevel();
}

/**
 * This API does not support individual logging configuration!
 *
 * @param debugLevel Ignored!
 *
 * @return -1
 */
int setDebugLevel(int debugLevel)
{
  return -1;
}

/**
 * This will be called prior un-binding the library. This allows the API
 * implementation to perform a clean shutdown / cleanup.
 *
 * @param status The status variable that returns more information.
 *
 * @return API_SUCCESS(1) or API_FAILURE (0 - check status)
 */
int release(sca_status_t* status)
{
  if (BOSSL_initialized)
  {
    ks_empty(BOSSL_pubKeys);
    free(BOSSL_pubKeys->head);
    BOSSL_pubKeys->head = NULL;
    free(BOSSL_pubKeys);
    BOSSL_pubKeys = NULL;

    ks_empty(BOSSL_privKeys);
    free(BOSSL_privKeys->head);
    BOSSL_privKeys->head = NULL;
    free(BOSSL_privKeys);
    BOSSL_privKeys = NULL;

    BOSSL_initialized = false;
  }

  if (status != NULL)
  {
    *status = API_STATUS_OK;
  }

  return API_SUCCESS;
}

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
bool freeHashMessage(SCA_HashMessage* hashMessage)
{
  // To allow the memory being freed, set ownedByAPI to false. BZ1068
  if (hashMessage != NULL)
  {
    hashMessage->ownedByAPI = false;
  }
  return sca_freeHashInput(hashMessage);
}

/**
 * Signatures are generated by the API and also freed by the API module.
 *
 * @param signature The signature element.
 *
 * @return false if the API is not the owner of the memory and cannot release
 *         the allocation, otherwise true
 */
bool freeSignature(SCA_Signature* signature)
{
  bool retVal = false;

  if (signature != NULL)
  {
    if (signature->ownedByAPI)
    {
      if (signature->sigBuff != NULL)
      {
        memset(signature->sigBuff, 0, signature->sigLen);
      }
      free(signature->sigBuff);
      memset(signature, 0, sizeof(SCA_Signature));
      free (signature);
      
      retVal = true;
    }
  }

  return retVal;
}

/**
 * Generate the hash out of the digest message
 *
 * @param message The message to be hashed
 * @param length the length of the message
 * @param digestBuff the digest buffer.
 *
 * @return the digest buffer
 */
static unsigned char* _createSha256Digest(const unsigned char* message,
                                          unsigned int length,
                                          u_int8_t* digestBuff)
{
  unsigned char result[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256ctx;
  SHA256_Init(&sha256ctx);
  SHA256_Update(&sha256ctx, message, length);
  SHA256_Final(result, &sha256ctx);

  if (digestBuff != NULL)
  {
    memcpy(digestBuff, result, SHA256_DIGEST_LENGTH);
  }
  return digestBuff;
}

/**
 * Perform BGPSEC path validation. This function required the keys to be
 * pre-registered to perform the validation.
 * The caller manages the memory and MUST assure the memory is intact until
 * the function returns.
 *
 * The following error status codes can be set:
 *
 * API_STATUS_ERR_USER1: The hash input could not be generated
 * API_STATUS_ERR_INVALID_KEY: The hex key retrieved from the storage is NULL.
 * API_STATUS_NO_DATA: No data to validate passed.
 * API_STATUS_INFO_KEY_NOTFOUND: One or more of the keys could not be found.
 * API_STATUS_INFO_SIGNATURE: One or more signatures could not be validated.
 *
 *
 * @param data This structure contains all necessary information to perform
 *             the path validation. The status flag will contain more
 *             information
 *
 * @return API_VALRESULT_VALID(1) or API_VALRESULT_INVALID(0). For 0 refer to
 *          the status code. Internal errors result in invalid.
 */
int validate(SCA_BGPSecValidationData* data)
{
  // @TODO: Currently we only deal with the first validation data result.
  //       It needs to be modified in such that it uses both results [0] and [1]
  int retVal = API_VALRESULT_INVALID;

  // Do some preliminary check
  if (data != NULL)
  {
    data->status = API_STATUS_ERR_NO_DATA;
    if (data->nlri != NULL)
    {
      if (data->bgpsec_path_attr != NULL)
      {
        // Generate the hash if none was generated prior.
        if (data->hashMessage[0] == NULL)
        {
          if (sca_generateHashMessage(data, SCA_ECDSA_ALGORITHM, &data->status) > 0)
          {
            // Now reset the values to allow the validation to be performed.
            data->status = API_STATUS_OK;
            retVal       = API_SUCCESS;
          }
          else
          {
            data->status = API_STATUS_ERR_USER1;
            retVal       = API_VALRESULT_INVALID;
          }
        }
        else
        {
          data->status = API_STATUS_OK;
          retVal       = API_VALRESULT_VALID;
        }
      }
    }
  }

  // Now perform validation
  if (retVal == API_VALRESULT_VALID)
  {
    // Now we can validate each signature -> This can be multi threaded
    // in this case the variables below need to be declared in each thread
    // separately.
    u_int32_t* asn       = NULL;
    EC_KEY**   ecdsa_key = NULL;
    u_int8_t*  signature = NULL;
    u_int16_t  sigLength = 0;
    SCA_BGPSEC_SignatureSegment* sigSeg = NULL;
    int idx = 0;

    u_int16_t noKeys = 0;
    int ecIdx = 0;

    // Temporary space for the generated message digest (hash)
    u_int8_t hashDigest[SHA256_DIGEST_LENGTH];

    for (; idx < data->hashMessage[0]->segmentCount; idx++)
    {
      // We want to have the signer key, This will be found in the next
      // path segment.
      if (idx+1 < data->hashMessage[0]->segmentCount)
      {
        asn = (u_int32_t*)data->hashMessage[0]->hashMessageValPtr[idx+1]->hashMessagePtr;
      }
      else
      {
        // Jump to the origin AS
        asn = (u_int32_t*)(data->hashMessage[0]->hashMessageValPtr[idx]->hashMessagePtr+6);
      }
      sigSeg = (SCA_BGPSEC_SignatureSegment*)data->hashMessage[0]->hashMessageValPtr[idx]->signaturePtr;

      /* The OpenSSL encoded key. */
      ecdsa_key = (EC_KEY**)ks_getKey(BOSSL_pubKeys, sigSeg->ski, *asn,
                            &noKeys, ks_eckey_e, &data->status);
      if (ecdsa_key != NULL)
      {
        // Generate the hash (messageDigest that will be signed.)
        _createSha256Digest (
                 data->hashMessage[0]->hashMessageValPtr[idx]->hashMessagePtr,
                 data->hashMessage[0]->hashMessageValPtr[idx]->hashMessageLength,
                 (u_int8_t*)&hashDigest);

        if (sca_getCurrentLogLevel() >= LOG_DEBUG)
        {
          sca_debugLog(LOG_DEBUG, "\nHash(validate):");
          printHex(data->hashMessage[0]->hashMessageValPtr[idx]->hashMessageLength,
              data->hashMessage[0]->hashMessageValPtr[idx]->hashMessagePtr);
          sca_debugLog(LOG_DEBUG, "\nDigest(validate):");
          printHex(SHA256_DIGEST_LENGTH, (u_int8_t*)hashDigest);
        }

        signature = data->hashMessage[0]->hashMessageValPtr[idx]->signaturePtr
                    + sizeof(SCA_BGPSEC_SignatureSegment);
        // find the signature:
        sigLength = ntohs(sigSeg->siglen);

        retVal = API_VALRESULT_INVALID;
        for (ecIdx=0; ecIdx < noKeys && retVal==API_VALRESULT_INVALID; ecIdx++)
        {
          if (ecdsa_key[ecIdx] != NULL)
          { // Toggle through the keys
            /* verify the signature */
            if (ECDSA_verify(0, hashDigest, SHA256_DIGEST_LENGTH,
                             signature, sigLength, ecdsa_key[ecIdx])
               == 1)
            {
              retVal = API_VALRESULT_VALID;
              sca_debugLog(LOG_DEBUG, "\033[92m""stack[%d] VERIFY SUCCESS""\033[0m \n", idx+1);
            }
            else
            {
              retVal = API_VALRESULT_INVALID;
              sca_debugLog(LOG_DEBUG,
                  "\033[91m""stack[%d] VERIFY FAILED (SKI: %02X%02X%02X%02X)""\033[0m \n",
                  idx+1,
                  sigSeg->ski[0], sigSeg->ski[1], sigSeg->ski[2], sigSeg->ski[3]);
              break;
            }
          }
          else
          {
            // Most likely a registration error!
            data->status |= API_STATUS_ERR_INVLID_KEY;
            sca_debugLog(LOG_WARNING, "The key storage returned a NULL eckey\n");
          }
        }

        if (retVal == API_VALRESULT_INVALID)
        {
          data->status |= API_STATUS_INFO_SIGNATURE;
          sca_debugLog(LOG_DEBUG, "[%s:%d] verify failed and quit: ret:%d idx:%d, ecIdx:%d\n",
              __FUNCTION__, __LINE__, retVal, idx, ecIdx );
          break; // No further validation needed
        }
      }
      else
      {
        retVal = API_VALRESULT_INVALID;
        data->status |= API_STATUS_INFO_KEY_NOTFOUND;
        sca_debugLog(LOG_DEBUG,
            "\033[91m""NO KEY -> VERIFY FAILED (SKI: %02X%02X%02X%02X)""\033[0m \n",
                  sigSeg->ski[0], sigSeg->ski[1], sigSeg->ski[2], sigSeg->ski[3]);
        break; // No further validation needed
      }
    }
  }

  return retVal;
}

/**
 * Implementation of a single sign operation. Called by the external visible
 * sign function.
 *
 * The following errors can be reported:
 *   API_STATUS_ERR_INVLID_KEY: The algorithm id is wrong or the loaded key
 *                              is invalid.
 *   API_STATUS_ERR_NO_DATA: Some of the required data is missing.
 *   API_STATUS_ERR_UNSUPPORTED_ALGO: The algorithm is not supported.
 * 
 *   API_STATUS_INFO_KEY_NOT_FOUND: As it says
 *   API_STATUS_INFO_SIGNATURE: Could not generate a signature
 *
 *
 * @param bgpsec_data The data object to be signed. This also includes the
 *                    generated signature.
 * @param ski The ski of the key to be used.
 *
 * @return API_SUCCESS or API_FAILURE 
 */
static int _sign(SCA_BGPSecSignData* bgpsec_data)
{
  int          retVal   = API_FAILURE;
  sca_status_t myStatus = API_STATUS_ERR_NO_DATA;
  bool         origin   = true;

  // At this point lets see what king of input data we have. In case of origin
  // we only might have the nlri, host information, and target.
  // Otherwise we will have a bgpsec path attribute.
  // In both cases we need the host, key, and target information
  // - lets first make sure we have this minimum of data available. Once this
  // is established check for the next required set of data according to the
  // mode - originate or transit.
  if (bgpsec_data != NULL)
  {
    // So what is needed is this host information
    if (bgpsec_data->myHost != NULL)
    {
      // We need the ski to get the key
      if (bgpsec_data->ski != NULL)
      {
        myStatus = API_STATUS_OK;
      }
    }
  }

  if (bgpsec_data->algorithmID != BOSSL_privKeys->algorithmID)
  {
    myStatus |= API_STATUS_ERR_INVLID_KEY;
  }
  else
  {
    // now check if transit or origination
    origin = bgpsec_data->hashMessage == NULL;
    if (origin)
    {
      // We need the NLRI to generate the hash message.
      if (bgpsec_data->nlri != NULL)
      {
        // Now generate the hash Message:
        bgpsec_data->hashMessage = sca_generateOriginHashMessage(
            bgpsec_data->peerAS,
            bgpsec_data->myHost, bgpsec_data->nlri,
            bgpsec_data->algorithmID);
      }
      else
      {
        myStatus = API_STATUS_ERR_NO_PREFIX;
      }
    }
  }

  if (myStatus == API_STATUS_OK)
  {
    // First find the key
    u_int16_t noKeys = 0;
    bgpsec_data->status = API_STATUS_OK;
    EC_KEY** ec_keys = (EC_KEY**)ks_getKey(BOSSL_privKeys, bgpsec_data->ski,
        bgpsec_data->myHost->asn, &noKeys,
        ks_eckey_e, &bgpsec_data->status);
    if (noKeys != 0)
    {
      // I know we do double work if this is an origin announcement. But only
      // the first time because we now will store the hash and can re-use it
      // the next time.
      // There we might change the target AS and we might want to change
      // pCount ans flags so that's why we need to rewrite this data each
      // time. - Yes we overwrite the host AS each time
      u_int8_t*  buffPtr  = bgpsec_data->hashMessage->buffer;
      u_int32_t* targetAS = (u_int32_t*)buffPtr;
      *targetAS = bgpsec_data->peerAS;
      buffPtr += 4; // Move to the path segment

      /* separate memcopy for origin and intermediate */
      if(origin)
        memcpy(buffPtr, bgpsec_data->myHost, LEN_SECPATHSEGMENT);
      else
        memcpy(bgpsec_data->hashMessage->hashMessageValPtr[0]->hashMessagePtr-2,
            bgpsec_data->myHost, LEN_SECPATHSEGMENT);

      u_int16_t sigLen  = ECDSA_size(ec_keys[0]);
      uint usedLen = 0;
      u_int8_t* sigBuff = malloc(sigLen);
      memset (sigBuff, 0, sigLen);

      /* temporay prepare two pointer holders for multi hop validation */
      u_int8_t *pTmpHashMsgPtr = NULL;
      u_int16_t iTmpHashMsgLeng = 0;

      /* adjust hash message pointer for multi hop validation */
      if(!origin)
      {
        pTmpHashMsgPtr  = bgpsec_data->hashMessage->hashMessageValPtr[0]->hashMessagePtr;
        iTmpHashMsgLeng = bgpsec_data->hashMessage->hashMessageValPtr[0]->hashMessageLength;

        bgpsec_data->hashMessage->hashMessageValPtr[0]->hashMessagePtr =
          bgpsec_data->hashMessage->buffer;
        bgpsec_data->hashMessage->hashMessageValPtr[0]->hashMessageLength =
          bgpsec_data->hashMessage->bufferSize;
      }

      // Now generate the hash
      // Temporary space for the generated message digest (hash)
      u_int8_t hashDigest[SHA256_DIGEST_LENGTH];
      // Generate the hash (messageDigest that will be signed.)
      _createSha256Digest (
          bgpsec_data->hashMessage->hashMessageValPtr[0]->hashMessagePtr,
          bgpsec_data->hashMessage->hashMessageValPtr[0]->hashMessageLength,
          (u_int8_t*)&hashDigest);

      if (sca_getCurrentLogLevel() >= LOG_DEBUG)
      {
        sca_debugLog(LOG_DEBUG, "\nHash(sign):");
        printHex(bgpsec_data->hashMessage->hashMessageValPtr[0]->hashMessageLength,
            bgpsec_data->hashMessage->hashMessageValPtr[0]->hashMessagePtr);
        sca_debugLog(LOG_DEBUG, "\nDigest(sign):");
        printHex(SHA256_DIGEST_LENGTH, (u_int8_t*)hashDigest);
      }

      // Use only the first key.
      int res = ECDSA_sign(0, hashDigest, SHA256_DIGEST_LENGTH,
          sigBuff, (unsigned int*)&usedLen, ec_keys[0]);

      /* after signing restore the saved pointer from the temp message holder */
      if(!origin)
      {
        bgpsec_data->hashMessage->hashMessageValPtr[0]->hashMessagePtr = pTmpHashMsgPtr;
        bgpsec_data->hashMessage->hashMessageValPtr[0]->hashMessageLength = iTmpHashMsgLeng;
      }

      if (res != 1)
      {
        myStatus |= API_STATUS_INFO_SIGNATURE;
        /* error */
        sca_debugLog(LOG_ERR, "+ [libcrypto] ECDSA_sign error: %s\n", \
            ERR_error_string(ERR_get_error(), NULL));
        ERR_print_errors_fp(stderr);
        free(sigBuff);
        sigBuff = NULL;
      }
      else
      {
        if (usedLen < sigLen)
        {
          sigBuff = realloc(sigBuff, usedLen);
        }

        if (bgpsec_data->signature != NULL)
        {
          // OK free up old data.
          freeSignature(bgpsec_data->signature);
        }
        bgpsec_data->signature             = malloc(sizeof(SCA_Signature));
        bgpsec_data->signature->ownedByAPI = true;
        bgpsec_data->signature->algoID     = bgpsec_data->algorithmID;
        memcpy(bgpsec_data->signature->ski, bgpsec_data->ski, SKI_LENGTH);
        //          bgpsec_data->signature->sigBuff    = malloc(usedLen);
        bgpsec_data->signature->sigLen     = usedLen;
        bgpsec_data->signature->sigBuff    = sigBuff;
        //memcpy(bgpsec_data->signature->sigBuff, &sigBuff, usedLen);
        retVal = API_SUCCESS;
      }
    }
  }

  if (bgpsec_data != NULL)
  {
    bgpsec_data->status |= myStatus;
  }

  return retVal;
}

/**
 * Sign the given BGPSecSign data using the given key. This method fills the
 * key into the BGPSecSignData object.
 *
 * The following errors can be reported:
 *   API_STATUS_ERR_INVLID_KEY: The algorithm id is wrong or the loaded key
 *                              is invalid.
 *   API_STATUS_ERR_NO_DATA: Some of the required data is missing.
 *   API_STATUS_ERR_UNSUPPORTED_ALGO: The algorithm is not supported.
 * 
 *   API_STATUS_INFO_KEY_NOT_FOUND: As it says
 *   API_STATUS_INFO_SIGNATURE: Could not generate a signature
 *
 *
 * @param bgpsec_data The data object to be signed. This also includes the
 *                    generated signature.
 * @param ski The ski of the key to be used.
 *
 * @return API_SUCCESS or API_FAILURE 
 */
int sign(int count, SCA_BGPSecSignData** bgpsec_data)
{
  int retVal = API_SUCCESS;
  int idx = 0;
  
  for (; idx < count; idx++)
  {
    if (_sign(bgpsec_data[idx]) == API_FAILURE)
    {
      retVal = API_FAILURE;
    }
  }
  
  return retVal;
}

/**
 * Register the given key. This method allows to register the
 * key with the API object. The key must be internally copied.
 * The memory is NOT shared for longer than the registration execution cycle.
 * NOTE: The key information MUST be copied within the API.
 *
 * The following errors can be reported:
 *   API_STATUS_ERR_NO_DATA: Some of the required data is missing.
 *   Also see key_storage.ks_storeKey()
 *
 * @param key The key itself - MUST contain the DER encoded key.
 * @param source The source of the key.
 * @param status Will contain the status information of this call.
 * @param isPublic The type of key to be stored.
 *
 * @return API_SUCCESS or API_FAILURE (check status)
 *
 * @since 0.2.0.3
 */
static u_int8_t _registerKey(BGPSecKey* key, sca_key_source_t source,
                             sca_status_t* status, bool isPrivate)
{
  u_int8_t retVal = API_FAILURE;
  if (key->keyLength != 0)
  {
    retVal = ks_storeKey(isPrivate ? BOSSL_privKeys : BOSSL_pubKeys,
                         key, source, status, true);
  }
  else if (status != NULL)
  {
    *status = API_STATUS_ERR_NO_DATA;
  }

  return retVal;
}

/**
 * Register the private key. This method allows to register the
 * private key with the API object. The Key must be internally copied.
 * The memory is NOT shared for longer than the registration execution cycle.
 * NOTE: The key information MUST be copied within the API.
 *
 * The following errors can be reported:
 *   API_STATUS_ERR_NO_DATA: Some of the required data is missing.
 *   Also see key_storage.ks_storeKey()
 *
 * @param key The key itself - MUST contain the DER encoded key.
 * @param status Will contain the status information of this call.
 *
 * @return API_SUCCESS or API_FAILURE
 */
u_int8_t registerPrivateKey(BGPSecKey* key, sca_status_t* status)
{
  return _registerKey(key, SCA_KSOURCE_INTERNAL, status, true);
}

/**
 * Remove the registration of a given key with the specified key ID.
 *
 * @param asn The ASN of the private key (network format).
 * @param ski The 20 Byte ski
 * @param algoID The algorithm ID of the key.
 * @param status Will contain the status information of this call.
 *
 * The following errors can be reported:
 *   See key_storage.ks_delKey()
 *
 * @return API_SUCCESS or API_FAILURE (check status)
 */
u_int8_t unregisterPrivateKey(u_int32_t asn, u_int8_t* ski, u_int8_t algoID, 
                              sca_status_t* status)
{
  BGPSecKey key;
  key.asn       = asn;
  key.algoID    = algoID;
  memcpy(&key.ski, ski, SKI_LENGTH);
  key.keyLength = 0;
  key.keyData   = NULL;
  return ks_delKey(BOSSL_privKeys, &key, SCA_KSOURCE_INTERNAL, status);
}

/**
 * Register the public key.
 * All keys must be registered within the API. This will allow to call the
 * verification without the need to determine the needed public keys by
 * the caller. The API will determine which key to be used.
 * NOTE: The key information MUST be copied within the API.
 *
 * The following errors can be reported:
 *   API_STATUS_ERR_NO_DATA: Some of the required data is missing.
 *   See key_storage.ks_storeKey()
 *
 * @param key The key itself - MUST contain the DER encoded key.
 * @param source The source of the key.
 * @param status Will contain the status information of this call.
 *
 * @return API_SUCCESS or API_FAILURE (check status)
 */
u_int8_t registerPublicKey(BGPSecKey* key, sca_key_source_t source,
                           sca_status_t* status)
{
  return _registerKey(key, source, status, false);
}

/**
 * Remove the registered key with the same ski and asn. (Optional)
 * This method allows to remove a particular key that is registered for the
 * given SKI and ASN.
 *
 * The following errors can be reported:
 *   See key_storage.ks_delKey()
 *
 * @param key The key needs at least contain the ASN and SKI.
 * @param source The source of the key
 * @param status Will contain the status information of this call.
 *
 * @return API_SUCCESS or API_FAILURE (check status)
 */
u_int8_t unregisterPublicKey(BGPSecKey* key, sca_key_source_t source,
                             sca_status_t* status)
{
  return ks_delKey(BOSSL_pubKeys, key, source, status);
}

/**
 * Internal method to clean the keys
 * 
 * @param source The key source which has to be removed.
 * @param status The status flag
 * @param isPrivate indicates if the keys are in the private (true) or 
 *                   public (false) key storage.
 */
static void _cleanKeys(sca_key_source_t source, sca_status_t* status, 
                       bool isPrivate)
{
  KeyStorage* storage = isPrivate ? BOSSL_privKeys : BOSSL_pubKeys;
  int count = ks_removeSource(storage, source);
  
  if (count == 0)
  {
    if (status != NULL)
    {
      *status = API_STATUS_INFO_KEY_NOTFOUND;
    }
  }
}

/**
 * Remove all public keys from the internal storage that were provided by the 
 * given key source.
 * 
 * @param source The source of the keys.
 * @param status Will contain the status information of this call.
 * 
 * API_STATUS_INFO_KEY_NOTFOUND: If no key was found.
 * 
 * @return API_SUCCESS
 * 
 * @since 0.3.0.0
 */
u_int8_t cleanKeys(sca_key_source_t source, sca_status_t* status)
{
  _cleanKeys(source, status, false);  
  return API_SUCCESS;
}

/**
 * Remove all private keys from the internal storage.
 * 
 * @param status Will contain the status information of this call.
 * 
 * @return API_SUCCESS or API_FAILURE (check status)
 * 
 * @since 0.3.0.0
 */
u_int8_t cleanPrivateKeys(sca_status_t* status)
{
  _cleanKeys(SCA_KSOURCE_INTERNAL, status, true);
  return API_SUCCESS;
}

/**
 * Allows to query if this plug-in supports the requested algorithm IDdd.
 * 
 * @param algoID The algorithm ID.
 * 
 * @return true if the algorithm is supported or not.
 * 
 * @since 0.3.0.0
 */
bool isAlgorithmSupported(u_int8_t algoID)
{
  return (algoID == SCA_ECDSA_ALGORITHM);
}


/** 
 * This function is only for the compiler to check the correct implementation
 * of the API. (Make sure all required functions do exist.)
 * 
 * @since 0.3.0.0
 */
 __attribute__((unused)) static void comptest()
{
  SRxCryptoAPI compAPI;
  compAPI.init                 = init;
  compAPI.release              = release;

  compAPI.sign                 = sign;
  compAPI.validate             = validate;

  compAPI.freeHashMessage      = freeHashMessage;
  compAPI.freeSignature        = freeSignature;

  compAPI.setDebugLevel        = setDebugLevel;
  compAPI.getDebugLevel        = getDebugLevel;

  compAPI.isAlgorithmSupported = isAlgorithmSupported;

  compAPI.registerPublicKey    = registerPublicKey;
  compAPI.unregisterPublicKey  = unregisterPublicKey;

  compAPI.registerPrivateKey   = registerPrivateKey;
  compAPI.unregisterPrivateKey = unregisterPrivateKey;

  compAPI.cleanKeys            = cleanKeys;
  compAPI.cleanPrivateKeys     = cleanPrivateKeys; 
}

__attribute__((always_inline)) inline void printHex(int len, unsigned char* buff)
{
  int i;
  for(i=0; i < len; i++ )
  {
    if(i%16 ==0) printf("\n");
    printf("%02x ", buff[i]);
  }
  printf("\n");
}

