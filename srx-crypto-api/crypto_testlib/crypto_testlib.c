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
 * This software provides a test implementation for a BGPSec plugin. This
 * plugin does only provide empty functions. and is for test only.
 *
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *   0.1.2.1 - 2016/02/02 - oborchert
 *             * added init method
 *   0.1.2.0 - 2015/12/03 - oborchert
 *             * moved location of srxcryptoapi.h
 *           - 2015/11/03 - oborchert
 *             * modified return values of validation 
 *             * updated sign_with_id according to modifications in srxcryptoapi
 *               (BZ795)
 *             * modified function signature of sign_with_id (BZ788)
 *           - 2015/09/22 - oborchert
 *             * Added ChangeLog to file.
 *   0.1.0.0 - 2015 - oborchert
 *             * Created File.
 */
#include <syslog.h>
#include <stddef.h>
#include "../srx/srxcryptoapi.h"

#define YES     1
#define NO      0

/**
 * This is the internal wrapper function. Currently it does return only the 
 * error code and provides a debug log.
 * 
 * @param bgpsec_path pointer to the BGPSEC path attribute.
 * @param number_keys The number of keys passed within the key array.
 * @param keys an array containing the keys.
 * @param prefix pointer to the prefix.
 * @param localAS the callers local AS number.
 * 
 * @return API_VALRESULT_ERROR (-1( for error (a NULL value for path or prefix),
 *         API_VALRESULT_INVALID (0) for missing keys, or API_VALRESULT_VALID (1)
 */
int validate(BgpsecPathAttr* bgpsec_path, u_int16_t number_keys,
             BGPSecKey** keys, void *prefix, u_int32_t localAS )
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'validate'\n");
  int retVal = (bgpsec_path == NULL) ?  API_VALRESULT_ERROR
               : (number_keys == 0) ?   API_VALRESULT_INVALID
                 : (keys == NULL) ?     API_VALRESULT_INVALID
                   : (prefix == NULL) ? API_VALRESULT_ERROR
                     : API_VALRESULT_VALID;
  
  return retVal;
}

  /**
   * Perform BGPSEC path validation. (Optional) This function uses the list of 
   * registered public keys and returns the validation state or -1 for an error. 
   * The caller manages the memory and MUST assure the memory is intact until 
   * the function returns. The implementation itself DOES NOT modify the given 
   * data.
   * 
   * @param bgpsec_path pointer to the BGPSEC path attribute.
   * @param prefix pointer to the prefix.
   * @param localAS the callers local AS number.
   * @param extCode contains more information in case the validation value is 
   *                invalid. 0: validation failed, 1: key not found.
   * 
   * @return -1 for error (a NULL value) or 1 for valid
   */
int extValidate(BgpsecPathAttr* bgpsec_path, void *prefix, u_int32_t localAS, 
                u_int8_t* extCode)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'extValidate'\n");  
  int retVal = (bgpsec_path == NULL) ? API_VALRESULT_ERROR
               : (prefix == NULL) ?    API_VALRESULT_ERROR
                 : API_VALRESULT_VALID;
  
  return retVal;
}
             
             
/**
 * Sign the given BGPSEC path data with the provided key. This implementation 
 * does not sign the path.
 * 
 * @param bgpsec_data The BGPSEc data to be signed.
 * @param key The key to be used for signing
 * 
 * @return API_FAILURE (0) for failure
 */
int sign_with_key(BGPSecSignData* bgpsec_data, BGPSecKey* key)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'sign_with_key'\n");
  
  return API_FAILURE;    
}

/**
 * 
 * Wrapper for sign the given BGPSEC path data with the provided key. This 
 * implementation does not sign the path.
 * 
 * @param bgpsec_data The data to be signed.
 * @param keyID The id of the key
 * 
 * @return API_FAILURE (0) for failure
 */
int sign_with_id(BGPSecSignData* bgpsec_data, u_int8_t keyID)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'sign_with_id'\n");
  
  return API_FAILURE;
}

/**
 * Register the private key. This method does not store the key. the return 
 * value is 0
 * 
 * @param key The key to be stored
 * 
 * @return API_FAILURE (0) for failure
 */
u_int8_t registerPrivateKey(BGPSecKey* key)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'registerPrivateKey'\n");
  
  return API_FAILURE;
}

/**
 * Unregister the key. This method actually does not register unregister the 
 * key. It returns 0
 * 
 * @param keyID The key id to unregister.
 * 
 * @return API_FAILURE (0) for failure
 */
u_int8_t unregisterPrivateKey(u_int8_t keyID)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'unregisterPrivateKey'\n");
  
  return API_FAILURE;
}

/**
 * Register the public key. (Optional)
 * In case the API provides public key management the keys can be 
 * pre-registered. This will allow to call the verification without the need
 * to determine the public keys. The API will get the key information itself.
 * NOTE: The key information MUST be copied within the API. 
 * 
 * @param key The key itself. 
 * 
 * @return API_FAILURE (0) for failure
 */
u_int8_t registerPublicKey(BGPSecKey* key)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'registerPublicKey'\n");
  
  return API_FAILURE;  
}

/**
 * Remove the registered key with the same ski and asn. (Optional)
 * This method allows to remove a particular key that is registered for the 
 * given SKI and ASN.
 * 
 * @param key The key itself. 
 * 
 * @return API_FAILURE (0) for failure
 */
int unregisterPublicKey(BGPSecKey* key)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'unregisterPublicKey'\n");
  
  return API_FAILURE;    
}

/**
 * This method determines if the API provides the extended public key 
 * management. In this case the extended validation method extValidate can be 
 * called.
 * 
 * @return 1: does provide extended functionality
 */
int isExtended()
{
  // Return 1 for "yes, it is extended"
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'isExtended'\n");
  return YES;
}

/**
 * Return 1 if this API allows the storage of private keys, otherwise 0.
 * 
 * @return 0: Does not provide private key storage
 */  
int isPrivateKeyStorage()
{
  // Return 1 for "yes, it is extended"
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'isPrivateKeyStroage'\n");
  return NO;
}

/**
 * Return 1 if this API allows the storage of private keys, otherwise 0.
 * 
 * @return 0: Does not provide private key storage
 */  
int isPublicKeyStorage()
{
  // Return 1 for "yes, it is extended"
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'isPublicKeyStroage'\n");
  return NO;
}


/**
 * Just print the given configuration string to logging framework using INFO 
 * level.
 * 
 * @param value some string
 * 
 * @return 1: Successfull 
 */
int init(const char* value)
{
  if (value != NULL)
  {
    sca_debugLog(LOG_INFO, "Called init('%s')\n", value);
  }
  else
  {
    sca_debugLog(LOG_INFO, "Called init(null)\n"); 
  }
  return 1;  
}
