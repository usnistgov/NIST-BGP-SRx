#include <syslog.h>
#include <stddef.h>
#include "../srxcryptoapi.h"

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
 * @return -1 for error (a NULL value) or 1 for valid
 */
int validate(BgpsecPathAttr* bgpsec_path, u_int16_t number_keys,
             BGPSecKey** keys, void *prefix, u_int32_t localAS )
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'validate'\n");
  int retVal = (bgpsec_path == NULL) ? -1
               : (number_keys == 0) ? -1
                 : (keys == NULL) ? -1
                   : (prefix == NULL) ? -1
                     : 1;
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
  int retVal = (bgpsec_path == NULL) ? -1
               : (prefix == NULL) ? -1
                 : 1;
  return retVal;
}
             
             
/**
 * Sign the given BGPSEC path data with the provided key. This implementation 
 * does not sign the path.
 * 
 * @param bgpsec_data The BGPSEc data to be signed.
 * @param key The key to be used for signing
 * 
 * @return 1 for success, 0 for failure
 */
int sign_with_key(BGPSecSignData* bgpsec_data, BGPSecKey* key)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'sign_with_key'\n");
  return 0;    
}

/**
 * 
 * Wrapper for sign the given BGPSEC path data with the provided key. This 
 * implementation does not sign the path.
 * 
 * @param dataLength The length of the data to be signed.
 * @param data The data to be signed.
 * @param keyID The id of the key
 * @param sigLen The length og the preallocated signature buffer
 * @param signature The pre-allocated buffer used to store the signature in.
 * 
 * @return 0 failure, 1 success
 */
int sign_with_id(u_int16_t dataLength, u_int8_t* data, u_int8_t keyID,
                 u_int16_t sigLen, u_int8_t* signature)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'sign_with_id'\n");
  return 0;
}

/**
 * Register the private key. This method does not store the key. the return 
 * value is 0
 * 
 * @param key The key to be stored
 * 
 * @return 0
 */
u_int8_t registerPrivateKey(BGPSecKey* key)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'registerPrivateKey'\n");
  return 0;
}

/**
 * Unregister the key. This method actually does not register unregister the 
 * key. It returns 0
 * 
 * @param keyID The key id to unregister.
 * 
 * @return 0
 */
u_int8_t unregisterPrivateKey(u_int8_t keyID)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'unregisterPrivateKey'\n");
  return 0;
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
 * @return 0: failure, 1: success
 */
u_int8_t registerPublicKey(BGPSecKey* key)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'registerPublicKey'\n");
  return 0;  
}

/**
 * Remove the registered key with the same ski and asn. (Optional)
 * This method allows to remove a particular key that is registered for the 
 * given SKI and ASN.
 * 
 * @param key The key itself. 
 * 
 * @return 0: failure, 1: success
 */
int unregisterPublicKey(BGPSecKey* key)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'unregisterPublicKey'\n");
  return 0;    
}

/**
 * This method determines if the API provides the extended public key 
 * management. In this case the extended validation method extValidate can be 
 * called.
 * 
 * @return 0: Does NOT provide the extended method. 1: does provide extended
 *         functionality
 */
int isExtended()
{
  // Return 1 for "yes, it is extended"
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'isExtended'\n");
  return 1;
}

/**
 * Return 1 if this API allows the storage of private keys, otherwise 0.
 * 
 * @return 0: Does not provide private key storage, 1: Does provide key 
 *         private storage
 */  
int isPrivateKeyStorage()
{
  // Return 1 for "yes, it is extended"
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'isPrivateKeyStroageExten"
                           "ded'\n");
  return 1;
}
