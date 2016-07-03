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
 * @version 0.2.0.0
 *
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *   0.2.0.0 - 2016/05/25 - oborchert
 *             * Updated to new API
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
#include <string.h>
#include "../srx/srxcryptoapi.h"

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
   * @return API_VALRESULT_VALID (1) or API_VALRESULT_VALID (0) and the status 
   *         flag contains further information - including errors.
   *         
   */
int validate(SCA_BGPSecValidationData* data)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'validate'\n");
  int status = (data != NULL) ? API_STATUS_OK : API_STATUS_ERR_NO_DATA;
  
  if ((status & API_STATUS_ERROR_MASK) == 0)
  {
    if (data->bgpsec_path_attr == NULL || data->hashMessage == NULL)
    {
      status |= API_STATUS_ERR_NO_DATA;
    }
    if (data->nlri == NULL)
    {
      status |= API_STATUS_ERR_NO_PREFIX;
    }
    
    data->status = status;
  }  
  
  return (status == API_STATUS_OK) ? API_VALRESULT_VALID : API_VALRESULT_INVALID;
}

/**
 * Sign the given BGPSecSign data using the given key. This method fills the
 * key into the BGPSecSignData object.
 *
 * @param bgpsec_data The data object to be signed. This also includes the
 *                    generated signature.
 * @param ski The ski of the key to be used.
 *
 * @return API_SUCCESS (0) or API_FAILURE (1)
 */
int sign(SCA_BGPSecSignData* bgpsec_data)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'validate'\n");
  int status = bgpsec_data != NULL ? API_STATUS_OK : API_STATUS_ERR_NO_DATA;
    
  return status == API_STATUS_OK ? API_VALRESULT_VALID : API_VALRESULT_INVALID;    
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
u_int8_t unregisterPrivateKey(char* ski)
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
 * Just print the given configuration string to logging framework using INFO 
 * level.
 * 
 * @param value some string
 * 
 * @return API_SUCCESS (1)
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
  return API_SUCCESS; 
}

  /**
   * This will be called prior un-binding the library. This allows the API 
   * implementation to perform a clean shutdown / cleanup.
   * 
   * @return API_SUCCESS(1)
   * 
   * @since 0.2.0.0
   */
  int release()
  {
    return API_SUCCESS;
  }

