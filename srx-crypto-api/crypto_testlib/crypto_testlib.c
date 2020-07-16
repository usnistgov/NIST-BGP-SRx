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
 * This software provides a test implementation for a BGPsec plug-in. This
 * plug-in does provide mostly empty functions except validation allows to be 
 * configured for parsing the BGPsec path attribute only. Also it can be 
 * configured with a default validation result as well as print found 
 * signatures.
 * 
 * @version 0.3.0.0
 *
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *   0.3.0.0 - 2017/09/12 - oborchert
 *             * Added missing mappings to function comptest and added compiler 
 *               function attribute unused.
 *             * Fixed return value in sign method.
 *           - 2017/08/15 - oborchert
 *             * Assess function compAPI that maps each method to a temp
 *               SRxCryptoAPI object to assure correct implementation. 
 *               (Or the compiler throws an error).
 *             * Updated all API functions to the latest version.
 *   0.2.0.2 - 2016/11/16 - oborchert
 *             * Added some functionalities to this test module.
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
#include <malloc.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "../srx/srxcryptoapi.h"

#define CT_STRING_LEN 255

#define CT_PARAM_VAL_RESULT     0
#define CT_PARAM_PARSE_BGPSEC   1
#define CT_PARAM_PRINTSIGNATURE 2

/** Specify the validation result. true = valid, false = invalid*/
static bool ct_validationResult  = true;
/** Specify id the given bgpsec path attribute will be processed. */
static bool ct_doParseBGPSecAttr = false;
/** If bgpsec path attribute is processed, indicae if SKI and signatures are to 
 * be printed.*/
static bool ct_printSignatures   = true;

bool freeSignature(SCA_Signature* signature);

/**
 * Print the data in hex format. This method prints at least one '\n'.
 * 
 * @param data The data to be printed
 * @param length The length of the data buffer
 * @param tab The tab to be used for each new line.
 */
static void _printHex(u_int8_t* data, int length, char* tab)
{
  bool printCR = length <= 0;
  int idx = 1;
  
  if (tab == NULL)
  {
    tab = "\0";
  }
  
  for (; idx <= length; idx++)
  {
    printf("%02X ", *data);
    printCR = true;
    if ((idx % 16) == 0)
    {
      printf ("\n");
      if (idx+1 < length)
      {
        printf ("%s", tab);
      }
      printCR = false;
    }
    else if ((idx % 8) == 0)
    {
      printf("  ");
    }

    data++;
  }
  
  if (printCR)
  {
    printf("\n");
  }
}

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
  int retVal = ct_validationResult ? API_VALRESULT_VALID 
                                   : API_VALRESULT_INVALID;
  bool generatedHashMessage = false;
  
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
        
    if (ct_doParseBGPSecAttr && (status & API_STATUS_ERROR_MASK) == 0)
    {
      // Now depending on the configuration we do some more work.
      // Generate the hash if none was generated prior.
      if (data->hashMessage[0] == NULL)
      {
        if (sca_generateHashMessage(data, SCA_ECDSA_ALGORITHM, 
                                    (sca_status_t*)&status) > 0)
        {
          // Now reset the values to allow the validation to be performed.
          status = API_STATUS_OK;
          retVal = API_SUCCESS;
          generatedHashMessage = true;
        }
        else
        {
          status = API_STATUS_ERR_USER1;
          retVal = API_VALRESULT_INVALID; 
        }
      }
      else
      {
        status = API_STATUS_OK;
        retVal = API_VALRESULT_VALID;
      }
      
      if (ct_printSignatures)
      {
        printf ("\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/"
                "\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\n");
        if (status == API_STATUS_OK)
        {
          // Now print signatures and ski's
          int idx = 0;
          SCA_HashMessage* hashMessage = data->hashMessage[0];
          int segments = hashMessage->segmentCount;
          for (idx = 0; idx < segments; idx++)
          {
            printf ("Segment %i:\n", idx);
            SCA_HashMessagePtr** hashMessageValPtr = hashMessage->hashMessageValPtr;

            u_int8_t* ptr = hashMessageValPtr[idx]->signaturePtr;
            SCA_BGPSEC_SignatureSegment* sigSeg = (SCA_BGPSEC_SignatureSegment*)ptr;
            ptr += sizeof(SCA_BGPSEC_SignatureSegment);
            printf ("  SKI:       ");
            _printHex(sigSeg->ski, SKI_LENGTH, "             ");
            printf ("  Signature: ");
            _printHex(ptr, ntohs(sigSeg->siglen), "             ");
          }
          
          hashMessage = NULL;
          
          if (generatedHashMessage)
          {
            sca_freeHashInput(data->hashMessage[0]);
            data->hashMessage[0] = NULL;
          }
        }
        printf ("/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\"        
                "/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\\n\n");
      }      
    }
    
    data->status = status;
    
  }  
  
  return (status == API_STATUS_OK) ? ct_validationResult 
                                   : API_VALRESULT_INVALID;
}

/**
 * Sign the given BGPSecSign data using the given key. This method fills the
 * key into the BGPSecSignData object.
 *
 * API_STATUS_ERR_USER1: In case one of the signatures is already generated and
 *                       NOT owned by the API.
 * 
 * @param bgpsec_data The data object to be signed. This also includes the
 *                    generated signature.
 * @param ski The ski of the key to be used.
 *
 * @return API_FAILURE
 */
int sign(int count, SCA_BGPSecSignData** bgpsec_data)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'sign'\n");
  int idx    = 0;
  int retVal = API_SUCCESS;
  SCA_BGPSecSignData* data = NULL;
  
  for (; idx < count; idx++)
  {
    data = bgpsec_data[idx];
    data->status = API_STATUS_OK;
    if (data->algorithmID == SCA_ECDSA_ALGORITHM)
    {
      if (data->signature != NULL)
      {
        if (freeSignature(data->signature))
        {
          data->status |= API_STATUS_ERR_USER1;
          retVal = API_FAILURE;
          continue;
        }
      }
      data->signature = malloc(sizeof(SCA_Signature));
      data->signature->algoID     = SCA_ECDSA_ALGORITHM;
      data->signature->ownedByAPI = true;
      memcpy(data->signature->ski, data->ski, SKI_LENGTH);
      data->signature->sigBuff = malloc(70);
      memset(data->signature->sigBuff, 0xAA, 70);
      data->signature->sigLen = 70;
    }
    else
    {
      data->status = API_STATUS_ERR_UNSUPPPORTED_ALGO;
      retVal = API_FAILURE;
    }
  }
  return API_FAILURE;
}

/**
 * Register the private key. This method does not store the key. The return 
 * value is API_FAILURE.
 * 
 * @param key The key to be stored
 * @param source The source of the key
 * @param status The status of the key registration
 * 
 * @return API_FAILURE for failure (API_STATUS_ERR_USER1)
 */
u_int8_t registerPrivateKey(BGPSecKey* key, sca_status_t* status)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'registerPrivateKey'\n");
  
  if (status != NULL)
  {
    *status = API_STATUS_ERR_USER1;
  }
  
  return API_FAILURE;  
}

/**
 * Unregister the key. This method actually does not register unregister the 
 * key. The return value is API_SUCCESS.
 * 
 * @param asn The asn of the private key
 * @param ski The SKI of the private key (Length 20 bytes)
 * @param algoID The algorithm id of the private key
 * @param status The status of the key removal
 * 
 * @return API_SUCCESS
 */
u_int8_t unregisterPrivateKey(u_int32_t asn, u_int8_t* ski, u_int8_t algoID, 
                              sca_status_t* status)

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
 * @param source The source of the key
 * @param status The status of the key
 * 
 * @return API_FAILURE for failure (API_STATUS_ERR_USER1)
 */
u_int8_t registerPublicKey(BGPSecKey* key, sca_key_source_t source,
                           sca_status_t* status)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'registerPublicKey'\n");
  
  if (status != NULL)
  {
    *status = API_STATUS_ERR_USER1;
  }
  
  return API_FAILURE;  
}

/**
 * Remove the registered key with the same ski and asn. (Optional)
 * This method allows to remove a particular key that is registered for the 
 * given SKI and ASN.
 * 
 * @param key The key itself. 
 * @param source The source of the key
 * @param status The status of the key removal
 * 
 * @return API_FAILURE for failure (API_STATUS_ERR_USER1)
 */
u_int8_t unregisterPublicKey(BGPSecKey* key, sca_key_source_t source,
                                sca_status_t* status)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "CryptoTestLib: Called 'unregisterPublicKey'\n");
  
  if (status != NULL)
  {
    *status = API_STATUS_ERR_USER1;
  }
  
  return API_FAILURE;  
}

/**
 * Initialized this library. Currently the configuration allows 3 settings to 
 * be set in a sequential manner.
 * 
 * VAL_RESULT;PARSE_BGPSEC;PRINT_SIGNATURE with each value as 0=false or 1=true
 * 0;0;0 sets all to false, ;1;0 sets parse signature and don't print.
 * 
 * By default all values are false.
 * 
 * @param value Some string
 * @param debugLevel IGNORED
 * @param status The status information
 * 
 * @return API_SUCCESS
 */
int init(const char* value, int debugLevel, sca_status_t* status)
{
  if (value != NULL)
  {
//    sca_debugLog(LOG_INFO, "Called init('%s')\n", value);  
    int initStrLen = (value != NULL) ? strlen(value) : 0;
    char* ch = (char*)value;
    int param = 0;
    bool value  = false;
    bool setVal = false;
    
    while (initStrLen > 0)
    {
      initStrLen--;
      switch (*ch)
      {
        case '0':
          value = false;
          setVal = true;
          break;
        case '1':
          value  = true;
          setVal = true;
          break;
        case ';': 
        case ',': 
        case '-': 
          param++;
        default:
          setVal = false;
          break;        
      }
      ch++;
      
      if (setVal)
      {
        switch (param)
        {
          case CT_PARAM_VAL_RESULT:
            ct_validationResult = setVal;
            break;
          case CT_PARAM_PARSE_BGPSEC:
            ct_doParseBGPSecAttr = setVal;
            break;
          case CT_PARAM_PRINTSIGNATURE:
            ct_printSignatures = setVal;
            break;
          default:
            break;
        }
        setVal = false;
      }
    }
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
 * @return API_SUCCESS
 * 
 * @since 0.2.0.0
 */
int release()
{
  return API_SUCCESS;
}

/**
 * Allows to query if this plug-in supports the requested algorithm IDdd.
 * 
 * @param algoID The algorithm ID.
 * 
 * @return true if the algorithm ECDSA p256 (1).
 * 
 * @since 0.3.0.0
 */
bool isAlgorithmSupported(u_int8_t algoID)
{
  return algoID == SCA_ECDSA_ALGORITHM ? true : false;
}

/**
 * Remove all keys from the internal storage that were provided by the given
 * key source.
 * 
 * @param source The source of the keys.
 * @param status Will contain the status information of this call.
 * 
 * @return API_FAILURE (API_STATUS_ERR_USER1)
 * 
 * @since 0.3.0.0
 */
u_int8_t cleanKeys(sca_key_source_t source, sca_status_t* status)
{
  if (status != NULL)
  {
    *status = API_STATUS_ERR_USER1;
  }
  
  return API_FAILURE;
}

/**
 * Remove all private keys from the internal storage.
 * 
 * @param status Will contain the status information of this call.
 * 
 * @return API_FAILURE
 * 
 * @since 0.3.0.0
 */
u_int8_t cleanPrivateKeys(sca_status_t* status)
{
  if (status != NULL)
  {
    *status = API_STATUS_ERR_USER1;
  }
  
  return API_FAILURE;
}

/**
 * Return the actively used debug level
 *
 * @return the debug level used within the API
 * 
 * @since 0.3.0.0
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
 * 
 * @since 0.3.0.0
 */
int setDebugLevel(int debugLevel)
{
  return -1;
}

/**
 * In case the validation method does return the generated hashMessage, this
 * function is used to free the allocated memory.
 * 
 * This function is copies from bgpsec_openssl.c
 *
 * @param hashMessage The generated hash input data, must be generated by the
 *                    API mapped library and retrieved using the validate
 *                    call.
 *
 * @return false if the API is not the owner of the memory and cannot release
 *         the allocation, otherwise true
 * 
 * @since 0.3.0.0
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
 * This function is copied from btgpsec_openss;
 *
 * @param signature The signature element.
 *
 * @return false if the API is not the owner of the memory and cannot release
 *         the allocation, otherwise true
 * 
 * @since 0.3.0.0
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
