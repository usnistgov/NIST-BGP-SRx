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
 * In addition this API allows to load keys stored on the file system. The
 * public key must be embedded in a DER formated X509 certificate and the
 * private key must be in DER format. This project contains OpennSSL scripts
 * that do generate the key files in the required form. See the tool sub
 * directory for more information.
 *
 * @Version 0.2.0.1
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.0.1 - 2016/07/02 - oborchert
 *            * Added missing hash generation for origin announcements.
 *  0.2.0.0 - 2016/06/27 - oborchert
 *            * Fixed endless loop in sca_generateHashMessage
 *            * modified sca_generateHashMessage to allow pre-generated hash 
 *              message. in this case return SUCCESS and set status ti INFO_USER1 
 *          - 2016/06/09 - oborchert
 *            * Added debug level functionality.
 *            * Removed use_init. Init is required from now on.
 *          - 2016/05/27 - 2016/06/08 - oborchert
 *            * Complete overhaul of the API
 *            * Added status flag to most methods.
 *  0.1.2.2 - 2016/04/23 - oborchert
 *            * Added draft 15 hash generation.
 *          - 2016/03/22 - oborchert
 *            * modified memory management in functions sca_generateMSG1 and
 *              sca_generateMSG2 by using realloc in lieu of malloc when 
 *              modifying the provided buffer (buff) to prevent a memory leak.
 *          - 2016/03/09 - oborchert
 *            * added NULL check to srxCryptoUnbind
 *  0.1.2.1 - 2016/02/03 - oborchert
 *            * Fixed BUG in mapping printout (BZ836)
 *            * Fixed bug in misinterpretation of init value.
 *          - 2016/02/01 - oborchert
 *            * added init method
 *  0.1.2.0 - 2016/01/13 - oborchert
 *            * added some more inline documentation 
 *          - 2015/12/03 - oborchert
 *            * moved srxcryptoapi.h into srx folder
 *          - 2015/11/03 - oborchert
 *            * Removed ski and algoID from struct BGPSecSignData, both data
 *              fields are part of the BGPSecKey structure. (BZ795)
 *            * modified function signature of sign_with_id (BZ788)
 *          - 2015/10/13 - oborchert
 *            * Fixed invalid method srxCryptoUnbind - previous interface did
 *              not ask for api object.
 *            * Modified srxCrytpoInit to only return failure if binding of
 *              the library failed.
 *          - 2015/09/22 - oborchert
 *            * added functions:
 *              > sca_getCurrentLogLevel
 *              > sca_SetDER_Ext - For private key
 *              > sca_SetX90_ext - For public key
 *            * Removed term_debug
 *            * Restructured initialization code and moved configuration and
 *              mapping into their respective methods.
 *            * Added configuration for key file extensions.
 *          - 2015/09/22 - oborchert
 *            * Added ChangeLog to file.
 *            * Return 0 for srxCryptoInit method when API is NULL.
 *            * Removed BIO_snprintf
 */
#include <syslog.h>
#include <libconfig.h>
#include <dlfcn.h>
#include <string.h>
#include <stdbool.h>
#include <malloc.h>
#include <netinet/in.h>
#include <openssl/bio.h>

#include "srx/srxcryptoapi.h"
#include "crypto_imple.h"

#ifndef LIBCFG_INT
#define LIBCFG_INT int
#endif

#define MAX_CMD_LEN                1024
#define MAX_EXT_SIZE               10
#define MAX_FUNC_NAME              512

#define CRYPTO_CFG_FILE            "srxcryptoapi.conf"

#define SCA_KEY_VOLT               "key_volt"
#define SCA_KEY_EXT_PRIV           "key_ext_private"
#define SCA_KEY_EXT_PUB            "key_ext_public"
#define SCA_LIBRARY_NAME           "library_name"
#define SCA_LIBRARY_CONF           "library_conf"

#define DEF_KEY_EXT_PRIV           "der"
#define DEF_KEY_EXT_PUB            "cert"

#define SCA_INIT_VALUE             "init_value"
#define SCA_INIT                   "method_init"
#define SCA_RELEASE                "method_release"

#define SCA_FREE_HASH_MESSAGE      "method_freeHashMessage"
#define SCA_FREE_SIGNATURE         "method_freeSignature"

#define SCA_GET_DEBUGLEVEL         "method_getDebugLevel"
#define SCA_SET_DEBUGLEVEL         "method_setDebugLevel"

#define SCA_SIGN                   "method_sign"
#define SCA_VALIDATE               "method_validate"

#define SCA_REGISTER_PRIVATE_KEY   "method_registerPrivateKey"
#define SCA_UNREGISTER_PRIVATE_KEY "method_unregisterPrivateKey"

#define SCA_REGISTER_PUBLIC_KEY    "method_registerPublicKey"
#define SCA_UNREGISTER_PUBLIC_KEY  "method_unregisterPublicKey"

#define SCA_DEF_INIT                   "init"
#define SCA_DEF_RELEASE                "release"

#define SCA_DEF_FREE_HASH_MESSAGE      "freeHashMessage"
#define SCA_DEF_FREE_SIGNATURE         "freeSignature"

#define SCA_DEF_GET_DEBUGLEVEL         "getDebugLevel"
#define SCA_DEF_SET_DEBUGLEVEL         "setDebugLevel"

#define SCA_DEF_SIGN                   "sign"
#define SCA_DEF_VALIDATE               "validate"

#define SCA_DEF_REGISTER_PRIVATE_KEY   "registerPrivateKey"
#define SCA_DEF_UNREGISTER_PRIVATE_KEY "unregisterPrivateKey"

#define SCA_DEF_REGISTER_PUBLIC_KEY    "registerPublicKey"
#define SCA_DEF_UNREGISTER_PUBLIC_KEY  "unregisterPublicKey"

#ifndef SYSCONFDIR
#define SYSCONFDIR               "/etc"
#endif // SYSCONFDIR

#define SYS_CFG_FILE SYSCONFDIR "/" CRYPTO_CFG_FILE
#define LOC_CFG_FILE "./" CRYPTO_CFG_FILE

typedef struct {
  const char* str_library_name;

  const char* str_init_val;  
  const char* str_method_init;
  const char* str_method_release;
  
  const char* str_method_freeHashMessage;
  const char* str_method_freeSignature;

  const char* str_method_getDebugLevel;
  const char* str_method_setDebugLevel;
  
  const char* str_method_sign;
  const char* str_method_validate;

  const char* str_method_registerPrivateKey;
  const char* str_method_unregisterPrivateKey;
  
  const char* str_method_registerPublicKey;
  const char* str_method_unregisterPublicKey;
} SCA_Mappings;

// Hash struct for first signature in path
typedef struct {
  u_int32_t targetAS;
  u_int32_t originAS;
  u_int8_t  pCount;
  u_int8_t  flags;
  u_int8_t  algoID;
  u_int16_t afi;
  u_int8_t  safi;
  // Now NLRI
  u_int8_t  pLen;
  // followed by pLen bits padded to the next full octet.
} __attribute__((packed)) TplHash1;

// Hash struct for consecutive signature in path
typedef struct {
  u_int32_t targetAS;
  u_int32_t signerAS;
  u_int8_t  pCount;
  u_int8_t  flags;
  // previous signature will follow
} __attribute__((packed)) TplHash2;


#if HAVE_LTDL_H
#include <ltdl.h>
int ltdl;
lt_dlhandle module;
/* libltdl is now patched, following preload symbols lines are no longer needed */
#ifdef USE_PRELOAD_SYMBOL
#ifndef lt__PROGRAM__LTX_preloaded_symbols
#define lt_preloaded_symbols    lt_libltdl_LTX_preloaded_symbols
extern LT_DLSYM_CONST lt_dlsymlist lt_libltdl_LTX_preloaded_symbols[];
#endif
#endif
#endif

/* Default logging information will be changed once configuration is loaded. */
static int g_loglevel = LOG_INFO;
/* Contains the path information to the key volt. */
static char _keyPath [MAXPATHLEN];
/* The file extension for DER encoded private key. */
static char _key_ext_priv[MAX_EXT_SIZE];
/* The file extension for X509 certificates containing the public key. */
static char _key_ext_pub[MAX_EXT_SIZE];

// Default function implementation.
/**
 * This is the internal 'init' wrapper function. Currently it does return only 
 * the error code nd provides a debug log.
 * 
 * @param value The initialization value.
 * @param debugLevel the debugging level - Follows the system debug levels.
 * @param status Will contain the status information of this call.
 * 
 * @return API_FILURE (0)
 */
int wrap_init(const char* value, int debugLevel, sca_status_t* status)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "Called local test wrapper 'init'\n");
  return API_FAILURE;  
}

/**
 * This will be called prior un-binding the library. This allows the API 
 * implementation to perform a clean shutdown / cleanup.
 * 
 * @return API_FAILURE (0)
 */
int wrap_release()
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "Called local test wrapper 'release'\n");
  return API_FAILURE;    
}

/**
  * In case the validation method does return the generated hashMessage, this
  * function is used to free the allocated memory.
  * 
  * @param hashMessage The generated hash input data, must be generated by the 
  *                    API mapped library and retrieved using the validate 
  *                    call.
 * 
 *  @return false
  */
bool wrap_freeHashMessage(SCA_HashMessage* hashMessage)
{
  sca_debugLog (LOG_DEBUG, "Called local test wrapper 'freeHashMessage'\n");
  
  return false;
}

  /**
   * Signatures are generated by the API and also freed by the API module.
   * 
   * @param signature The signature element.
   * 
   * @return false
   */
  bool wrap_freeSignature(SCA_Signature* signature)
  {
    sca_debugLog (LOG_DEBUG, "Called local test wrapper 'freeSignature'\n");
    
    return false;
  }
  
  /**
   * Return the current debug level of -1 if not supported
   * 
   * @return -1 (not supported)
   */
  int wrap_getDebugLevel()
  {
    sca_debugLog (LOG_DEBUG, "Called local test wrapper 'getDebugLevel'\n");
    return -1;
  }

  /**
   * Set the new debug level going forward. This methid returns the previous set 
   * debug level or -1 if not supported.
   * 
   * @param debugLevel The debug level to be set - Follows system debug values.
   * 
   * @return -1 (not supported)
   */
  int wrap_setDebugLevel(int debugLevel)
  {
    sca_debugLog (LOG_DEBUG, "Called local test wrapper 'setDebugLevel'\n");
    return -1;    
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
   * @return API_VALRESULT_INVALID (1) and the status 
   *         flag contains further information - including errors.
   *         
   */
int wrap_validate(SCA_BGPSecValidationData* data)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "Called local test wrapper 'validate'\n");
  if (data != NULL)
  {
    data->status = API_STATUS_INFO_KEY_NOTFOUND
                   | API_STATUS_ERR_INVLID_KEY            
                   | API_STATUS_ERR_KEY_IO
                   | API_STATUS_ERR_INSUF_BUFFER
                   | API_STATUS_ERR_NO_PREFIX;    
  }  
  return API_VALRESULT_INVALID;
}

/**
 * This is the internal wrapper function. Currently it does return only the
 * error code and provides a debug log.
 *
 * @param bgpsec_path The BGPSEC Path Segment
 * @param number_keys The number of keys provided
 * @param keys The array of keys
 * @param prefix pointer to the prefix.
 * @param localAS the callers local AS number.
 *
 * @return API_VALRESULT_INVALID -> status = API_STATUS_ERR_USER1
 */
int wrap_sign(SCA_BGPSecSignData* data)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "Called local test wrapper 'sign'\n");
  if (data != NULL)
  {
    data->status = API_STATUS_INFO_KEY_NOTFOUND
                   | API_STATUS_ERR_INVLID_KEY            
                   | API_STATUS_ERR_KEY_IO;
  }
  return API_FAILURE;
}

/**
 * Register the private key. This method does not store the key. the return
 * value is 0
 *
 * @param key The key to be stored
 * @param status Will contain the status information of this call.
 *
 * @return API_FAILURE - check status
 */
u_int8_t wrap_registerPrivateKey(BGPSecKey* key, sca_status_t* status)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "Called local test wrapper 'registerPrivateKey'\n");
  if (status != NULL)
  {
    *status =   API_STATUS_ERR_INSUF_KEYSTORAGE 
              | API_STATUS_ERR_INVLID_KEY 
              | API_STATUS_ERR_KEY_IO;
  }

  return API_FAILURE;
}

/**
 * Unregister the Private key. This method actually does not register unregister
 * the private key. It returns 0
 *
 * @param key The key needs at least contain the ASN and SKI.
 * @param status Will contain the status information of this call.
 *
 * @return API_FAILURE - check status
 */
u_int8_t wrap_unregisterPrivateKey(BGPSecKey* key, sca_status_t* status)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "Called local test wrapper "
                           "'unregisterPrivateKey'\n");
  if (status != NULL)
  {
    *status =  API_STATUS_ERR_KEY_IO
              | API_STATUS_INFO_KEY_NOTFOUND;
  }

  return API_FAILURE;
}

/**
 * Register the public key. This method does not store the key. the return
 * value is 0
 *
 * @param key The key to be stored
 * @param status Will contain the status information of this call.
 *
 * @return API_FAILURE - check status
 */
u_int8_t wrap_registerPublicKey(BGPSecKey* key, sca_status_t* status)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "Called local test wrapper 'registerPublicKey'\n");
  if (status != NULL)
  {
    *status =   API_STATUS_ERR_INSUF_KEYSTORAGE 
              | API_STATUS_ERR_INVLID_KEY 
              | API_STATUS_ERR_KEY_IO;
  }

  return API_FAILURE;
}

/**
 * Unregister the Private key. This method actually does not register unregister
 * the private key. It returns 0
 *
 * @param keyID The key id to unregister.
 * @param status Will contain the status information of this call.
 *
 * @return API_FAILURE - check status
 */
u_int8_t wrap_unregisterPublicKey(BGPSecKey* key, sca_status_t* status)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "Called local test wrapper 'unregisterPublicKey'\n");
  
  if (status != NULL)
  {
    // Just set all errors
    *status =   API_STATUS_INFO_KEY_NOTFOUND
              | API_STATUS_ERR_KEY_IO;
  }

  return API_FAILURE;
}

/**
 * Look if the configuration file is specified and if not, attempt to load the
 * default one in the system configuration folder or the current folder.
 *
 * @param api The SRxCryptoAPI object.
 *
 * @return 0 if no configuration file is specified and no file is found.
 */
static int _checkConfigFile(SRxCryptoAPI* api)
{
  int retVal = API_FAILURE;

  // 1st check if file is provided in api
  if (api->configFile != NULL)
  {
    sca_debugLog(LOG_INFO, "Use custom crypto configuration located in %s\n",
                           api->configFile);
    retVal = API_SUCCESS;
  }
  else
  {
    FILE* file;
    // Find configuration file.
    //1. Check for system configuration
    file = fopen(SYS_CFG_FILE , "r");
    if (file != NULL)
    {
      // System configuration exist
      api->configFile = SYS_CFG_FILE;
      fclose(file);
      retVal = API_SUCCESS;
      sca_debugLog(LOG_INFO, "Use crypto configuration located in %s\n",
                            SYS_CFG_FILE);
    }
    else
    {
      //2. Check for local configuration
      file = fopen(LOC_CFG_FILE, "r");
      if (file != NULL)
      {
        fclose(file);
        retVal = API_SUCCESS;
        api->configFile = LOC_CFG_FILE;
        sca_debugLog(LOG_INFO, "Use crypto configuration located in %s\n",
                               LOC_CFG_FILE);
      }
    }
  }

  return retVal;
}

/**
 * Load the general configuration setting that is independent of the library
 * that will be mapped.
 *
 * @param cfg The configuration object
 * @param status The status information if errors happened.
 *
 * @return true if all went well otherwise look into status.
 */
static void _loadGeneralConfiguration(config_t* cfg, sca_status_t* status)
{
    /* debug level */
  LIBCFG_INT newLogLevel = (LIBCFG_INT)g_loglevel;
  if(config_lookup_int(cfg, "debug-type", (LIBCFG_INT*)&newLogLevel))
  {
    sca_debugLog(LOG_INFO, "- debug type: %d\n", newLogLevel);
    g_loglevel = newLogLevel;
  }
  else
  {
    sca_debugLog(LOG_INFO, "- debug type: not configured! use value %d \n",
                           g_loglevel);
  }

  // Set the default key location if configured.
  const char* key_volt;
  if (config_lookup_string(cfg, SCA_KEY_VOLT, &key_volt))
  {
    sca_SetKeyPath((char *)key_volt);
    void* file = fopen(key_volt , "r");
    if (!file)
    {
      sca_debugLog(LOG_WARNING, "%s - Invalid directory \"%s\"\n",
                   SCA_KEY_VOLT, key_volt);
    }
    else
    {
      fclose(file);
      sca_debugLog(LOG_INFO, "- %s=\"%s\"\n", SCA_KEY_VOLT, key_volt);
    }
  }

  // Set the default extension for private key.
  const char* ext_priv;
  if (config_lookup_string(cfg, SCA_KEY_EXT_PRIV, &ext_priv))
  {
    sca_setDER_ext((char *)ext_priv);
  }
  sca_debugLog(LOG_INFO, "- %s=\"%s\"\n", SCA_KEY_EXT_PRIV, _key_ext_priv);

  // Set the default extension for public key (x509 cert)
  const char* ext_pub;
  if (config_lookup_string(cfg, SCA_KEY_EXT_PUB, &ext_pub))
  {
    sca_setX509_ext((char *)ext_pub);
  }
  sca_debugLog(LOG_INFO, "- %s=\"%s\"\n", SCA_KEY_EXT_PUB, _key_ext_pub);
}

#define WARNING_MSG "mapping information in configuration file!"
/**
 * Try to load the requested configuration entry and handle all debug output.
 *
 * @param set The configuration section
 * @param key The key of the configuration object
 * @param mapStr The string to fill
 */
static void __readMapping(config_setting_t *set, const char* key,
                          const char** mapStr)
{
  if (!config_setting_lookup_string(set, key, mapStr))
  {
    sca_debugLog(LOG_WARNING, "- '%s' MISSING %s\n", key, WARNING_MSG);
  }
  else
  {
    sca_debugLog(LOG_INFO, "- %s=\"%s\"\n", key, *mapStr);
  }
}

/**
 * Load all configuration setting for the given library.
 *
 * @param set The configuration section
 * @param mappings The mapping strings.
 */
static void _loadMapping(config_setting_t *set, SCA_Mappings* mappings)
{
  //////////////////////////////////////////////////////////////////////////////
  // LIBRARY NAME
  //////////////////////////////////////////////////////////////////////////////
  __readMapping(set, SCA_LIBRARY_NAME, &mappings->str_library_name);
  
  //////////////////////////////////////////////////////////////////////////////
  // LOAD INIT VALUES and INIT / DESTROY FUNCTIONS
  //////////////////////////////////////////////////////////////////////////////  
  __readMapping(set, SCA_INIT_VALUE, &mappings->str_init_val);  
  
  __readMapping(set, SCA_INIT, &mappings->str_method_init);
  __readMapping(set, SCA_RELEASE, &mappings->str_method_release);
  
  __readMapping(set, SCA_FREE_HASH_MESSAGE, 
                     &mappings->str_method_freeHashMessage);
  __readMapping(set, SCA_FREE_SIGNATURE, 
                     &mappings->str_method_freeSignature);

  //////////////////////////////////////////////////////////////////////////////
  // LOAD DEBUG FUNCTIONS
  //////////////////////////////////////////////////////////////////////////////  
  __readMapping(set, SCA_GET_DEBUGLEVEL, 
                     &mappings->str_method_getDebugLevel);
  __readMapping(set, SCA_SET_DEBUGLEVEL, 
                     &mappings->str_method_setDebugLevel);
  
  
  //////////////////////////////////////////////////////////////////////////////
  // SIGN / VALIDATE FUNCTIONS
  //////////////////////////////////////////////////////////////////////////////
  __readMapping(set, SCA_SIGN, &mappings->str_method_sign);
  __readMapping(set, SCA_VALIDATE, &mappings->str_method_validate);
  
  
  //////////////////////////////////////////////////////////////////////////////
  // PRIVATE KEY STORAGE
  //////////////////////////////////////////////////////////////////////////////
  __readMapping(set, SCA_REGISTER_PRIVATE_KEY,
                     &mappings->str_method_registerPrivateKey);
  __readMapping(set, SCA_UNREGISTER_PRIVATE_KEY,
                     &mappings->str_method_unregisterPrivateKey);

  //////////////////////////////////////////////////////////////////////////////
  // EXTENDED - validation and public key storage
  //////////////////////////////////////////////////////////////////////////////
  __readMapping(set, SCA_REGISTER_PUBLIC_KEY,
                     &mappings->str_method_registerPublicKey);
  __readMapping(set, SCA_UNREGISTER_PUBLIC_KEY,
                     &mappings->str_method_unregisterPublicKey);
}

/**
 * Perform the mapping into the library or to the wrapper implementation. The
 * first attempt is to mapp the configured function, if this fails then the
 * default function name is tested. If nothing works, no mapping will be
 * performed.
 *
 * @param apiFkt The api function that has to be mapped
 * @param cfgName The configured library name to map to
 * @param defName The default name to map to
 *
 */
static void __doMapFunction(void* libHandle, void** apiFkt, const char* cfgName,
                            const char* defName)
{
  void* loaded = NULL;
  bool  loadDefault = true;
  char* error = NULL;
  // clear any existing errors.
  dlerror();
#if HAVE_LTDL_H
  lt_dlhandle libModule = (lt_dlhandle)libHandle;
#endif

  // Try to mapp the configured name
  if (cfgName != NULL)
  {
    sca_debugLog(LOG_INFO, "Linking \"%s\" to \"%s\"!\n",
                 defName, cfgName);
#if HAVE_LTDL_H
    loaded = lt_dlsym(libModule, cfgName);
    error = (char*)lt_dlerror();
#else
    loaded = dlsym(libHandle, cfgName);
    error = dlerror();
#endif
    loadDefault = error != NULL;
    if (loadDefault)
    {
      sca_debugLog(LOG_ERR, "- Could not link \"%s\" to api method \"%s\"!\n", 
                               defName, cfgName);      
    }
  }
  if (loadDefault)
  {
    // Try the default method name
    sca_debugLog(LOG_INFO, "Linking \"%s\" to default method!\n", defName);
#if HAVE_LTDL_H
    loaded = lt_dlsym(libModule, defName);
    error = (char*)lt_dlerror();
#else
    loaded = dlsym(libHandle, defName);
    error = dlerror();
#endif
    if (error != NULL)
    {
      loaded = *apiFkt;
      sca_debugLog(LOG_WARNING, "Linking error (%s) for function \"%s\""
                                " - use internal wrapper!\n",
                   error, defName);
    }
  }

  *apiFkt = loaded;
}

/**
 * Do the final mapping of the plugin. The first attempt is to mapp to the
 * method configured in srxcrytpoapi.conf. If this does not work, try to map
 * towards the default name, if this does not work, map to the wrapper.
 *
 * @param mappings The mappings read from the configuration
 * @param api the api to map in
 *
 * @return int API_FAILURE (0) for failure API_SUCCESS (1) for success.
 */
static int _mapAPI(SCA_Mappings* mappings, SRxCryptoAPI* api)
{
  int retVal = API_SUCCESS;
  char* error = NULL;

#if HAVE_LTDL_H
  module = lt_dlopen(mappings->str_library_name);
  if(module != 0)
  {
    api->libHandle = (void*)module;
  }
  error = (char*)lt_dlerror();
#else
  // Map the library
  api->libHandle = dlopen(mappings->str_library_name, RTLD_LOCAL | RTLD_LAZY);
  error = dlerror();
#endif
  if (api->libHandle == NULL)
  {
    sca_debugLog(LOG_ERR, "Library %s could not be opened (%s)!\n",
                 mappings->str_library_name, error);
    retVal = API_FAILURE;
  }
  else
  {
    __doMapFunction(api->libHandle, (void**)&api->init,
                    mappings->str_method_init, SCA_DEF_INIT);
    __doMapFunction(api->libHandle, (void**)&api->release,
                    mappings->str_method_release, SCA_DEF_RELEASE);

    __doMapFunction(api->libHandle, (void**)&api->freeHashMessage,
                    mappings->str_method_freeHashMessage, 
                    SCA_DEF_FREE_HASH_MESSAGE);    

    __doMapFunction(api->libHandle, (void**)&api->freeSignature,
                    mappings->str_method_freeSignature, 
                    SCA_DEF_FREE_SIGNATURE);    

    
    __doMapFunction(api->libHandle, (void**)&api->sign,
                    mappings->str_method_sign, SCA_DEF_SIGN);
    __doMapFunction(api->libHandle, (void**)&api->validate,
                    mappings->str_method_validate, SCA_DEF_VALIDATE);
    
    __doMapFunction(api->libHandle, (void**)&api->registerPublicKey,
                    mappings->str_method_registerPublicKey,
                    SCA_DEF_REGISTER_PUBLIC_KEY);
    __doMapFunction(api->libHandle, (void**)&api->unregisterPublicKey,
                    mappings->str_method_unregisterPublicKey,
                    SCA_DEF_UNREGISTER_PUBLIC_KEY);

    __doMapFunction(api->libHandle, (void**)&api->registerPrivateKey,
                    mappings->str_method_registerPrivateKey,
                    SCA_DEF_REGISTER_PRIVATE_KEY);
    __doMapFunction(api->libHandle, (void**)&api->unregisterPrivateKey,
                    mappings->str_method_unregisterPrivateKey,
                    SCA_DEF_UNREGISTER_PRIVATE_KEY);
  }

  return retVal;
}

/**
 * Initialize the crypto API by reading the crypto configuration and linking the
 * implementation library to the crypto pi object. The configuration is located
 * in the system config folder or the current "./" folder. In case another
 * location is requested the attribute api->configFile must be set.
 *
 * The initialization fails only if a library is specified and cannot be bound
 * or bindings of methods fail. In case no configuration is found the default
 * mapping will be performed.
 *
 * @param api the crypto api container - MUST NOT BE NULL
 * @param the status variable containing information about failures etc.
 *
 * @return int API_SUCCESS(1) or API_FAILURE(0 - see status) 
 */
int srxCryptoInit(SRxCryptoAPI* api, sca_status_t* status)
{
  int               retVal           = API_FAILURE;
  SCA_Mappings*     mappings         = NULL;
  config_setting_t* set              = NULL;
  bool              useLocal         = false;
  const char*       str_library_conf = NULL;
  static config_t   cfg;
  memset (&cfg, 0, sizeof(config_t));

  if (api == NULL)
  {
    sca_debugLog(LOG_ERR, "API instance NULL.\n");
    return retVal;
  }

  if (api->libHandle != NULL)
  {
    sca_debugLog(LOG_ERR, "API already initialized.\n");
    return retVal;
  }

#ifdef MEM_CHECK
  mallopt(M_CHECK_ACTION, 3);
  sca_debugLog(LOG_INFO, "CryptoAPI activated M_CHECK_ACTION 3. To disable, "
                        "reconfigure without --enable-mcheck and recompile.\n");
#endif

#if HAVE_LTDL_H
  LTDL_SET_PRELOADED_SYMBOLS();
  ltdl = lt_dlinit();
#endif

  // First initialize the api and set the pointers to null.
  api->libHandle            = NULL;
  // The following debug information will be printed regardless of the 
  // debug code specified in the configuration file. 
  sca_debugLog(LOG_INFO, "Preset local wrapper for all methods!\n");

  // Just set default wrapper mappings
  api->init                 = wrap_init;
  api->release              = wrap_release;
  
  api->freeHashMessage      = wrap_freeHashMessage;
  api->freeSignature        = wrap_freeSignature;
  
  api->sign                 = wrap_sign;
  api->validate             = wrap_validate;

  api->registerPublicKey    = wrap_registerPublicKey;
  api->unregisterPublicKey  = wrap_unregisterPublicKey;

  api->registerPrivateKey   = wrap_registerPrivateKey;
  api->unregisterPrivateKey = wrap_unregisterPrivateKey;

  // Now initialize mapping names
  mappings = malloc(sizeof(SCA_Mappings));
  memset (mappings, 0, sizeof(SCA_Mappings));

  // Read Configuration script
  sca_setDER_ext(DEF_KEY_EXT_PRIV);
  sca_setX509_ext(DEF_KEY_EXT_PUB);

  if (!_checkConfigFile(api))
  {
    sca_debugLog(LOG_WARNING, "No configuration File specified, "
                              "use default local settings\n");
    useLocal = true;
  }
  else // Load the Configuration.
  {
    config_init(&cfg);
    // The following debug information will be printed regardless of the 
    // debug code specified in the configuration file. 
    sca_debugLog(LOG_INFO, "Use configuration file \"%s\"\n", api->configFile);

    if (config_read_file(&cfg, api->configFile))
    {
////////////////////////////////////////////////////////////////////////////////
// DEFAULT CONFIGURATION
////////////////////////////////////////////////////////////////////////////////
      _loadGeneralConfiguration(&cfg, status);

////////////////////////////////////////////////////////////////////////////////
// LIBRAQRY MAPPING INFORAMTION
////////////////////////////////////////////////////////////////////////////////
      // Load the mapping information.
      if (config_lookup_string(&cfg, SCA_LIBRARY_CONF, &str_library_conf))
      {
        set = config_lookup(&cfg, str_library_conf);
        // The configuration requires all parameters to be available, even if
        // the implementation is missing.
        if (set != NULL)
        {
          // load the mapping information for the plugin - They are read from
          // the srxcrytpoapi.conf
          _loadMapping(set, mappings);

          // Do the final mapping of the API functions into the plugin.
          retVal = _mapAPI(mappings, api);
          if (retVal != API_FAILURE)
          {
            // Do the library initialization if specified
            const char* initVal = NULL;
            if (mappings->str_init_val != NULL)
            {
              if (strcmp(mappings->str_init_val, "NULL") != 0)
              {
                initVal = mappings->str_init_val;
              }
            }
            
            // initialize API
            sca_debugLog(LOG_INFO, 
                         "Initiate library initialization using '%s'\n",
                         initVal);
            retVal = api->init(initVal, sca_getCurrentLogLevel(), status);
            if (retVal == API_FAILURE)
            {
              sca_status_t releaseStatus = API_STATUS_OK;
              api->release(&releaseStatus);
              sca_debugLog(LOG_ERR, "Initialization failed (0x%X, 0x%X)!\n", 
                           status, releaseStatus);
            }
          }
          else
          {
            sca_debugLog(LOG_ERR, "API could not be linked!\n");
          }
        }
      }
      else
      {
        sca_debugLog(LOG_WARNING, "%s - Parameter library_conf is missing, use "
                                  "local mapping!\n", api->configFile);
        useLocal = true;
      }
    }
    else
    {
      sca_debugLog(LOG_ERR, "%s:%d - %s\n", api->configFile,
                   cfg.error_line, cfg.error_text);
    }

    // Free configuration structure
    config_destroy(&cfg);
  }

  if (retVal != API_SUCCESS)
  {
    if (!useLocal)
    {
      sca_debugLog(LOG_ERR, "Library could not be loaded!\n");
      // Just in case the failure occurred not only during the beginning,
      srxCryptoUnbind(api, status);
    }
    else
    {
      sca_debugLog(LOG_WARNING, "No library specified, use local mapping!\n");
      retVal = API_SUCCESS;
      //Don't do unbind here, unbind also removes local mappings.
    }
  }

  memset (mappings, 0, sizeof(SCA_Mappings));
  free(mappings);
  mappings = NULL;

  return retVal;
}

/**
 * close the linked library, sets all api settings to NULL / 0
 *
 * @param api Unbind the SRxCryptoAPI
 * @param status the status in case an error occured.
 *
 * @return API_SUCCESS(1) or API_FAILURE(0 - see status)
 */
int srxCryptoUnbind(SRxCryptoAPI* api, sca_status_t* status)
{
  sca_status_t myStatus = API_STATUS_OK;
  
  if (api != NULL)
  {
    if (api->libHandle != NULL)
    {
      api->release(&myStatus);
      
      // free errors from library
#if HAVE_LTDL_H
      lt_dlerror();

      if (ltdl == 0)
      {
        if (api->libHandle != 0)
        {
          lt_dlclose(api->libHandle);
        }
        lt_dlexit();
      }
      module = 0;
#else
      dlerror();
      if (dlclose(api->libHandle) != 0)
      {
        sca_debugLog(LOG_WARNING, "Unbinding of SRxCryptoAPI plugin seems to have"
                                  " caused some issues!");
      }
#endif
    }

    // NULL the complete API
    memset (api, 0, sizeof(SRxCryptoAPI));
  }
  else
  {
    myStatus |= API_STATUS_ERR_NO_DATA;
  }
  
  if (status != NULL)
  {
    *status = myStatus;
  }

  return ((myStatus & API_STATUS_ERROR_MASK) == 0) ? API_SUCCESS: API_FAILURE;
}

////////////////////////////////////////////////////////////////////////////////
// Helper Functions
////////////////////////////////////////////////////////////////////////////////

/**
 * This function sets the key path.
 *
 * @param key_path the path to the keys (\0 terminated).
 *
 * @return API_SUCCESS(1) or API_FAILURE(0)
 *
 */
int sca_SetKeyPath (char* key_path)
{
  int retVal = API_FAILURE;

  if (strlen(key_path) < (MAX_CMD_LEN-1))
  {
    memset(_keyPath, '\0', MAXPATHLEN);
    sprintf(_keyPath, "%s%c", key_path, '\0');
    retVal = API_SUCCESS;
  }

  return retVal;
}

/**
 * Set the file extension for DER encoded private key.
 *
 * @param key_ext The file extension
 *
 * @return 0 error, 1 success
 *
 * @since 0.1.2.0
 */
int sca_setDER_ext (char* key_ext)
{
  return snprintf(_key_ext_priv, MAX_EXT_SIZE, "%s", key_ext) < 0
                  ? API_FAILURE : API_SUCCESS;
}

/**
 * Set the file extension for the DER encoded x509 certificate containing the
 * public key.
 *
 * @param x509_ext The file extension
 *
 * @return 0 error, 1 success
 *
 * @since 0.1.2.0
 */
int sca_setX509_ext (char* x509_ext)
{
  return snprintf(_key_ext_pub, MAX_EXT_SIZE, "%s", x509_ext) < 0
                  ? API_FAILURE : API_SUCCESS;
}

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
char* sca_FindDirInSKI (char* filenamebuf, size_t filenamebufLen, u_int8_t* ski)
{
  char *path = _keyPath;
  char skiHex[SKI_HEX_LENGTH+1];
  char* skiPtr = skiHex;
  int idx;

  // Transform the ski into a hex string
  for (idx = 0; idx < SKI_LENGTH; idx++)
  {
    skiPtr += sprintf(skiPtr, "%02X", ski[idx]);
  }

  filenamebuf[filenamebufLen-1] = '\0';

  snprintf(filenamebuf, filenamebufLen-1, "%s/%2.2s/%4.4s/%s",
           path,
           skiHex, skiHex + 2, skiHex + 6);

  return filenamebuf;
}


/**
 * Writes the loging information.
 *
 * @param level The logging level
 * @param format The format of the logging info
 * @param ...
 */
void sca_debugLog( int level, const char *format, ...)
{
  char buffer[0xff] = {0};
  char *slevel;

  va_list ap;

  if( level <= g_loglevel )
  {
    va_start(ap, format);
    vsnprintf( buffer, 0xff, format, ap);
    va_end(ap);

    switch (level)
    {
      case LOG_DEBUG    : slevel = "DEBUG"; break;
      case LOG_WARNING  : slevel = "WARNING"; break;
      case LOG_INFO     : slevel = "INFO"; break;
      case LOG_ERR      : slevel = "ERROR"; break;
      default: slevel = "??";
    }
    fprintf(stdout, "[SRxCryptoAPI - %s] %s", slevel, buffer);
    //vsyslog((int)level, format, ap);
  }
}

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
int sca_loadKey(BGPSecKey* key, bool fPrivate, sca_status_t* status)
{
  if (_key_ext_priv[0] == '\0')
  {
    sca_debugLog(LOG_INFO, "Extension for private key not set. Set "
            "'%s' as key-file extension!\n", DEF_KEY_EXT_PRIV);
    sca_setDER_ext(DEF_KEY_EXT_PRIV);
  }
  if (_key_ext_pub[0] == '\0')
  {
    sca_debugLog(LOG_INFO, "Extension for public key (X509 cert) not set. Set "
            "'%s' as cert-file extension!\n", DEF_KEY_EXT_PUB);
    sca_setX509_ext(DEF_KEY_EXT_PUB);
  }

  int retVal =  impl_loadKey(key, fPrivate, fPrivate ? _key_ext_priv 
                                                     : _key_ext_pub);
  if (retVal == API_LOADKEY_FAILURE)
  {
    retVal = API_FAILURE;
    if (status != NULL)
    {
      *status |= API_STATUS_ERR_KEY_IO | API_STATUS_INFO_KEY_NOTFOUND;
    }
  }
  else
  {
    retVal = API_SUCCESS;
  }
  return retVal;
}

/**
 * Return the configured log level.
 *
 * @return the logLevel configured.
 *
 * @since 0.1.2.0
 */
long sca_getCurrentLogLevel()
{
  return g_loglevel;
}

////////////////////////////////////////////////////////////////////////////////
// DRAFT 15 
////////////////////////////////////////////////////////////////////////////////

/**
 * Generate the message digest from the given data.
 * It will return API_STATUS_ERR_USER2 if the signature block cannot be found in
 * the BGPSec Path Attribute data
 * 
 * The following status settings are returned:
 * 
 * API_STATUS_ERR_USER1: The given data is corrupt.
 * API_STATUS_ERR_USER2: No matching signature block could be found.
 * API_STATUS_ERR_NO_DATA: Data of some kind is missing.
 * 
 * API_STATUS_INFO_USER1: A Hash message already exist (not NULL) so we
 *                        do not generate a new one.
 * 
 * The optimizer breaks this function therefore the optimization level is hard 
 * coded down to -O0
 * 
 * @param data Contains the BGPSec Path attribute as it is on the wire and all 
 *             the required information.
 * @param algoID Look for the signatures of the given algorithm suite id
 * @param status The status flag in case of 0 return value
 * 
 * @return the number of bytes used in the internal buffer or 0.
 */
#pragma GCC push_options
#ifndef FORCE_OPTIMIZING
#pragma GCC optimize ("O0")
#endif
int sca_generateHashMessage(SCA_BGPSecValidationData* data, u_int8_t algoID, 
                            sca_status_t* status)
{
  // @TODO: Revisit once data can have multiple hashMessage blocks. Then 
  // it gets a bit more complicated. For now we use the HM_BLOCK and assume
  // we only have one block. Remove the BLOCK_0/BLOCK_1 define once the 2 block
  // handling is properly added.
#define BLOCK_0 0
#define BLOCK_1 1
  
  sca_status_t myStatus = API_STATUS_OK;
  
  // Some initial check
  if (data != NULL)
  {
    // we accept the given hash Message and stop. 
    if (data->hashMessage[BLOCK_0] != NULL) // Interestingly -02 removes this line only and removed check.
    {
      myStatus = API_STATUS_INFO_USER1; // info will be set in -O2 GCC 4.8.5 even though if data-digest != NULL
    }
    if (data->bgpsec_path_attr == NULL)
    {
      myStatus = API_STATUS_ERR_NO_DATA;         
    }
  }
  else
  {
    myStatus = API_STATUS_ERR_NO_DATA;    
  }
  
  if (myStatus != API_STATUS_OK)
  {
    if (status != NULL)
    {
      *status = myStatus;
    }
    // Return valid if a hash message already existed. (some speedup)
    return ((myStatus & API_STATUS_ERROR_MASK) == 0) ? API_VALRESULT_VALID
                                                     : API_VALRESULT_INVALID;
  }
  
  // Now set the pointers to the path segment and signature segments.
  u_int8_t* bgpsecPathAttr = data->bgpsec_path_attr;
  // Cast it to the BGPSEC Path Attribute to easily access the data and move the 
  // pointer to the path segment portion of the data
  SCA_BGPSEC_PathAttribute* bgpsecAttrHdr = 
                                      (SCA_BGPSEC_PathAttribute*)bgpsecPathAttr;
  bgpsecPathAttr += LEN_BGPSECPATHATTR_HDR;
  // Contains the length of SecurePath and all Signature blocks.
  u_int16_t remainder = ntohs(bgpsecAttrHdr->attrLength);
  
  // Cast it to the Secure Path header element and move it to the first secure 
  // Path segments
  SCA_BGPSEC_SecurePath* secPathHdr = (SCA_BGPSEC_SecurePath*)bgpsecPathAttr;
  // Get the length in bytes. (div by 6 equals segment count))  
  const u_int16_t secPathLen = ntohs(secPathHdr->length);
  
  // @TODO: Add management of second block - in case two signature blocks are 
  //        available - here a loop would be the correct approach.
  data->hashMessage[BLOCK_0] = malloc(sizeof(SCA_HashMessage));
  data->hashMessage[BLOCK_1] = NULL;
  memset (data->hashMessage[BLOCK_0], 0, sizeof(SCA_HashMessage));
  data->hashMessage[BLOCK_0]->segmentCount = secPathLen / LEN_SECPATHSEGMENT;

  // Now Move it over the SecurePath Header and position it at the secure path
  // segment.
  bgpsecPathAttr += LEN_SECPATH_HDR;
  remainder      -= LEN_SECPATH_HDR;  
  
  // Cast it to the first secure path segment and move the pointer to the 
  // Signature block. (secPath->length includes the length field size which we 
  // already moved out pointer by. subtract this size from the length and move
  // to the signature block. 
  SCA_BGPSEC_SecurePathSegment* pSeg = 
                                  (SCA_BGPSEC_SecurePathSegment*)bgpsecPathAttr;
  bgpsecPathAttr += (secPathLen - LEN_SECPATH_HDR);
  // Adjust the remainder
  remainder -= (secPathLen - LEN_SECPATH_HDR);
  
  // Now find the correct signature block
  SCA_BGPSEC_SignatureBlock*   sBlock = NULL;
  SCA_BGPSEC_SignatureSegment* sigSeg = NULL;
  u_int16_t blockLength = 0;
  while (remainder != 0)
  {
    sBlock = (SCA_BGPSEC_SignatureBlock*)bgpsecPathAttr;
    blockLength = ntohs(sBlock->length);
    if ((blockLength > remainder) || (blockLength == 0 && remainder != 0))
    {
      // Bugfix in case the given data is corrupted it might end up in an 
      // endless loop or segmentation fault by reading over the allocated 
      // memory
      myStatus = API_STATUS_ERR_USER1;
      free (data->hashMessage[BLOCK_0]);
      data->hashMessage[BLOCK_0] = NULL;
      
      sBlock   = NULL;
      break;
    }
    remainder -= blockLength;
    if (sBlock->algoID != algoID)
    {
      // Move to the next block
      bgpsecPathAttr += blockLength;
      sBlock = NULL;
      continue;
    }
    sigSeg = (SCA_BGPSEC_SignatureSegment*)(bgpsecPathAttr + LEN_SIGBLOCK_HDR);
    // nothing more necessary!
    break;
  }
  
  // Now pointers are placed, generate the digest.
  
  int used = 0;
  int size = 0;
  if (sBlock != NULL)
  {
    // Now prepare the prefix information
    u_int8_t  prefixBLen = (u_int8_t)((data->nlri->length + 7) / 8);

    // Now we have all major pointers in place, calculate the required size and 
    // see if the buffer fits:
    int segments = data->hashMessage[BLOCK_0]->segmentCount;
    
    
    // +---------------------------+
    // | target AS   (4 octets)    | <- For signing to next peer
    // +---------------------------+
    // | Signature Segment N       | <- Signature coming to MyAS sig[0]
    // +---------------------------+
    // | Path Segment (myAS)       |
    // |   pCount    (1 octet) = 0 | <- set myAS pCount for signing to peer
    // |   flags     (1 octet) = 0 | <- set MyAS flags for signing to peer
    // |   MyAS      (4 octets)    | <- Start digest degest[0]
    // +---------------------------+
    // | Signature Segment N-1     | <- Signature sig[1] - signed over digest[1]
    // +---------------------------+
    // | Path Segment (N)          |
    // |   pCount    (1 octet)     |
    // |   flags     (1 octet)     |
    // |   asn       (4 octets)    | <- Start digest degest[1]
    // +---------------------------+
    // ...
    // +---------------------------+
    // | Signature Segment N-1     | <- Signature sig[Origin] 
    // +---------------------------+
    // | Path Segment (2)          |
    // |   pCount    (1 octet)     |
    // |   flags     (1 octet)     |
    // |   asn       (4 octets)    |  <- Start digest [Origin]
    // +---------------------------+
    // | Path Segment (1)          |
    // +---------------------------+
    // | algoID, NLRI              |
    // +---------------------------+
    

    size = 4 //s Target AS               
           + ((segments + 1) * LEN_SECPATHSEGMENT) // always one segment more in the path
           + (blockLength - LEN_SIGBLOCK_HDR)   // only the signature segments
           + 1 + 4 + prefixBLen; // 1 for AlgoID, 2, for AFI, 1 for SAFI,
                                 // 1 for pLength, compressed prefix in bytes

    // Now create the digest buffer
    data->hashMessage[BLOCK_0]->buffer     = malloc(size);
    data->hashMessage[BLOCK_0]->bufferSize = size;    

    // Now prepare the digest and signature pointers into the buffer
    data->hashMessage[BLOCK_0]->hashMessageValPtr = malloc(sizeof(u_int8_t*) * segments);
    memset (data->hashMessage[BLOCK_0]->hashMessageValPtr, 0, (sizeof(u_int8_t*)*segments));

    // Now the buffer pointer we walk through  
    u_int8_t* buffPtr = data->hashMessage[BLOCK_0]->buffer;
    // initialize the buffer
    memset (buffPtr, 0, size);

    // Skip the first 4 bytes (placeholder for the target AS)
    buffPtr += 4;    
    used    += 4;

    int segment = 0;
    //set pointer to first signature N
    u_int8_t* sigPtr  = (u_int8_t*)sigSeg;
    //set pointer to fist path segment N
    u_int8_t* pathPtr = (u_int8_t*)pSeg;

    // Only needed to easily read the length field
    SCA_BGPSEC_SignatureSegment*  sPtr = NULL;

    int dataLength = 0;

    //now add the segments and signatures, etc.  
    for (; segment < segments; segment++)
    {
      sPtr = (SCA_BGPSEC_SignatureSegment*)sigPtr; 
      // Determine the size of the signature segment
      dataLength = LEN_SIGSEGMENT_HDR + ntohs(sPtr->siglen);
      
      // Create the digest pointers
      data->hashMessage[BLOCK_0]->hashMessageValPtr[segment] = malloc(sizeof(SCA_HashMessagePtr));
      //Copy the complete signature segment into the buffer
      memcpy(buffPtr, sigPtr, dataLength);
      // Set the signature pointer to the signature within the buffer
      data->hashMessage[BLOCK_0]->hashMessageValPtr[segment]->signaturePtr = buffPtr;
      // Move to next signature
      sigPtr  +=  dataLength;
      
      // Move  buffer to the next position (secure Path element)
      buffPtr += dataLength;
      // Mark this data as used data. 
      used    += dataLength;

      // Now add the path segment
      if (segment != 0) // a regular path segment incl. flags and pcount
      {
        memcpy(buffPtr, pathPtr, 6);
        // Move to ASN as start for digest
        buffPtr += 2; 
        used    += 2;
        // Now set the digest pointer into the buffer N
        data->hashMessage[BLOCK_0]->hashMessageValPtr[segment]->hashMessagePtr = buffPtr;
        // Now specify the remaining length of the digest
        data->hashMessage[BLOCK_0]->hashMessageValPtr[segment]->hashMessageLength = 
                                                                    size - used;
        
        // Now move to next signature (or origin path segment)
        buffPtr += 4; 
        pathPtr += 6;
        used    += 4;
      }
      else
      {
        // This is the my AS (target AS of peer - skip flags and pcount.)
        buffPtr += 2;
        used    += 2;
        // Now store myAS in the buffer
        u_int32_t* asn = (u_int32_t*)buffPtr;
        *asn = data->myAS;
        // Now set the digest pointer
        data->hashMessage[BLOCK_0]->hashMessageValPtr[segment]->hashMessagePtr = buffPtr;
        // Set the length of the digest
        data->hashMessage[BLOCK_0]->hashMessageValPtr[segment]->hashMessageLength = 
                                                                      size-used;
        
        buffPtr += 4;
        used    += 4;
      }  
    }
    // Now add the origin path segment
    
    memcpy(buffPtr, pathPtr, 6);
    buffPtr += 6;
    used    += 6;

    // Now add the algoID
    *buffPtr = algoID;
    buffPtr++;
    used++;

    // Copy prefix:
    memcpy(buffPtr, data->nlri, prefixBLen+4);
    used += prefixBLen + 4;
  }
  else
  {
    myStatus = API_STATUS_ERR_USER1;
    used = 0;
    if (data->hashMessage[BLOCK_0] != NULL)
    {
      sca_freeHashInput(data->hashMessage[BLOCK_0]);
      data->hashMessage[BLOCK_0] = NULL;
    }
  }
  
  if (status != NULL)
  {
    *status = myStatus;
  }
  return used;
}

/**
 * This function generates the Hash for a prefix origination - This is used
 * for signing.
 * 
 * @param targetAS The target AS (network format)
 * @param spSeg The Secure Path segment of the origin (all network format)
 * @param nlri The NLRI information
 * @param algoID The algorithm site identifier.
 * 
 * @return Return the hash message.
 */
SCA_HashMessage* sca_gnenerateOriginHashMessage(u_int32_t targetAS, 
                                            SCA_BGPSEC_SecurePathSegment* spSeg, 
                                            SCA_Prefix* nlri, u_int8_t algoID)
{
    //Now set the completeNLRI information
    int nlriLen = ((nlri->length + 7) / 8) + 4; // afi(2), safi(1), len(1)
    
    // Now its up to us to generate the hash message.
    int bLen =   4                  // targetAS
               + LEN_SECPATHSEGMENT // Originator Path Segment
               + 1                  // algoID
               + nlriLen;           // all the prefix info (afi, safi, len, ip)
    SCA_HashMessage* hashMsg = malloc(sizeof(SCA_HashMessage));
    hashMsg->ownedByAPI   = true;
    hashMsg->segmentCount = 1;
    hashMsg->bufferSize = bLen;
    hashMsg->buffer = malloc(bLen);
    memset(hashMsg->buffer, 0, bLen);
    hashMsg->hashMessageValPtr = malloc(sizeof(SCA_HashMessagePtr*));
    hashMsg->hashMessageValPtr[0] = malloc(sizeof(SCA_HashMessagePtr));
    hashMsg->hashMessageValPtr[0]->signaturePtr      = NULL;
    hashMsg->hashMessageValPtr[0]->hashMessagePtr    = hashMsg->buffer;
    hashMsg->hashMessageValPtr[0]->hashMessageLength = bLen;
    // We don't need to set the peer as or flags or pCount. That will be done 
    // in sign.
    // We can immediately skipp the first 6 bytes and write directly the
    // origin as followed by the bottom info (algoID, AFI, SAFI, NLRI)
    u_int8_t* ptr = hashMsg->buffer;
    
    // Set the target AS:
    u_int32_t* asn = (u_int32_t*)ptr;
    *asn = targetAS;
    ptr += 4;
    
    // Now set the origin
    memcpy(ptr, spSeg, LEN_SECPATHSEGMENT);
    ptr += LEN_SECPATHSEGMENT;
    
    // Now set the algoID
    *ptr = algoID;
    ptr++;
    
    memcpy (ptr, nlri, nlriLen);
    
    return hashMsg;
}
#pragma GCC pop_options    

/**
 * This function will free the copmlete digest structure if NOT owned by the 
 * API.
 * 
 * @param data The validation data that contain the validation digest that
 *             has to be deleted.
 * 
 * @return true if the hash input could be released.
 */
bool sca_freeHashInput(SCA_HashMessage* data)
{
  if (data != NULL)
  {
    if (data->ownedByAPI)
    {
      return false;
    }
    
    if (data->hashMessageValPtr != NULL)
    {
      int idx = 0;
      for (idx = 0; idx < data->segmentCount; idx++)
      {
        free(data->hashMessageValPtr[idx]);
        data->hashMessageValPtr[idx] = NULL;
      }
      free (data->hashMessageValPtr);
      data->hashMessageValPtr = NULL;
      data->segmentCount = 0;
    }
    if (data->buffer != NULL)
    {
      memset(data->buffer, 0, data->bufferSize);
      free(data->buffer);
      data->buffer     = NULL;
      data->bufferSize = 0;
    }
    free(data);
  }
  
  return true;
}

/**
 * Return the algorithm ID used for this hashMEssage
 * 
 * @param hashMessage The hash Message.
 * 
 * @return The algorithm ID for this hash Message or 0 if none can be found.
 * 
 * @since 0.2.0.0
 */
u_int8_t sca_getAlgorithmID(SCA_HashMessage* hashMessage)
{
  u_int8_t algoID = 0;
  
  if (hashMessage != NULL)
  {
    SCA_HashMessagePtr* hmPtr = hashMessage->hashMessageValPtr[hashMessage->segmentCount-1];
    if (hmPtr != NULL)
    {
      if (hmPtr->hashMessageLength >= 11)
      {
        // This is the last hash message pointer. It points to the origination 
        // and the data of the origination has the following format:
        //
        // +--------------------------------------+ Address - offset
        // |  Target AS   (4 octets)              | 00 - 03
        // |  pCount      (1 octet  - originator) | 04 - 04
        // |  flags       (1 octet  - originator) | 05 - 05
        // |  ASN         (4 octets - originator) | 06 - 10
        // |  AlgorithmID (1 octet)               | 11 - 11
        // | ...
        algoID =  *(hmPtr->hashMessagePtr + 11);
      }
    }
  }
  
  return algoID;
}


/**
 * Print the status information in human readable format
 * 
 * @param status the status variable to be printed
 * 
 * @since 0.2.0.0
 */
void sca_printStatus(sca_status_t status)
{     
  if ((status & API_STATUS_INFO_MASK) > 0)
  {
    char* IS  = (status & API_STATUS_INFO_SIGNATURE) > 0 
                ? "|1+--API_STATUS_INFO_SIGNATURE"
                : " 0 ";
    char* IKN = (status & API_STATUS_INFO_KEY_NOTFOUND) > 0 
                ? "|1+-----API_STATUS_INFO_KEY_NOTFOUND"
                : " 0 ";
    char* IU1 = (status & API_STATUS_INFO_USER1) > 0 
                ? "|1+---------------API_STATUS_INFO_USER1"
                : " 0 ";
    char* IU2 = (status & API_STATUS_INFO_USER2) > 0 
                ? "|1+-----------------API_STATUS_INFO_USER_2"
                : " 0 ";
    
    printf ("INFO:  0x%04X\n", status & API_STATUS_INFO_MASK);
    printf ("       8 4 2 1 8 4 2 1\n");
    printf ("       %c %c - - - - %c %c\n", IU2[1], IU1[1], IKN[1], IS[1]);
    printf ("       %c %c         %c %c\n", IU2[0], IU1[0], IKN[0], IS[0]);
    
    if ((status & API_STATUS_INFO_SIGNATURE) > 0)
      printf ("       %c %c         %c %s\n", *IU2, *IU1, *IKN, &IS[2]);//0x0001
    if ((status & API_STATUS_INFO_KEY_NOTFOUND) > 0)
      printf ("       %c %c         %s\n", *IU2, *IU1, &IKN[2]);      //  0x0002
    if ((status & API_STATUS_INFO_USER1) > 0)
      printf ("       %c %s\n", *IU2, &IU1[2]);                       //  0x0040
    if ((status & API_STATUS_INFO_USER2) > 0)
      printf ("       %s\n", &IU2[2]);                                //  0x0080
  }
  else if ((status & API_STATUS_ERROR_MASK) > 0)
  {
    char* END = (status & API_STATUS_ERR_NO_DATA) > 0 
                ? "|1+--API_STATUS_ERR_NO_DATA"                         // 0x0100
                : " 0 ";
    char* ENP = (status & API_STATUS_ERR_NO_PREFIX) > 0                // 0x0200
                ? "|1+----API_STATUS_ERR_NO_DATA"
                : " 0 ";
    char* EIK = (status & API_STATUS_ERR_INVLID_KEY) > 0               // 0x0400
                ? "|1+------API_STATUS_ERR_INVALID_KEY"
                : " 0 ";
    char* EKI = (status & API_STATUS_ERR_KEY_IO) > 0                   // 0x0800
                ? "|1+--------API_STATUS_ERR_KEY_IO"
                : " 0 ";
    char* EIB = (status & API_STATUS_ERR_INSUF_BUFFER) > 0             // 0x1000
                ? "|1+----------API_STATUS_ERR_INSUF_BUFFER"
                : " 0 ";
    char* EIS = (status & API_STATUS_ERR_INSUF_KEYSTORAGE) > 0         // 0x2000
                ? "|1+------------API_STATUS_ERR_INSUF_KEYSTORAGE"
                : " 0 ";
    char* EU1 = (status & API_STATUS_ERR_USER1) > 0                    // 0x4000
                ? "|1+------------API_STATUS_ERR_USER1"
                : " 0 ";
    char* EU2 = (status & API_STATUS_ERR_USER2) > 0                    // 0x8000
                ? "|1+------------API_STATUS_ERR_USER2"
                : " 0 ";
    
    printf ("ERROR: 0x%04X\n", status & API_STATUS_ERROR_MASK);
    printf ("       8 4 2 1 8 4 2 1\n");
    printf ("       %c %c %c %c %c %c %c %c\n", EU2[1], EU1[1], EIS[1], EIB[1], 
                                                EKI[1], EIK[1], ENP[1], END[1]);
    printf ("       %c %c %c %c %c %c %c %c\n", EU2[0], EU1[0], EIS[0], EIB[0], 
                                                EKI[0], EIK[0], ENP[0], END[0]);
    
    if ((status & API_STATUS_ERR_NO_DATA) > 0)
      printf ("       %c %c %c %c %c %c %c %s\n", *EU2, *EU1, *EIS, *EIB, *EKI, 
                                                   *EIK, *ENP, &END[2]);
    if ((status & API_STATUS_ERR_NO_PREFIX) > 0)
      printf ("       %c %c %c %c %c %c %s\n", *EU2, *EU1, *EIS, *EIB, *EKI, 
                                               *EIK, &ENP[2]);
    if ((status & API_STATUS_ERR_INVLID_KEY) > 0)
      printf ("       %c %c %c %c %c %s\n", *EU2, *EU1, *EIS, *EIB, *EKI, 
                                            &EIK[2]);
    if ((status & API_STATUS_ERR_KEY_IO) > 0)
      printf ("       %c %c %c %c %s\n", *EU2, *EU1, *EIS, *EIB, &EKI[2]);
    if ((status & API_STATUS_ERR_INSUF_BUFFER) > 0)
      printf ("       %c %c %c %s\n", *EU2, *EU1, *EIS, &EIB[2]);
    if ((status & API_STATUS_ERR_INSUF_KEYSTORAGE) > 0)
      printf ("       %c %c %s\n", *EU2, *EU1, &EIS[2]);
    if ((status & API_STATUS_ERR_USER1) > 0)
      printf ("       %c %s\n", *EU2, &EU1[2]);
    if ((status & API_STATUS_ERR_USER2) > 0)
      printf ("       %s\n", &EU2[2]);
  }
  if (status == API_STATUS_OK)
  {
    printf ("STATUS: OK\n");    
  }
}
