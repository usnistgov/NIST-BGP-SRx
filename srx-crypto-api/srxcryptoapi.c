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
 * @Version 0.1.2.1
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *   0.1.2.1 - 2016/02/03 - oborchert
 *             * Fixed BUG in mapping printout (BZ836)
 *             * Fixed bug in misinterpretation of init value.
 *           - 2016/02/01 - oborchert
 *             * added init method
 *   0.1.2.0 - 2016/01/13 - oborchert
 *             * added some more inline documentation 
 *           - 2015/12/03 - oborchert
 *             * moved srxcryptoapi.h into srx folder
 *           - 2015/11/03 - oborchert
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
 *             * Restructured initialization code and moved configuration and
 *               mapping into their respective methods.
 *             * Added configuration for key file extensions.
 *           - 2015/09/22 - oborchert
 *             * Added ChangeLog to file.
 *             * Return 0 for srxCryptoInit method when API is NULL.
 *             * Removed BIO_snprintf
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

// Below might be removed again
#ifdef CPU_64
#define CT_INT long
#else
#define CT_INT int
#endif

#define MAX_CMD_LEN                1024
#define MAX_EXT_SIZE               10

#define CRYPTO_CFG_FILE            "srxcryptoapi.conf"

#define SCA_KEY_VOLT               "key_volt"
#define SCA_KEY_EXT_PRIV           "key_ext_private"
#define SCA_KEY_EXT_PUB            "key_ext_public"
#define SCA_LIBRARY_NAME           "library_name"
#define SCA_LIBRARY_CONF           "library_conf"

#define DEF_KEY_EXT_PRIV           "der"
#define DEF_KEY_EXT_PUB            "cert"

#define SCA_USE_INIT               "use_init"
#define SCA_INIT_VALUE             "init_value"

#define SCA_INIT                   "method_init"

#define SCA_SIGN_WITH_KEY          "method_sign_with_key"
#define SCA_SIGN_WITH_ID           "method_sign_with_id"
#define SCA_VALIDATE               "method_validate"

#define SCA_IS_EXTENDED            "method_isExtended"
#define SCA_EXT_VALIDATE           "method_extValidate"

#define SCA_IS_PRIVATE_KEY_STORAGE "method_isPrivateKeyStorage"
#define SCA_REGISTER_PRIVATE_KEY   "method_registerPrivateKey"
#define SCA_UNREGISTER_PRIVATE_KEY "method_unregisterPrivateKey"

#define SCA_REGISTER_PUBLIC_KEY    "method_registerPublicKey"
#define SCA_UNREGISTER_PUBLIC_KEY  "method_unregisterPublicKey"

#define SCA_DEF_INIT                  "init"

#define SCA_DEF_VALIDATE               "validate"
#define SCA_DEF_SIGN_WITH_KEY          "sign_with_key"

#define SCA_DEF_IS_EXTENDED            "isExtended"
#define SCA_DEF_EXT_VALIDATE           "extValidate"
#define SCA_DEF_REGISTER_PUBLIC_KEY    "registerPublicKey"
#define SCA_DEF_UNREGISTER_PUBLIC_KEY  "unregisterPublicKey"

#define SCA_DEF_IS_PRIVATE_KEY_STORAGE "isPrivateKeyStorage"
#define SCA_DEF_SIGN_WITH_ID           "sign_with_id"
#define SCA_DEF_REGISTER_PRIVATE_KEY   "registerPrivateKey"
#define SCA_DEF_UNREGISTER_PRIVATE_KEY "unregisterPrivateKey"

#ifndef SYSCONFDIR
#define SYSCONFDIR               "/etc"
#endif // SYSCONFDIR

#define SYS_CFG_FILE SYSCONFDIR "/" CRYPTO_CFG_FILE
#define LOC_CFG_FILE "./" CRYPTO_CFG_FILE

#define MAX_FUNC_NAME 512

typedef struct {
  const char* str_library_name;

  const char* str_use_init;
  const char* str_init_val;
  
  const char* str_method_init;
  
  const char* str_method_validate;
  const char* str_method_sign_with_key;

  const char* str_method_isExtended;
  const char* str_method_extValidate;
  const char* str_method_registerPublicKey;
  const char* str_method_unregisterPublicKey;

  const char* str_method_isPrivateKeyStorage;
  const char* str_method_sign_with_id;
  const char* str_method_registerPrivateKey;
  const char* str_method_unregisterPrivateKey;
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
 * 
 * @return 0: error.
 */
int wrap_init(const char* value)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "Called local test wrapper 'init'\n");
  return 0;  
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
 * @return -1: error -> implementation missing
 */
int wrap_validate(BgpsecPathAttr* bgpsec_path, u_int16_t number_keys,
                  BGPSecKey** keys, void *prefix, u_int32_t localAS )
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "Called local test wrapper 'validate'\n");
  return -1;
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
 * @return -1: error -> Missing implementation
 */
int wrap_extValidate(BgpsecPathAttr* bgpsec_path, void *prefix,
                     u_int32_t localAS, u_int8_t* extCode)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "Called local test wrapper 'wrap_extValidate'\n");
  return -1;
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
int wrap_sign_with_key(BGPSecSignData* bgpsec_data, BGPSecKey* key)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "Called local test wrapper 'sign_with_key'\n");

  return API_FAILURE;
}

/**
 *
 * Wrapper for sign the given BGPSEC path data with the provided key. This
 * implementation does not sign the path.
 *
 * @param bgpsec_data The data object to be signed. This also includes the
 *                    generated signature.
 * @param keyID The pre-registered private key to be used
 *
 * @return 1 for success, 0 for failure
 */
int wrap_sign_with_id(BGPSecSignData* bgpsec_data, u_int8_t keyID)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "Called local test wrapper 'sign_with_id'\n");

  return API_FAILURE;
}

/**
 * Register the private key. This method does not store the key. the return
 * value is 0
 *
 * @param key The key to be stored
 *
 * @return 0
 */
u_int8_t wrap_registerPrivateKey(BGPSecKey* key)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "Called local test wrapper 'registerPrivateKey'\n");

  return API_FAILURE;
}

/**
 * Unregister the Private key. This method actually does not register unregister
 * the private key. It returns 0
 *
 * @param keyID The key id to unregister.
 *
 * @return 0
 */
u_int8_t wrap_unregisterPrivateKey(u_int8_t keyID)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "Called local test wrapper "
                           "'unregisterPrivateKey'\n");

  return API_FAILURE;
}

/**
 * Register the public key. This method does not store the key. the return
 * value is 0
 *
 * @param key The key to be stored
 *
 * @return 0
 */
u_int8_t wrap_registerPublicKey(BGPSecKey* key)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "Called local test wrapper 'registerPublicKey'\n");

  return API_FAILURE;
}

/**
 * Unregister the Private key. This method actually does not register unregister
 * the private key. It returns 0
 *
 * @param keyID The key id to unregister.
 *
 * @return 0
 */
int wrap_unregisterPublicKey(BGPSecKey* key)
{
  // Return an error for missing implementation.
  sca_debugLog (LOG_DEBUG, "Called local test wrapper 'unregisterPublicKey'\n");

  return API_FAILURE;
}

/**
 * This method determines if the API provides the extended public key
 * management. In this case the extended validation method extValidate can be
 * called.
 *
 * @return 0: Does NOT provide the extended method. 1: does provide extended
 *         functionality
 */
int wrap_isExtended()
{
  sca_debugLog (LOG_DEBUG, "Called local test wrapper 'isExtended'\n");

  return 0;
}

/**
 * Return 1 if this API allows the storage of private keys, otherwise 0.
 *
 * @return 0: Does not provide private key storage, 1: Does provide key
 *         private storage
 */
int wrap_isPrivateKeyStorage()
{
  sca_debugLog (LOG_DEBUG, "Called local test wrapper 'isPrivateKeyStorage'\n");

  return 0;
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
 *
 * @return true if all went well.
 */
static void _loadGeneralConfiguration(config_t* cfg)
{
    /* debug level */
  long int newLogLevel = g_loglevel;
  if(config_lookup_int(cfg, "debug-type", &newLogLevel))
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
  // LOAD INIT VALUES
  //////////////////////////////////////////////////////////////////////////////  
  __readMapping(set, SCA_USE_INIT, &mappings->str_use_init);
  __readMapping(set, SCA_INIT_VALUE, &mappings->str_init_val); 
  __readMapping(set, SCA_INIT, &mappings->str_method_init);
  
  //////////////////////////////////////////////////////////////////////////////
  // REQUIRED FUNCTIONS
  //////////////////////////////////////////////////////////////////////////////
  __readMapping(set, SCA_SIGN_WITH_KEY, &mappings->str_method_sign_with_key);
  __readMapping(set, SCA_VALIDATE, &mappings->str_method_validate);

  //////////////////////////////////////////////////////////////////////////////
  // PRIVATE KEY STORAGE
  //////////////////////////////////////////////////////////////////////////////
  __readMapping(set, SCA_IS_PRIVATE_KEY_STORAGE,
                     &mappings->str_method_isPrivateKeyStorage);
  __readMapping(set, SCA_SIGN_WITH_ID, &mappings->str_method_sign_with_id);
  __readMapping(set, SCA_REGISTER_PRIVATE_KEY,
                     &mappings->str_method_registerPrivateKey);
  __readMapping(set, SCA_UNREGISTER_PRIVATE_KEY,
                     &mappings->str_method_unregisterPrivateKey);

  //////////////////////////////////////////////////////////////////////////////
  // EXTENDED - validation and public key storage
  //////////////////////////////////////////////////////////////////////////////
  __readMapping(set, SCA_IS_EXTENDED, &mappings->str_method_isExtended);
  __readMapping(set, SCA_EXT_VALIDATE, &mappings->str_method_extValidate);
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
    
    __doMapFunction(api->libHandle, (void**)&api->validate,
                    mappings->str_method_validate, SCA_DEF_VALIDATE);
    __doMapFunction(api->libHandle, (void**)&api->sign_with_key,
                    mappings->str_method_sign_with_key, SCA_DEF_SIGN_WITH_KEY);
    __doMapFunction(api->libHandle, (void**)&api->isExtended,
                    mappings->str_method_isExtended, SCA_DEF_IS_EXTENDED);
    __doMapFunction(api->libHandle, (void**)&api->isPrivateKeyStorage,
                    mappings->str_method_isPrivateKeyStorage,
                    SCA_DEF_IS_PRIVATE_KEY_STORAGE);

    if (api->isExtended())
    {
      __doMapFunction(api->libHandle, (void**)&api->extValidate,
                      mappings->str_method_extValidate, SCA_DEF_EXT_VALIDATE);
      __doMapFunction(api->libHandle, (void**)&api->registerPublicKey,
                      mappings->str_method_registerPublicKey,
                      SCA_DEF_REGISTER_PUBLIC_KEY);
      __doMapFunction(api->libHandle, (void**)&api->unregisterPublicKey,
                      mappings->str_method_unregisterPublicKey,
                      SCA_DEF_UNREGISTER_PUBLIC_KEY);
    }

    if (api->isPrivateKeyStorage())
    {
      __doMapFunction(api->libHandle, (void**)&api->sign_with_id,
                      mappings->str_method_sign_with_id, SCA_DEF_SIGN_WITH_ID);
      __doMapFunction(api->libHandle, (void**)&api->registerPrivateKey,
                      mappings->str_method_registerPrivateKey,
                      SCA_DEF_REGISTER_PRIVATE_KEY);
      __doMapFunction(api->libHandle, (void**)&api->unregisterPrivateKey,
                      mappings->str_method_unregisterPrivateKey,
                      SCA_DEF_UNREGISTER_PRIVATE_KEY);
    }
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
 *
 * @return int API_FAILURE (0) for failure API_SUCCESS (1) for success.
 */
int srxCryptoInit(SRxCryptoAPI* api)
{
  int retVal             = API_FAILURE;
  SCA_Mappings* mappings = NULL;
  config_setting_t *set  = NULL;
  bool useLocal          = false;
  const char* str_library_conf = NULL;
  static config_t cfg;
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
  api->validate             = wrap_validate;
  api->sign_with_key        = wrap_sign_with_key;

  api->isExtended           = wrap_isExtended;
  api->extValidate          = wrap_extValidate;
  api->registerPublicKey    = wrap_registerPublicKey;
  api->unregisterPublicKey  = wrap_unregisterPublicKey;

  api->isPrivateKeyStorage  = wrap_isPrivateKeyStorage;
  api->sign_with_id         = wrap_sign_with_id;
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
      _loadGeneralConfiguration(&cfg);

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
          
          // Do the library initialization if specified
          const char* initVal = NULL;
          if (mappings->str_init_val != NULL)
          {
            if (strcmp(mappings->str_init_val, "NULL") != 0)
            {
              initVal = mappings->str_init_val;
            }
          }
          if (mappings->str_use_init != NULL)
          {
            int use_init = atoi(mappings->str_use_init);
            if (use_init == 1)
            {
              // initialize API
              sca_debugLog(LOG_INFO, 
                           "Initiate library initialization using '%s'\n",
                           initVal);
              if (api->init(initVal) == 0)
              {
                sca_debugLog(LOG_ERR, "Initialization failed!\n");
              }
            }
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
      srxCryptoUnbind(api);
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
 *
 * @return 0
 */
int srxCryptoUnbind(SRxCryptoAPI* api)
{
  if (api->libHandle != NULL)
  {
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

  return 0;
}

////////////////////////////////////////////////////////////////////////////////
// Helper Functions
////////////////////////////////////////////////////////////////////////////////

/**
 * This function sets the key path.
 *
 * @param key_path the path to the keys (\0 terminated).
 *
 * @return 0 error, 1 success
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
 *
 * @return 1 if key was loaded successfully, 0 otherwise
 */
int sca_loadKey(BGPSecKey* key, bool fPrivate)
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

  return impl_loadKey(key, fPrivate, fPrivate ? _key_ext_priv : _key_ext_pub);
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

/**
 * Generate the message for the hash generation for the initial segment for
 * protocol draft 13
 *
 * @param buff The buffer to be used or NULL - In the later case a new buffer
 *             will be allocated using malloc
 * @param blen IN/OUT for IN the size of buff, for OUT, the number of bytes used
 *             in buff which might be the total length of buff or less.s
 * @param targetAS The next AS to send the update to
 * @param originAS The origin AS
 * @param pCount the pCount of this hop (OriginAS)
 * @param flags The flags
 * @param algoID The Algorithm ID
 * @param afi The AFI (AFI_V4 | AFI_V6)
 * @param safi The SAFI
 * @param pLen The prefix length in bits. Used to calculate the bytes needed to
 *        store the prefix (padded)
 * @param nlri The prefix.
 *
 * @return The hash stored in either the given buff or a new allocated memory.
 *         The length of the new hash is stores in 'blen'
 */
u_int8_t* sca_generateMSG1(u_int8_t* buff, u_int8_t* blen, u_int32_t targetAS,
                           u_int32_t originAS, u_int8_t  pCount,
                           u_int8_t  flags, u_int8_t  algoID, u_int16_t afi,
                           u_int8_t  safi, u_int8_t  pLen, u_int8_t* nlri)
{
  if (blen != NULL)
  {
    // Determine the memory needed.
    u_int8_t nlriLength = (pLen / 8) + (pLen % 8 == 0 ? 0 : 1);
    u_int8_t neededLen = 4+4+1+1+1+2+1+1+nlriLength;

    if (buff == NULL || *blen < neededLen)
    {
      buff = malloc(neededLen);
    }
    memset(buff, 0, neededLen);
    TplHash1* hash1 = (TplHash1*)buff;
    hash1->targetAS = htonl(targetAS);
    hash1->originAS = htonl(originAS);
    hash1->pCount   = pCount;
    hash1->flags    = flags;
    hash1->algoID   = algoID;
    hash1->afi      = htons(afi);
    hash1->safi     = safi;
    hash1->pLen     = pLen;
    if (pLen > 0)
    {
      u_int8_t* hashNlri = buff + sizeof(TplHash1);
      memcpy(hashNlri, nlri, nlriLength);
    }
    *blen = neededLen;
  }
  else
  {
    sca_debugLog(LOG_ERR, "Invalid buffer size 'NULL'\n");
    buff = NULL;
  }

  return buff;
}

/**
 * Generate the message for the hash generation for the intermediate segment for
 * protocol draft 13
 *
 * @param buff The buffer to be used or NULL - In the later case a new buffer
 *             will be allocated using malloc.
 * @param buffLen The length of the input buffer (only used if buff != NULL)
 * @param targetAS The next AS to send the update to.
 * @param originAS The origin AS.
 * @param pCount the pCount of this hop (OriginAS).
 * @param flags The flags.
 * @param sigLen The length of the given signature.
 * @param signature The previous signature.
 *
 * @return The hash stored in either the given buff or a new allocated memory.
 *         The length of the new hash is stores in 'blen'
 */
u_int8_t* sca_generateMSG2(u_int8_t* buff, u_int8_t* blen, u_int32_t targetAS,
                           u_int32_t signerAS, u_int8_t pCount, u_int8_t flags,
                           u_int8_t sigLen, u_int8_t* signature)
{
  // Determine the memory needed.
  u_int8_t neededLen = 4+4+1+1+sigLen;
  if (blen != NULL)
  {
    if (buff == NULL || *blen < neededLen)
    {
      buff = malloc(neededLen);
    }
    memset(buff, 0, neededLen);

    TplHash2* hash2 = (TplHash2*)buff;
    hash2->targetAS = htonl(targetAS);
    hash2->signerAS = htonl(signerAS);
    hash2->pCount   = pCount;
    hash2->flags    = flags;
    u_int8_t* ptr = buff + sizeof(TplHash2);
    memcpy(ptr, signature, sigLen);

    *blen = neededLen;
  }
  else
  {
    sca_debugLog(LOG_ERR, "Invalid buffer size 'NULL'\n");
    buff = NULL;
  }

  return buff;
}
