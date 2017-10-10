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
 * File contains methods to test API.
 * 
 * @version 0.2.0.3
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 *   0.2.0.4 - 2017/09/12 - oborchert
 *             * Moved SCA 0.2.x into branch for further bugfixes. Trunk will
 *               is different.
 *             * Added missing integer type in static variable TEST_1
 *   0.2.0.3 - 2017/04/19 - oborchert
 *             * Added test parameter to arguments and restructured defines.
 *           - 2017/04/19 - oborchert
 *             * Fixed checking of parameters.
 *             * Added some more testing, including the parameter '-k ...'
 *   0.1.2.2 - 2016/03/25 - oborchert
 *             * Fixed BZ898 which caused the test tool not to read the provided
 *               configuration file.
 *   0.1.2.0 - 2015/12/01 - oborchert
 *             * Removed unused header bgpsec_openssl/bgpsec_openssh.h
 *           - 2015/11/03 - oborchert
 *             * Removed ski and algoID from struct BGPSecSignData, both data 
 *               fields are part of the BGPSecKey structure. (BZ795)
 *             * modified function signature of sign_with_id (BZ788)
 *   0.1.0   - October 7, 2015 - oborchert
 *             * Moved file back into project.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <openssl/bio.h>
#include "srx/srxcryptoapi.h"

/** String size. */
#define STR_MAX 256

/* informational */
#define LOG_ERR     3
/* informational */
#define LOG_INFO    6
/* debug-level messages */
#define LOG_DEBUG   7 
 /* The maximum number of keys */
#define MAX_NO_KEYS   10
/* The number of as paths */
#define MAX_NO_ASPATH 3

#ifndef SYSCONFDIR
#define SYSCONFDIR "."
#endif

#define CONF_FILE SYSCONFDIR "/srxcryptoapi.conf"

#define TEST_1 1
#define TEST_2 2
#define TEST_OK 0
#define TEST_FAILED 1

/** Contains provided key specifications. */
typedef struct {
  /** Determine if this spec is for a private or public key. */
  bool      isPrivate;
  /** The ASN in network format */
  u_int32_t asn;
  /** the SKI of the key as hex string.*/
  char      ski[STR_MAX];
  /** The algorithm ID of the key */
  u_int8_t  algoID;
} KeySpec;

/** Contains a list of provided key specifications. */
typedef struct _st_list {
  struct _st_list* next;
  KeySpec keySpec;
} st_list;

/** This struct allows to reduce the code by assigning the requred public or 
 * private function to the key management. */
typedef struct {
  u_int8_t(*registerKey)(BGPSecKey* key, sca_status_t* status);
  u_int8_t(*unregisterKey)(BGPSecKey* ski, sca_status_t* status);
} KeyTester;

static st_list* keyList = NULL;
static int st_test = TEST_1;

/**
 * Add the key specification to the list
 * 
 * @param ski the SKI
 * @param isPrivate indicates if the key is private or not.
 */
static void pushKeySpec(char* priv, char* asn, char* ski)
{
  st_list* ptr;
  st_list* listElem = malloc(sizeof(st_list));
  
  memset (listElem, 0, sizeof(st_list));  
  
  listElem->keySpec.asn = htonl(atoi(asn));
  snprintf(listElem->keySpec.ski, STR_MAX, "%s", ski);
  listElem->keySpec.isPrivate = strncmp(priv, "priv", 4) == 0;
  listElem->keySpec.algoID    = SCA_ECDSA_ALGORITHM;
  
  if (keyList == NULL)
  {
    keyList = listElem;
  }
  else
  {
    ptr = keyList;
    while (ptr->next != NULL)
    {
      ptr = ptr->next;
    }
    ptr->next = listElem;
  }
}

/**
 * Fill the given keySpec with the values found.
 * 
 * @return true if keySpec could be filled, otherwise false.
 * 
 * @since 0.2.0.3
 */
static bool popKeySpec(KeySpec* keySpec)
{
  bool retVal = false;
  if (keySpec != NULL)
  {
    st_list* element = keyList;
    if (element != NULL)
    {
      keyList = keyList->next;
      memcpy (keySpec, &element->keySpec, sizeof(KeySpec));      
      memset (element, 0, sizeof(st_list));      
      free(element);
      retVal = true;
    }
    else
    {
      memset (keySpec, 0, sizeof(KeySpec));
    }
  }
  return retVal;
}

/**
 * Zero out and free the given element.
 * 
 * @param listElem The list elem element
 * @since 0.2.0.3
 */
static void freeKeySpec(st_list* listElem)
{
  if (listElem != NULL)
  {
    memset(listElem, 0, sizeof(st_list));
    free (listElem);
  }
}
/**
 * Similar to assert except no ERROR will be thrown.
 * @param assertion
 */
static void report(bool assertion)
{
  if (!assertion)
  {
    printf("\n********************* ASSERT FAILED *************************\n");
  }
}

#define NO_KEYS 5

/** Print the program syntax 
 * 
 * @since 0.2.0.3
 */
static void __syntax()
{
  printf ("Syntax: srx_crypto_tester [options]\n");
  printf ("  Options:\n");
  printf ("    -?               This screen!\n");
  printf ("    -f <cfg-file>    Use the provided configuration file!\n");
  printf ("    -k <pub|priv> <asn> <20-byte ski as HEX VALUE>\n");
  printf ("                     Add the particular key to the tests.\n");
  printf ("    -t <1|2>         Run Test 1 or Test 2.\n");
  printf ("             Test 1: Read configuration and then attempt to register\n");
  printf ("                     the incomplete key. followed by unregister, ");
  printf ("                     followed by a registration with der key loaded.\n");
  printf ("             Test 2: Just load the keys in the order specified.\n");
  printf ("    -t <1|2>         Run Test 1 or Test 2.\n");
  printf ("\n");
  printf ("2017 Advanced Network Technologies Division (NIST)!\n");
}

/**
 * Check the program parameters.
 * 
 * @param argc The number of arguments
 * @param argv The array containing the arguments
 * @param crypto The crypto API
 * 
 * @return 0 if the program has to be exited, 1 if the program can be continued.
 * 
 * @since 0.2.0.3
 */
static int _checkParams(int argc, char** argv, SRxCryptoAPI* crypto)
{
  int idx = 0;
  int retVal = 1;
  
  if (crypto != NULL)
  {    
    char* priv = NULL;
    char* asn  = NULL;
    char* ski  = NULL;
    for (; idx < argc; idx++)
    {
      if (argv[idx][0] == '-' )
      {
        if (strlen(argv[idx]) > 1)
        {
          switch (argv[idx][1])
          {
            case '?' :
              __syntax();
              retVal = 0;
              break;
            case 'k' :
              if ((idx + 3) < argc)
              {
                priv = argv[++idx];
                asn  = argv[++idx];
                ski  = argv[++idx];
                printf ("Store the Key (%s, %s, '%s')\n", priv, asn, ski);
                pushKeySpec(priv, asn, ski);
                priv = NULL; asn  = NULL; ski  = NULL;
              }
              else
              {
                printf ("ERROR: Insufficient data for '-k'!\n");                
                __syntax();
                retVal = 1;
                idx = argc;
              }
              break;
            case 't' :
              if (idx < argc) // flipped variables BZ898
              {
                st_test = atoi(argv[++idx]);
                switch (st_test)
                {
                  case TEST_1:
                  case TEST_2:
                    break;
                  default:
                    __syntax();
                    retVal = 1;
                }
              }
              
              break;
            case 'c' : 
              printf ("WARNING: Parameter -c is deprecated, please use -f "
                      "instead!\n");
            case 'f' : 
              idx++;
              if (idx < argc) // flipped variables BZ898
              {
                crypto->configFile = argv[idx];
              }
              break;
            default:
              break;
          }
        }
      }
    }
  
    // Needed to move the code below inside this if clause to prevent a possible
    // segmentation fault if crypto == NULL
    if (crypto->configFile == NULL)
    {
      crypto->configFile = CONF_FILE;        
    }
  }
  
  return retVal;
}

/**
 * Copy the data specified in the keySpec into the BGPSEcKey instance.
 * 
 * @param key A pre-allocated instance that will be filled with the data stored 
 *            in the parameter keySpec.
 * @param keySpec The specification for the bgpsec key.
 * 
 * @since 0.2.0.3
 */
static void _setBGPSEcKey(BGPSecKey* key, KeySpec* keySpec)
{
  if (key != NULL)
  {
    if (key->keyData != NULL)
    {
      free (key->keyData);
    }
    memset (key, 0, sizeof(BGPSecKey));
    
    key->asn    = keySpec->asn;
    key->algoID = keySpec->algoID;

    int keySpecLen = strlen(keySpec->ski);
    int idx1, idx2;
    char hexNum[5] = {'0', 'x', 0, 0, 0};
    for (idx1 = 0, idx2 = 0; (idx1 < SKI_LENGTH) && (idx2 < keySpecLen); 
         idx1++, idx2++)
    {
      hexNum[2] = keySpec->ski[idx2];
      hexNum[3] = keySpec->ski[++idx2];
      key->ski[idx1] = (u_int8_t)strtol(hexNum, NULL, 0);;
    }
  }  
}

/** Test the keys by installing and un installing. 
 * For best results, do NOT preload keys.
 * 
 * @param key The BGPSEC Key (empty)
 * @param keySpec The key specificatoin
 * @param api points to the register and unregister fundtions
 * @param privacyStr Contains "private" or "public" 
 * @param status The status informtaion 
 * 
 * @return 0 if all went well, otherwise 1.
 */
static int _doKeyTest_1(BGPSecKey* key, KeySpec* keySpec, KeyTester* api, 
                        char* keyName, sca_status_t* status)
{
  int retVal = TEST_OK;
  
  // 1st try to store a key that does not provide DER key.
  printf ("  - Register incomplete %s key...", keyName);
  if (api->registerKey(key, status) == API_SUCCESS)
  {
    printf ("failed - key stored!!\n"
            "WARNING: %s key without DER information stored!\n", keyName);
    retVal = TEST_FAILED;
  }
  else
  {
    printf ("success - key NOT stored.\n");
  }
  // 2nd have the crypto API load the key
  sca_loadKey(key, keySpec->isPrivate, status);
  // 3rd have the crypto API loaded key register in the plugin
  printf ("  - Register complete %s key...", keyName);
  if (api->registerKey(key, status) != API_SUCCESS)
  {
    printf ("failed\n"
            "WARNING: Could not store %s key.\n", keyName);
    retVal = TEST_FAILED;
  }
  else
  {
    // - Now unregister
    printf ("succes\n  - Unregister %s key...", keyName);
    if (api->unregisterKey(key, status) != API_SUCCESS)
    {
      printf ("failed\n"
              "WARNING: could not unregister %s key.\n", keyName);
      retVal = TEST_FAILED;
    }
    else
    {
      printf ("success\n");
    }
  }
  
  return retVal;
}

/** Test the keys by installing and un installing. 
 * For best results, do NOT preload keys.
 * 
 * @param key The BGPSEC Key (empty)
 * @param keySpec The key specificatoin
 * @param api points to the register and unregister fundtions
 * @param privacyStr Contains "private" or "public" 
 * @param status The status informtaion 
 * 
 * @return 0 if all went well, otherwise 1.
 */
static int _doKeyTest_2(BGPSecKey* key, KeySpec* keySpec, KeyTester* api, 
                        char* keyName, sca_status_t* status)
{
  int retVal =  TEST_OK;

  sca_loadKey(key, keySpec->isPrivate, status);
  api->registerKey(key, status);
  api->registerKey(key, status);
  api->unregisterKey(key, status);
  api->unregisterKey(key, status);
    
  return retVal;
}


/**
 * The main test program.
 * 
 * @param argc The number of arguments handed to the program
 * @param argv The argument handed to the program
 * 
 * @return 0 if all is OK, otherwise 1
 */
int main(int argc, char** argv)
{     
  int retVal = TEST_OK;
  
  SRxCryptoAPI* crypto = malloc(sizeof(SRxCryptoAPI));
  memset (crypto, 0, sizeof(SRxCryptoAPI));
  
  if (_checkParams(argc, argv, crypto))
  {
    int initVal = 0;
    sca_status_t status = API_STATUS_OK;
    initVal = srxCryptoInit(crypto, &status);

    // For now just to disable the compiler warning
    report (true);

    if (initVal)
    {
      printf ("API initialized!\n");
      
      KeySpec   keySpec;
      memset (&keySpec, 0, sizeof(KeySpec));
      BGPSecKey key;
      memset (&key, 0, sizeof(BGPSecKey));
      KeyTester keyTester;
      memset(&keyTester, 0, sizeof(KeyTester));

      bool lastPrivate = true;
      keyTester.registerKey   = crypto->registerPrivateKey;
      keyTester.unregisterKey = crypto->unregisterPrivateKey;
      char* keyName = "private";
      
      while (popKeySpec(&keySpec))
      
      {
        if (keySpec.isPrivate != lastPrivate)
        {
          memset(&keyTester, 0, sizeof(keyTester));
          if (keySpec.isPrivate)
          {
            keyTester.registerKey   = crypto->registerPrivateKey;
            keyTester.unregisterKey = crypto->unregisterPrivateKey;
            keyName = "private";
          }
          else
          {
            keyTester.registerKey   = crypto->registerPublicKey;
            keyTester.unregisterKey = crypto->unregisterPublicKey;
            keyName = "public";
          }
          lastPrivate = keySpec.isPrivate;
        }
        
        printf ("Process key: %s; ASN %u; SKI [%s]\n", keyName,
                htonl(keySpec.asn), keySpec.ski);
        _setBGPSEcKey(&key, &keySpec);

        switch (st_test)
        {
          case TEST_1 : 
            printf ("Run TEST 1\n");
            _doKeyTest_1(&key, &keySpec, &keyTester, keyName , &status);
            break;
          case TEST_2:
            printf ("Run TEST 2\n");
            _doKeyTest_2(&key, &keySpec, &keyTester, keyName , &status);
            break;
          default:
            printf ("No test!\n");
        }                        
        
        if (key.keyData !=  NULL)
        {
          free(key.keyData);
          key.keyLength = 0;
        }        
        memset(&key, 0, sizeof(BGPSecKey));
      }      
      memset(&keyTester, 0, sizeof(keyTester));
    }
    else
    {
      printf ("Failure initializing API!\n");
      retVal = TEST_FAILED;
    }

    status = API_STATUS_OK;
    srxCryptoUnbind(crypto, &status);
    free(crypto);
    printf ("done!\n");
  }  
  return 0;  
}