#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <openssl/bio.h>
#include "srxcryptoapi.h"

#define LOG_ERR     3   /* informational */
#define LOG_INFO    6   /* informational */
#define LOG_DEBUG   7   /* debug-level messages */

#define MAX_NO_KEYS   10  /* The maximum number of keys */
#define MAX_NO_ASPATH 3   /* The number of as paths */

char** asPaths = NULL;


typedef struct {
  BGPSecKey*      privKey;
  u_int8_t        keyID;
  u_int16_t       noPubKeys;
  BgpsecPathAttr* bgpsecPath;
  void*           prefix;
  u_int16_t       localAS;
  u_int8_t        extCode;
  BGPSecSignData* bgpsecData;
  u_int16_t       dataLength;
  u_int8_t*       data;
  u_int16_t       sigLen;
  u_int8_t*       signature;
  BGPSecKey*      pubKeys[MAX_NO_KEYS];
} TestData;

/**
 * Create an empty the data element. The only initialized element is the key 
 * array which contains an empty array
 * @param int noKeys The number of keys used within the test data.
 * 
 * @return an empty initialized TestData object.
 */
TestData* createEmptyTestData()
{
  int size = sizeof(TestData);
  TestData* tData = malloc(size);  
  memset(tData, '\0', size);
  return tData;
}

/**
 * REturn the key for the particular ASN
 * 
 * @param asn The AS number the key is wanted for
 * @param private Determines if the private or public key is requested
 * 
 * @return The key or NULL
 */
BGPSecKey* getKey(int asn, bool private)
{
  BGPSecKey* key = NULL;
  
  key = malloc(sizeof(BGPSecKey));
  memset (key, '\0', sizeof(BGPSecKey));
  
  key->algoID = 1;
  key->asn = asn;
  key->keyLength = 0;
  key->keyData = NULL;
  memset(key->ski, '\0', SKI_LENGTH);
  return key;
}

/**
 * Free all pointers that are not NULL and free the structure itself.
 * 
 * @param tData The test data.
 */
void freeTestData(TestData* tData)
{
  int idx = 0;
  
  // Don't free the keys, the are part of the system
  tData->privKey = NULL;
  if (tData->noPubKeys != 0)
  {
    for (idx = 0; idx < tData->noPubKeys; idx++)
    {
      tData->pubKeys[idx] = NULL; 
    }
    free (tData->pubKeys);
  }  
  tData->bgpsecPath = NULL;
  
  if (tData->prefix != NULL)
  {
    free(tData->prefix);
  }
  if (tData->bgpsecData != NULL)
  {
    free(tData->bgpsecData);
  }
  if (tData->data != NULL)
  {
    free(tData->data);
  }
  if (tData->signature != NULL)
  {
    free(tData->signature);
  }
  free (tData);
}

/**
 * Prepare the data for test 1. The data is an empty initialized set. 
 * 
 * @return TestData* Pointer to the test data.
 */
TestData* dataTest1()
{
  TestData* data = createEmptyTestData();
  
  return data;
}

BGPSecKey* _getKey(int asn, bool isPrivate)
{
  assert(asn <= MAX_NO_KEYS);
  
  return NULL;
}

/**
 * Prepare the data for test 2. The data contains 2 keys, a path that can 
 * be signed etc.
 * 
 * @return TestData* Pointer to the test data.
 */
TestData* dataTest2()
{
  TestData* tData = createEmptyTestData();
  
  tData->localAS    = 1;
  tData->noPubKeys  = 2;
  tData->pubKeys[0] = _getKey(60000, false);
  tData->pubKeys[1] = _getKey(60001, false);
  tData->privKey    = _getKey(49, true);
  //tData->data
  return tData;  
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

/**
 * This method checks the faulre return of the bound API
 * 
 * @param crypto The initialized crypto API
 */
void testFailAll(SRxCryptoAPI* crypto, TestData* tData)
{
  int testRetVal = 0;
  int idx=0;
  
  printf ("\nTest (1): Call all available functions and check for call "
          "failures.\n");
  
  printf ("\nTest Validate...\n\t");
  testRetVal = crypto->validate(tData->bgpsecPath, tData->noPubKeys, 
                                tData->pubKeys, tData->prefix, tData->localAS);
  report(testRetVal==-1);

  if (crypto->isExtended)
  {
    printf ("\nTest register %d public keys...\n\t", tData->noPubKeys);
    for (idx = 0; idx < tData->noPubKeys; idx++)
    {
      testRetVal = crypto->registerPublicKey(tData->pubKeys[idx]);
      report(testRetVal==0);    
      printf ("\t");
    }

    printf ("\nTest Extended Validate...\n\t");
    testRetVal = crypto->extValidate(tData->bgpsecPath, tData->prefix, 
                                     tData->localAS, &(tData->extCode));
    report(testRetVal==-1);      

    printf ("\nTest unregister %d public keys...\n\t", tData->noPubKeys);
    for (idx = 0; idx < tData->noPubKeys; idx++)
    {
      testRetVal = crypto->unregisterPublicKey(tData->pubKeys[idx]);      
      report(testRetVal==0);    
      printf ("\t");
    }
  }
  else
  {
    printf ("No Extended Validate Available\n");      
  }

  printf ("\nTest sign with Key...\n\t");
  testRetVal = crypto->sign_with_key(tData->bgpsecData, tData->privKey);
  report(testRetVal==0);        

  if (crypto->isPrivateKeyStorage)
  {
    printf ("\nTest register private key...\n\t");
    tData->keyID = crypto->registerPrivateKey(tData->privKey);
    report(tData->keyID==0);    

    printf ("\nTest sign with KeyID...\n\t");
    testRetVal = crypto->sign_with_id(tData->dataLength, tData->data, 
                                      tData->keyID, tData->sigLen, 
                                      tData->signature);
    report(testRetVal==0);    
    
    printf ("\nTest unregister private key...\n\t");
    crypto->unregisterPrivateKey(tData->keyID);
    report(testRetVal==0);        
  }  
}

/**
 * This method checks the validation return "valid" of the bound API
 * 
 * @param crypto The initialized crypto API
 */
void testValidValidation(SRxCryptoAPI* crypto)
{
  BGPSecKey*      privKey    = NULL;
  u_int8_t        keyID      = 0;    
  u_int16_t       noPubKeys  = 0;
  BGPSecKey**     pubKeys    = NULL;
  BgpsecPathAttr* bgpsecPath = NULL;
  void*           prefix     = NULL;
  u_int16_t       localAS    = 0;
  u_int8_t        extCode    = 0;
  BGPSecSignData* bgpsecData = NULL;
  u_int16_t       dataLength = 0;
  u_int8_t*       data       = NULL;
  u_int16_t       sigLen     = 0;
  u_int8_t*       signature  = NULL;
  //TODO fill values above and make calls.

  int testRetVal = 0;
  int idx=0;
  
  printf ("\nTest (2): Call all available functions and check for call "
          "with valid return.\n");

  printf ("\nTest Validate...\n\t");
  testRetVal = crypto->validate(bgpsecPath, noPubKeys, pubKeys, prefix, localAS);
  report(testRetVal==1);

  if (crypto->isExtended)
  {
    printf ("\nTest register %d public keys...\n\t", noPubKeys);
    for (idx = 0; idx < noPubKeys; idx++)
    {
      testRetVal = crypto->registerPublicKey(pubKeys[idx]);
      report(testRetVal==1);    
      printf ("\t");
    }

    printf ("\nTest Extended Validate...\n\t");
    testRetVal = crypto->extValidate(bgpsecPath, prefix, localAS, &extCode);
    report(testRetVal==1);      

    printf ("\nTest unregister %d public keys...\n\t", noPubKeys);
    for (idx = 0; idx < noPubKeys; idx++)
    {
      testRetVal = crypto->unregisterPublicKey(pubKeys[idx]);
      report(testRetVal==1);    
      printf ("\t");
    }
  }
  else
  {
    printf ("No Extended Validate Available\n");      
  }

  printf ("\nTest sign with Key...\n\t");
  testRetVal = crypto->sign_with_key(bgpsecData, privKey);
  report(testRetVal==1);        

  if (crypto->isPrivateKeyStorage)
  {
    printf ("\nTest register private key...\n\t");
    keyID = crypto->registerPrivateKey(privKey);
    report(keyID > 0);    

    printf ("\nTest sign with KeyID...\n\t");
    testRetVal = crypto->sign_with_id(dataLength, data, keyID, 
                                      sigLen, signature);
    report(testRetVal==1);    
    
    printf ("\nTest unregister private key...\n\t");
    crypto->unregisterPrivateKey(keyID);
    report(testRetVal==1);        
  }  
}

/**
 * This method checks the validation return "invalid" of the bound API
 * 
 * @param crypto The initialized crypto API
 */
void testInValidValidation(SRxCryptoAPI* crypto)
{
  BGPSecKey*      privKey    = NULL;
  u_int8_t        keyID      = 0;    
  u_int16_t       noPubKeys  = 0;
  BGPSecKey**     pubKeys    = NULL;
  BgpsecPathAttr* bgpsecPath = NULL;
  void*           prefix     = NULL;
  u_int16_t       localAS    = 0;
  u_int8_t        extCode    = 0;
  BGPSecSignData* bgpsecData = NULL;
  u_int16_t       dataLength = 0;
  u_int8_t*       data       = NULL;
  u_int16_t       sigLen     = 0;
  u_int8_t*       signature  = NULL;
  //TODO fill values above and make calls.

  int testRetVal = 0;
  int idx=0;
  
  printf ("\nTest (3): Call all available functions and check for call "
          "with invalid return.\n");

  printf ("\nTest Validate...\n\t");
  testRetVal = crypto->validate(bgpsecPath, noPubKeys, pubKeys, prefix, localAS);
  report(testRetVal==0);

  if (crypto->isExtended)
  {
    printf ("\nTest register %d public keys...\n\t", noPubKeys);
    for (idx = 0; idx < noPubKeys; idx++)
    {
      testRetVal = crypto->registerPublicKey(pubKeys[idx]);
      report(testRetVal==1);    
      printf ("\t");
    }

    printf ("\nTest Extended Validate...\n\t");
    testRetVal = crypto->extValidate(bgpsecPath, prefix, localAS, &extCode);
    report(testRetVal==0);      

    printf ("\nTest unregister %d public keys...\n\t", noPubKeys);
    for (idx = 0; idx < noPubKeys; idx++)
    {
      testRetVal = crypto->unregisterPublicKey(pubKeys[idx]);
      report(testRetVal==1);    
      printf ("\t");
    }
  }
  else
  {
    printf ("No Extended Validate Available\n");      
  }

  printf ("\nTest sign with Key...\n\t");
  testRetVal = crypto->sign_with_key(bgpsecData, privKey);
  report(testRetVal==1);        

  if (crypto->isPrivateKeyStorage)
  {
    printf ("\nTest register private key...\n\t");
    keyID = crypto->registerPrivateKey(privKey);
    report(keyID > 0);    

    printf ("\nTest sign with KeyID...\n\t");
    testRetVal = crypto->sign_with_id(dataLength, data, keyID, 
                                      sigLen, signature);
    report(testRetVal==1);    
    
    printf ("\nTest unregister private key...\n\t");
    crypto->unregisterPrivateKey(keyID);
    report(testRetVal==1);        
  }  
}

#define NO_KEYS 5

int main()
{   
  BIO *out;
  out = BIO_new_fp(stdout, BIO_NOCLOSE);
  
  SRxCryptoAPI* crypto = malloc(sizeof(SRxCryptoAPI));
  crypto->configFile = "./srxcryptoapi.conf.sample";
  int initVal = 0;
  initVal = srxCryptoInit(crypto);

//  PathSegment* path = createSecurePath("1 12 123\0");
  
  if (initVal)
  {
    printf ("API initialized!\n");
    TestData* tData = createEmptyTestData();
    testFailAll(crypto, tData);
    freeTestData(tData);
    //testValidValidation(crypto)
    //testInValidValidation(crypto)
  }
  else
  {
    printf ("Failure initializing API!\n");
  }
  
  srxCryptoUnbind(crypto);
  free(crypto);
  printf ("done\n");
  return 0;
  
  BIO_free(out);
  
  return 0;    
}