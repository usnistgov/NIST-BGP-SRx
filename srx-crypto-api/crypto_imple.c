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
 * This file provides the implementation for SRxCryptoAPI for loading OpenSSL 
 * generated keys. This package provides the qsrx_... scripts for key 
 * generation.
 * 
 * Known Issue:
 *   At this time only pem formated private keys can be loaded.
 *
 * @version 0.2.0.0
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *   0.2.0.0 - 2016/06/08 - oborchert
 *             * Fixed memory leak during loading of public key
 *   0.1.2.0 - 2016/05/20 - oborchert
 *             * Removed unused defines and structures. 
 *             * cleaned up more code and streamlined implementation.
 *           - 2015/09/22 - oborchert
 *             * Added ChangeLog to file.
 *             * Cleaned up code and added some documentation
 *             * Moved defines into newly generated header file.
 *             * Fixed invalid file descriptor from int to FILE*
 *             * Fixed memory leaks in code
 *             * Replaced hard coded integer values with defines
 *             * Replaced usage of BIO_snprintf with snprintf, tests showed
 *               BIO is much slower
 *   0.1.1.0 - kyehwanl
 *             * Initial implementation.
 */
#include <string.h>
#include <syslog.h>
#include <stdbool.h>

#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/ecdsa.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "srx/srxcryptoapi.h"
#include "crypto_imple.h"

#define PK_FILE_BUFF_SIZE 2048

int g_loglevel=0; // need to set a certain value for debugging


// More than enough space to load the key into
#define KEYFILE_BUFF_SIZE 500
// More than enough space to load the ASN1 String of the public key
#define ASN1_BUFF_SIZE    200

/**
 * Convert the ecpoint top DER format. The memory is allocated using
 * OPENSSL_malloc.
 *  
 * @param bin_ecpoint the EC_POINT of the key.
 * 
 * @return the public key in DER format.
 */
static u_int8_t* _new_pub_ecpoint2Der(u_int8_t* bin_ecpoint)
{
  u_int8_t arrPubDerHead[26] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00};

  u_int8_t* pubDer = NULL;
  pubDer = malloc(SIZE_DER_PUBKEY);
  
  if(pubDer != NULL)
  {
    memcpy (pubDer,    arrPubDerHead, 26); // 26: der header
    memcpy (pubDer+26, bin_ecpoint,   65); // 65: ec point length
  }
  else
  {
    sca_debugLog(LOG_ERR, "+ [libcrypto] Not enough memory to generate DER\n");
  }

  return pubDer;
}

/**
 * Load the private key into the BGPSecKey object.
 * 
 * @param fName The file name of the key
 * @param key the key information itself
 * 
 * @return true if the key could be loaded, otherwise false.
 */
static bool _loadPrivKey(char* fName, BGPSecKey* key, bool checkKey)
{
  char  buff[KEYFILE_BUFF_SIZE];
  // Load the private key in DER format
  FILE*   keyFile = fopen (fName, "r");
  EC_KEY* test_key = NULL;
  char*   ptr      = buff;
  
  if (keyFile != NULL)
  {
    key->keyLength = (u_int16_t)fread (&buff, sizeof(char), KEYFILE_BUFF_SIZE, 
                                       keyFile);
    fclose(keyFile);
    
    // If requested verify the validity of the key
    if (checkKey)
    {
      test_key = d2i_ECPrivateKey(NULL, (const unsigned char**)&ptr, 
                                  key->keyLength);
      if (!EC_KEY_check_key(test_key)) 
      {
        sca_debugLog(LOG_ERR, "+ [libcrypto] EC_KEY_check failed: EC key check error\n");
        key->keyLength = 0; // This will prevent the allocation of memory
      }
      // Free the test key again.
      EC_KEY_free(test_key);
      test_key = NULL;
    }
    if (key->keyLength > 0)
    {
      key->keyData = malloc(key->keyLength);
      memcpy(key->keyData, buff, key->keyLength);
    }
  }
  else
  {
    sca_debugLog(LOG_ERR, "+ [libcrypto] Cannot open Key file '%s'!\n", 
                          fName);      
  }
  
  return key->keyLength > 0;
}

/**
 * Extract the DER key from the given X509 certificate.
 * 
 * @param cert The X509 Cert containing the key information
 * @param ket The BGPSEc key where the DER key will be stored in
 * @param curveID The IF of the key's curve
 * 
 * @return true if the key could be loaded in DER form. The DER key is stored in
 *              the given BGPSEC-Key
 */
static bool _getPublicKey(X509* cert, BGPSecKey* key, int curveID)
{
  EC_POINT* ecPointPublicKey = NULL;
  EC_GROUP* ecGroup          = NULL;
  EC_KEY*   ecdsa_key        = NULL;
  
  BN_CTX*   bn_ctx           = NULL;
  u_int8_t* buff             = NULL;
  size_t    bLen             = 0;
  
  int  asn1Len = 0;
  char asn1Buff[ASN1_BUFF_SIZE];
  
  ecGroup = EC_GROUP_new_by_curve_name(curveID);
  if (ecGroup != NULL) 
  {
    ecPointPublicKey = EC_POINT_new(ecGroup);
    if (ecPointPublicKey != NULL)
    {
      memset (&asn1Buff, '\0', ASN1_BUFF_SIZE);
      asn1Len = ASN1_STRING_length(cert->cert_info->key->public_key);
      memcpy (asn1Buff, ASN1_STRING_data(cert->cert_info->key->public_key),
              asn1Len);
      ecdsa_key = EC_KEY_new_by_curve_name(CURVE_ECDSA_P_256);
      if (ecdsa_key != NULL)
      {
        if (EC_POINT_oct2point(ecGroup, ecPointPublicKey, 
                               (const unsigned char*)asn1Buff, asn1Len, NULL))
        {
          if (EC_KEY_set_public_key(ecdsa_key, ecPointPublicKey))
          {             
            if (EC_KEY_check_key(ecdsa_key))
            {
              // HERE GO WILD AND GENERATE THE KEY
              bn_ctx    = BN_CTX_new();
              if (bn_ctx != NULL)
              {
                bLen = EC_POINT_point2oct(ecGroup, ecPointPublicKey,
                          POINT_CONVERSION_UNCOMPRESSED/*4*/ , NULL, 0, bn_ctx);
                if (bLen > 0)
                {
                  buff = OPENSSL_malloc(bLen);
                  if (buff != NULL)
                  {
                    if (EC_POINT_point2oct(ecGroup, ecPointPublicKey,
                             POINT_CONVERSION_UNCOMPRESSED , buff, bLen, bn_ctx)
                          != 0)
                    {
                      /* call generate DER form function */
                      key->keyData = _new_pub_ecpoint2Der(buff);
                      if (key->keyData != NULL)
                      {
                        key->keyLength = SIZE_DER_PUBKEY;
                      }
                      else
                      {
                        sca_debugLog(LOG_ERR, "+ [libcrypto] Could not generate the DER key!\n");                                                                           
                      }
                    }
                    OPENSSL_free(buff);
                    buff = NULL;
                  }
                  else
                  {
                    sca_debugLog(LOG_ERR, "+ [libcrypto] Not enough memory!\n");                                                    
                  }
                  bLen = 0;
                }
                else
                {
                  sca_debugLog(LOG_ERR, "+ [libcrypto] Faulty Point Conversions!\n");                                
                }
                BN_CTX_free(bn_ctx);
                bn_ctx = NULL;
              }
              else
              {
                sca_debugLog(LOG_ERR, "+ [libcrypto] Could not generate CTX.\n");                
              }
            }
            else
            {
              sca_debugLog(LOG_ERR, "+ [libcrypto] Public key check faulty\n");
            }
          }
        }
        // Clean up ecdsa_key, only needed to generate the public DER key
        EC_KEY_free(ecdsa_key);
        ecdsa_key = NULL;        
      }
      else
      { 
        sca_debugLog(LOG_ERR, "+ [libcrypto] Error creating a public ECDSA key!\n");
      }
      
      // The Point needs cleaning up
      EC_POINT_free(ecPointPublicKey);
      ecPointPublicKey = NULL;
    }
    else
    {
      sca_debugLog(LOG_ERR, "+ [libcrypto] Error creating ECDSA point!\n");              
    }

    // The EC_GROUP needs to be cleaned up
    EC_GROUP_free(ecGroup);
    ecGroup = NULL;
  }
  else
  {
    sca_debugLog(LOG_ERR, "+ [libcrypto] Error creating ECDSA group!\n");
  }
  
  return key->keyLength > 0;
}

/**
 * Load the public key into the BGPSecKey object.
 * 
 * @param fName The file name of the key certificate
 * @param key the key information itself
 * 
 * @return true if the key could be loaded, otherwise false.
 */
static bool _loadPubKey(char* fName, BGPSecKey* key)
{
  int      retVal    = false;
  BIO*     bio       = BIO_new(BIO_s_file());
  X509*    cert      = NULL;
  
  if (bio != NULL)
  {
    if (BIO_read_filename(bio, fName) > 0)
    {
      /* this is ASN.1 format */
      cert = X509_new();
      if (cert != NULL)
      {
        // Fill the cert
        cert = d2i_X509_bio(bio, &cert);        
      }
      if (cert != NULL) 
      {
        // Extract the public key in DER format from the certificate. It is 
        // successfull if key->keyLength > 0.
        _getPublicKey(cert, key, CURVE_ECDSA_P_256);        
        retVal = key->keyLength > 0;
        // The certificate needs to be cleaned up
        X509_free(cert);
        cert = NULL;
      }
      else
      { // ecdsa == NULL
        sca_debugLog(LOG_ERR, "+ [libcrypto] Error occurred while loading cert\n");
      }
    }
    else
    { // cert file could not be read 
      sca_debugLog(LOG_ERR, "+ [libcrypto] Unable to read the key from the bio\n");
    }
    // bio needs to be cleaned up
    BIO_free_all(bio);
    bio = NULL;    
  }
  else
  { // bio == NULL
    sca_debugLog(LOG_ERR, "+ [libcrypto] Unable to create BIO object\n");
  }
  
  // Clean the memory leaks.
  EVP_cleanup();
  ENGINE_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_remove_state(0);
  ERR_free_strings();
  
  return retVal;
}




/**
 * Load the key from the key volt location configured within the API. The key
 * needs the SKI specified in binary format.
 * The returned key is in DER format. The parameter fPrivate is used to
 * indicate if the private or public key will be returned. This is of importance
 * in case both keys exist. Both keys will have the same SKI.
 * 
 * This function uses OpenSSL to verify the correctness of the key itself.
 *
 * @param key Pre-allocated memory where the ley will be loaded into.
 * @param fPrivate indicates if the key is private or public.
 * @param fileExt The extension of the filename containing the key.
 *
 * @return LOAD_KEY_SUCCESS (1) if key was loaded successfully, 
 *         LOAD_KEY_FAILURE (0) otherwise
 */
int impl_loadKey(BGPSecKey* key, bool fPrivate, char* fileExt)
{
  int    retVal = API_LOADKEY_FAILURE;
  
  char   keyFileName[MAXPATHLEN];
  char*  ptr = NULL;
  bool   foundFile = false;
  bool   doTestKey = true;
  struct stat statbuf;

  // Initialize memory to prevent security issues
  memset(&keyFileName, 0, MAXPATHLEN);
  
  // PRoceed by determining the key/cert filename and if found, load it.
  if (sca_FindDirInSKI(keyFileName, MAXPATHLEN, key->ski))
  {
    int strLen = strlen(keyFileName);
    ptr = keyFileName + strLen;
    if (strLen+strlen(fileExt)+1 < MAXPATHLEN)
    {
      sprintf(ptr, ".%s", fileExt);
      foundFile = (stat(keyFileName, &statbuf) == 0);
    }
    
    if (foundFile)
    { // Now we can move on loading the key
      if (fPrivate)
      {
        if (_loadPrivKey(keyFileName, key, doTestKey))
        {
          retVal = API_LOADKEY_SUCCESS;
        }
      }
      else
      {
        // Load the public key in DER format.
        if (_loadPubKey(keyFileName, key))
        {
          retVal = API_LOADKEY_SUCCESS;
        }
      }
    }
    else
    {
      sca_debugLog(LOG_WARNING, "+ [libcrypto] Key file '%s' not found!\n", 
                                keyFileName);
    }
  }
  else
  {
    sca_debugLog(LOG_ERR, "+ [libcrypto] failed to access a file name from a ski\n");
  }
  
  return retVal;
}
