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
 * A wrapper for the OpenSSL crypto needed. It also includes a key storage.
 *
 * @version 0.2.0.0
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.0.0 - 2016/05/10 - oborchert
 *            * Fixed compiler warnings BZ950
 *  0.1.1.0 - 2016/03/28 - oborchert
 *            * Modified signature of preloadKeys to indicate what keys have to
 *              be loaded
 *          - 2016/03/22 - oborchert
 *            * Modified signature of function CRYPTO_createSignature by adding 
 *              the parameter testSig.
 *          - 2016/03/21 - oborchert
 *            * Fixed BZ891 missing signature if keys are already loaded and 
 *              checked.
 *          - 2016/03/08 - oborchert
 *            * Added error reporting when signing failed.
 *  0.1.0.0 - 2015/08/06 - oborchert
 *            * Created File.
 */
#include <stddef.h>
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <string.h>
#include <netdb.h>
#include <srx/srxcryptoapi.h>
#include "bgpsec/Crypto.h"

/**
 * This function will load the OpenSSL version EC_KEY of the DER encoded key.
 * 
 * @param asinfo The as key information object.
 */
static void _convertToOpenSSLKey(TASInfo* asinfo)
{
  if (asinfo->ec_key == NULL && asinfo->key.keyData != NULL)
  {
    EC_KEY*   ecdsa_key = NULL;
    size_t    ecdsa_key_int;
    char* p    = NULL;
    p = (char*)asinfo->key.keyData;

    if (asinfo->isPublic)
    {
      ecdsa_key_int = (size_t)d2i_EC_PUBKEY(NULL, (const unsigned char**)&p, 
                                            asinfo->key.keyLength);
      ecdsa_key = (EC_KEY*)ecdsa_key_int;

    }
    else
    {
      ecdsa_key = d2i_ECPrivateKey (NULL, (const unsigned char**)&p, 
                                    asinfo->key.keyLength);      
    }
    
    if (ecdsa_key != NULL)
    {
      if (EC_KEY_check_key(ecdsa_key))
      {
        asinfo->ec_key     = (u_int8_t*)ecdsa_key;
        asinfo->ec_key_len = ECDSA_size(ecdsa_key);
      }
      else
      {
        EC_KEY_free(ecdsa_key);
      }
    }
  }
}

/**
 * Create the message digest.
 *
 * @param message The message to be signed
 * @param length The message length in bytes
 * @param digestBuff The pre-allocated memory for the message digest. Must be
 *          >= SHA256_DIGEST_LENGTH
 * 
 * @return pointer to the given digestBuff or NULL in case of an error.
 */
unsigned char* createSha256Digest(const unsigned char* message, 
                                  unsigned int length, u_int8_t* digestBuff)
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

#ifdef DEBUG_SIGN
/**
 * performs openssl sign action
 *
 * @param digest char string in which message digest contained
 * @param digest_len message digest length
 * @param eckey_key is ECDSA key used for signing
 * @param signatureBuff The buffer where the signature is stored in
 * @param verifyToo verify after signing.
 *
 * @return signature length or 0
 */
int signECDSA (u_int8_t* digest, int digest_len, EC_KEY* ecdsa_key, 
               u_int8_t* signatureBuff, bool verifyToo)
{
  int len = sprintf((char*)signatureBuff, "Hello");
  return len;
}

#else

/**
 * performs openssl sign action
 *
 * @param digest char string in which message digest contained
 * @param digest_len message digest length
 * @param eckey_key is ECDSA key used for signing
 * @param signatureBuff The buffer where the signature is stored in
 * @param verifyToo verify after signing.
 *
 * @return signature length or 0
 */
int signECDSA (u_int8_t* digest, int digest_len, EC_KEY* ecdsa_key, 
               u_int8_t* signatureBuff, bool verifyToo)
{
  unsigned int sig_len;
  
  sig_len = ECDSA_size(ecdsa_key);
  
  if (ECDSA_sign(0, digest, digest_len, signatureBuff, &sig_len, ecdsa_key))
  {
    if (verifyToo)
    {
      /* verify the signature */
      if (ECDSA_verify(0, digest, digest_len, signatureBuff, sig_len, ecdsa_key) 
          != 1)
      {
        printf("ERROR: Could not verify the just created signature!\n");
        sig_len = 0;
      }
    }
  }
  else
  {
    printf("ERROR: Error signing '%s'!\n", ERR_error_string(ERR_get_error(), 
           NULL));
    sig_len = 0;
  }
  
  return sig_len;
}

#endif // DEBUG_SIGN

///////////////////////////////////////
/**
 * Create the signature from the given hash for the ASN. The given signature 
 * must be NULL. The return value is the signature in a memory allocated into 
 * signature with the size given in the return value.
 * 
 * @param asList The list of as numbers - Contains all keys etc.
 * @param segElem The signature element where the signature will be stored in.
 * @param message The buffer containing the message to be signed.
 * @param len The length of the message in host format.
 * @param algoID  Specifies the algorithm to be used for signing.
 * @param testSig If true the generated signature is validated right away. This
 *                is for test purpose only.
 * 
 * @return 0 if the signature could not be generated, otherwise the length of 
 *         the signature in host format
 */
int CRYPTO_createSignature(TASList* asList, tPSegList* segElem, 
                           u_int8_t* message, int len, int algoID, bool testSig)
{
  if (segElem->signature != NULL)
  {
    return 0;
  }
  // Temporary space for the generated message digest (hash)
  u_int8_t messageDigest[SHA256_DIGEST_LENGTH];
  // Temporary space to hold the signature.
  u_int8_t sigBuff[BGPSEC_MAX_SIG_LENGTH];
      
  // Load the private Key
  if (segElem->asInfo == NULL)
  {
    segElem->asInfo = getListInfo(asList, segElem->spSeg->asn, algoID, true);
    if (segElem->asInfo == NULL)
    {
      return 0;
    }
  }
  
  bool checkNeeded = false;
  if (segElem->asInfo->ec_key == NULL)
  {
    // EC_KEY was not generated, generate it now.
    _convertToOpenSSLKey(segElem->asInfo);
    checkNeeded = true;
  }
  EC_KEY*    ecdsa_key = (EC_KEY*)segElem->asInfo->ec_key;
  int sigLen = 0;
  // Used later, only sign with an OK key (Fix of BZ891)
  bool key_ok = !checkNeeded;
  
  if (checkNeeded)
  {
    if (EC_KEY_check_key(ecdsa_key)) 
    {
      key_ok = true;
    }
    else
    {
      printf ("ERROR: Key for ASN %u failed check!\n", segElem->asInfo->key.asn);
    }
  }
  
  if (key_ok)
  {
    // Generate the hash (messageDigest that will be signed.)
    createSha256Digest (message, len, (u_int8_t*)&messageDigest);
    // Sign the data
    sigLen = signECDSA ((u_int8_t*)&messageDigest, SHA256_DIGEST_LENGTH, 
                        ecdsa_key, (u_int8_t*)&sigBuff, testSig);
    if (sigLen > 0)
    {
      segElem->sigLen = (u_int8_t)sigLen;
      segElem->signature = malloc(sigLen);
      memcpy(segElem->signature, sigBuff, sigLen);
    }           
  }
    
  return sigLen;
}

/**
 * Read the given ASN-SKI file and generate an internal list containing all 
 * entries including the keys.
 * 
 * @param fileName The key-loader filename of the ASN-SKI list
 * @param keyRoot The root of the key files.
 * @param addEC_KEY if true the EC_KEY will be generated as well.
 * @param keytype indicated if the keys loaded are private, public or both keys
 * 
* @return the AS list with the keys or NULL if the keyloader ASN_SKI could not
 *         be found.
  */
TASList* preloadKeys(char* fileName, char* keyRoot, bool addEC_KEY, 
                     u_int8_t algoID, T_Key keytype)
{
  // First load the list of AS SKi's.
  TASList* asList = NULL;
  int noKeys = 0;
  int noFailed = 0;
  
  if (fileName != NULL && keyRoot != NULL)
  {
    sca_SetKeyPath(keyRoot);
    bool loadPubKey  = (keytype != k_private); // will be set id public or both
    bool loadPrivKey = (keytype != k_public); // will be set id private or both

    asList = loadAS_SKI(fileName, asList, algoID, loadPubKey, loadPrivKey);    

    if (asList != NULL)
    {
      // Now load the keys.
      ListElem* ptr    = asList->head;
      TASInfo*  asinfo = NULL;
      while (ptr != NULL)
      {
        //Maybe that can be created already during the list generation.
        asinfo = (TASInfo*)ptr->elem;
        noKeys++;
        // use !isPublic because loadkey asks for private and private != public
        sca_status_t status;
        if (!sca_loadKey(&asinfo->key, !asinfo->isPublic, &status))
        {
          noFailed++;
          asinfo->key.keyLength = 0;
          asinfo->key.keyData = NULL;
        }
        else
        {
          if (addEC_KEY)
          {
            // The ECDSA Portion is memory intense. 
            _convertToOpenSSLKey(asinfo);
          }
        }
        ptr = ptr->next;
      }
    }
  }
  
  if (noFailed > 0)
  {
    printf("ERROR: %d/%d keys not loaded!\n", noFailed, noKeys);
  }
  
  return asList;
}
