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
 * This software might use libraries that are under GNU public license or
 * other licenses. Please refer to the licenses of all libraries required
 * by this software.
 *
 * A wrapper for the OpenSSL crypto needed. It also includes a key storage.
 *
 * @version 0.2.0.5
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.0.5 - 2016/12/28 - oborchert
 *            * Modified newly added code to use newly added configuration 
 *              settings
 *          - 2016/12/28 - Antara Teknik
 *            * Added customixed OpenSSL code fragments that allow specification
 *              of "k" for ECDSA signing.
 *          - 2016/11/21 - oborchert
 *            * Renamed internal methods using _ as initial character.
 *            * Restructured the usage of DEBUG_SIGN definition
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
#include <openssl/bn.h>
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
static unsigned char* _createSha256Digest(const unsigned char* message, 
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

int fixed_k_ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                             BIGNUM **rp, SignatureGenMode k_mode)
{
  BN_CTX *ctx = NULL;
  BIGNUM *k = NULL, *r = NULL, *order = NULL, *X = NULL;
  EC_POINT *tmp_point = NULL;
  const EC_GROUP *group;
  int ret = 0;

  //fixed k
//  unsigned char nist_p256_rfc6979_A_2_5_SHA256_k_sample[] = {
//    0xA6, 0xE3, 0xC5, 0x7D, 0xD0, 0x1A, 0xBE, 0x90, 
//    0x08, 0x65, 0x38, 0x39, 0x83, 0x55, 0xDD, 0x4C, 
//    0x3B, 0x17, 0xAA, 0x87, 0x33, 0x82, 0xB0, 0xF2, 
//    0x4D, 0x61, 0x29, 0x49, 0x3D, 0x8A, 0xAD, 0x60};

  unsigned char nist_p256_rfc6979_A_2_5_SHA256_k_test[] = {
    0xD1, 0x6B, 0x6A, 0xE8, 0x27, 0xF1, 0x71, 0x75, 
    0xE0, 0x40, 0x87, 0x1A, 0x1C, 0x7E, 0xC3, 0x50, 
    0x01, 0x92, 0xC4, 0xC9, 0x26, 0x77, 0x33, 0x6E, 
    0xC2, 0x53, 0x7A, 0xCA, 0xEE, 0x00, 0x08, 0xE0};

  unsigned char nist_p256_rfc6979_A_2_5_SHA256_k_sample[] = {
    0x58, 0x0e, 0xc0, 0x0d, 0x85, 0x64, 0x34, 0x33,
    0x4c, 0xef, 0x3f, 0x71, 0xec, 0xae, 0xd4, 0x96,
    0x5b, 0x12, 0xae, 0x37, 0xfa, 0x47, 0x05, 0x5b,
    0x19, 0x65, 0xc7, 0xb1, 0x34, 0xee, 0x45, 0xd0};
  
  unsigned char* nist_p256_testvec_k = NULL;
  
  switch (k_mode)
  {
    case SM_BIO_K1:  // SM_BIO_K1_STR
      nist_p256_testvec_k = nist_p256_rfc6979_A_2_5_SHA256_k_sample;
      break;
    case SM_BIO_K2:  // SM_BIO_K2_STR
      nist_p256_testvec_k = nist_p256_rfc6979_A_2_5_SHA256_k_test;
      break;
    default:
      return 0;
  }
                            
  if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL) 
  {
      ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_PASSED_NULL_PARAMETER);
      return 0;
  }

  if (ctx_in == NULL) 
  {
    if ((ctx = BN_CTX_new()) == NULL) 
    {
      ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_MALLOC_FAILURE);
      return 0;
    }
  } 
  else
  {
    ctx = ctx_in;
  }

  k = BN_new();               /* this value is later returned in *kinvp */
  r = BN_new();               /* this value is later returned in *rp */
  order = BN_new();
  X = BN_new();
  if (!k || !r || !order || !X) 
  {
      ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_MALLOC_FAILURE);
      goto err;
  }
  if ((tmp_point = EC_POINT_new(group)) == NULL) 
  {
      ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
      goto err;
  }
  if (!EC_GROUP_get_order(group, order, ctx)) 
  {
      ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
      goto err;
  }

  do 
  {
      /* get random k */
/*    do
        if (!BN_rand_range(k, order)) 
        {
          ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP,
                   ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED);
          goto err;
        }
      while (BN_is_zero(k)) ;
*/

    //set fixed random number
    (void) BN_bin2bn((const unsigned char *)nist_p256_testvec_k, 32, k);
	
    /*
     * We do not want timing information to leak the length of k, so we
     * compute G*k using an equivalent scalar of fixed bit-length.
     */

    if (!BN_add(k, k, order))
    {
        goto err;
    }
    if (BN_num_bits(k) <= BN_num_bits(order))
    {      
      if (!BN_add(k, k, order))
      {
        goto err;
      }
    }

    /* compute r the x-coordinate of generator * k */
    if (!EC_POINT_mul(group, tmp_point, k, NULL, NULL, ctx)) 
    {
        ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
        goto err;
    }
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
        NID_X9_62_prime_field) 
    {
      if (!EC_POINT_get_affine_coordinates_GFp
          (group, tmp_point, X, NULL, ctx)) 
      {
        ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
        goto err;
      }
    }
#ifndef OPENSSL_NO_EC2M
    else 
    {                  /* NID_X9_62_characteristic_two_field */
      if (!EC_POINT_get_affine_coordinates_GF2m(group,
                                                tmp_point, X, NULL,
                                                ctx)) 
      {
        ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
        goto err;
      }
    }
#endif
    if (!BN_nnmod(r, X, order, ctx)) 
    {
      ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
      goto err;
    }
  }
  while (BN_is_zero(r));

  /* compute the inverse of k */
/*  if (EC_GROUP_get_mont_data(group) != NULL) 
  {
    //
    // * We want inverse in constant time, therefore we utilize the fact
    // * order must be prime and use Fermats Little Theorem instead.
    // *
    if (!BN_set_word(X, 2)) 
    {
      ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
      goto err;
    }
    if (!BN_mod_sub(X, order, X, order, ctx)) 
    {
      ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
      goto err;
    }
    BN_set_flags(X, BN_FLG_CONSTTIME);
    if (!BN_mod_exp_mont_consttime
          (k, k, X, order, ctx, EC_GROUP_get_mont_data(group))) 
    {
      ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
      goto err;
    }
  } 
  else
*/  {
    if (!BN_mod_inverse(k, k, order, ctx)) 
    {
      ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
      goto err;
    }
  }

  /* clear old values if necessary */
  if (*rp != NULL)
  {
    BN_clear_free(*rp);
  }
  if (*kinvp != NULL)
  {
    BN_clear_free(*kinvp);
  }
  /* save the pre-computed values  */
  *rp = r;
  *kinvp = k;
  ret = 1;
err:
  if (!ret) 
  {
    if (k != NULL)
    {
      BN_clear_free(k);
    }
    if (r != NULL)
    {
      BN_clear_free(r);
    }
  }
  if (ctx_in == NULL)
  {
    BN_CTX_free(ctx);
  }
  if (order != NULL)
  {
    BN_free(order);
  }
  if (tmp_point != NULL)
  {
    EC_POINT_free(tmp_point);
  }
  if (X)
  {
    BN_clear_free(X);
  }

  return (ret);
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
 * @param k_mode Specifies if a random k (preferred) or a specified k has to be 
 *        used.
 *
 * @return signature length or 0
 */
static int _signECDSA (u_int8_t* digest, int digest_len, EC_KEY* ecdsa_key, 
                      u_int8_t* signatureBuff, bool verifyToo, 
                      SignatureGenMode k_mode)
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
 * @param k_mode Specifies if a random k (preferred) or a specified k has to be 
 *        used.
 *
 * @return signature length or 0
 */
static int _signECDSA (u_int8_t* digest, int digest_len, EC_KEY* ecdsa_key, 
                      u_int8_t* signatureBuff, bool verifyToo, 
                      SignatureGenMode k_mode)
{
  unsigned int sig_len;

  sig_len = ECDSA_size(ecdsa_key);
  
  if (k_mode == SM_BIO)
  {  
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
  }
  else
  {
    // Added to allow signing with a custom k
    BIGNUM *kinvp = NULL;
    BIGNUM *rp = NULL;

    kinvp = BN_new();               /* this value is later returned in *kinvp */
    rp = BN_new(); 

    if (!kinvp || !rp ) 
    {
      ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_MALLOC_FAILURE);
      sig_len = 0;
      goto exit;
    }
    // Computing fixedk_kinv!
    if (!fixed_k_ecdsa_sign_setup(ecdsa_key, NULL, &kinvp, &rp, k_mode))
    {
      printf("ERROR: Could not compute fixedk_kinv!\n");
      sig_len = 0;
      goto exit;
    }

    // Executing ECDSA_Sign with precomputed kinv
    if (ECDSA_sign_ex(0, digest, digest_len, signatureBuff, &sig_len, kinvp, rp, 
                      ecdsa_key))
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

  exit:
    if (kinvp != NULL)
    {
      BN_clear_free(kinvp);
    }
    if (rp != NULL)
    {
      BN_clear_free(rp);
    }
  }
  
  return sig_len;
}

#endif // DEBUG_SIGN

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
 * @param k_mode  Specifies if a random k (preferred) or s specified k has to be 
 *                used.
 * 
 * @return 0 if the signature could not be generated, otherwise the length of 
 *         the signature in host format
 */
int CRYPTO_createSignature(TASList* asList, tPSegList* segElem, 
                           u_int8_t* message, int len, int algoID, 
                           bool testSig, SignatureGenMode k_mode)
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
    _createSha256Digest (message, len, (u_int8_t*)&messageDigest);
    // Sign the data
/*    printf ("Digest: ");
    printHex(messageDigest, SHA224_DIGEST_LENGTH, "        ");
    printf ("k-mode: ");
    switch (k_mode)
    {
      case SM_CAPI:
        printf ("CAPI\n");
        break;
      case SM_BIO:
        printf("BIO\n");
        break;
      case SM_BIO_K1:
        printf("BIO-K1\n");
        break;
      case SM_BIO_K2:
        printf("BIO-K2\n");
        break;
      default:
        printf ("???\n");            
    }
*/
    sigLen = _signECDSA ((u_int8_t*)&messageDigest, SHA256_DIGEST_LENGTH, 
                        ecdsa_key, (u_int8_t*)&sigBuff, testSig, k_mode);
    if (sigLen > 0)
    {
      segElem->sigLen = (u_int8_t)sigLen;
      segElem->signature = malloc(sigLen);
      memset(segElem->signature, 0, sigLen);
      memcpy(segElem->signature, sigBuff, sigLen);
      
//      printf("Signature: ");      
//      printHex(segElem->signature, sigLen, "           ");
    }           
  }
    
  return sigLen;
}

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
int CAPI_createSignature(TASList* asList, tPSegList* segElem, 
                         u_int8_t* message, int len, int algoID, bool testSig, 
                         SignatureGenMode k_mode)
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
    _createSha256Digest (message, len, (u_int8_t*)&messageDigest);
    // Sign the data
    
    printf ("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
    printf ("HERE CALL CAPI\n");
//    sigLen = _signECDSA ((u_int8_t*)&messageDigest, SHA256_DIGEST_LENGTH, 
//                         ecdsa_key, (u_int8_t*)&sigBuff, testSig);
    printf ("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
    
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
