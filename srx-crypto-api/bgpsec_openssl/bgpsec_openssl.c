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
 * This plugin provides an OpenSSL ECDSA implementation for BGPSEC.
 *
 * @version 0.1.3.0
 *
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *   0.1.3.0 - 2016/04/29 - oborchert
 *             * Additional modification in ERROR reporting as well as 
 *               logging of results.
 *           - 2016/04/28 - kyehwanl
 *             * Modified reporting of ERROR, SUCCESS and FAILURE during 
 *               validation
 *   0.1.2.1 - 2016/03/11 - kyehwanl
 *             * Complement ExtBgpsecVerify function with using pubkey ids
 *           - 2016/02/09 - oborchert
 *             * Removed key loading functions, code is provided by srxcryptoapi
 *           - 2016/02/04 - kyehwanl
 *             * deprecated codes removed
 *           - 2016/02/02 - borchert
 *             * Added init method.
 *   0.1.2.0 - 2016/01/05 - kyehwanl
 *             * Provide extValidate function
 *           - 2016/01/04 - oborchert
 *             * Changed return value if isExtended from 1 to 0
 *           - 2015/12/03 - oborchert
 *             * Fixed location of bgpsec_openssl.h
 *           - 2015/09/25 - oborchert
 *             * Resolved compiler warnings.
 *           - 2015/09/22 - oborchert
 *             * Added ChangeLog to file.
 *   0.1.0.0 - 2015 - kyehwanl
 *             * Created File.
 */
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <stdbool.h>


/* general API header which will be public to the customer side */
#include "bgpsec_openssl.h"

Record_t *g_records = NULL;
Record_t *g_records_pub = NULL;
struct Enbuf_Eckey_t
{
  void  *en_buf;
  void  *ec_key;
  int   id;
};
static struct Enbuf_Eckey_t  stEnbuf_Eckey[ID_NUM_MAX];

/* global variable for containing strings which indicates the key location */

// Foward declaration
int cl_SignParamWithKeySanityCheck(BGPSecSignData *signData, BGPSecKey *key);
int cl_SignParamWithIDSanityCheck(BGPSecSignData *signData, u_int8_t keyID);
void PrintPrivPubKeyHex(EC_KEY* ec_key);
Record_t* restoreKeyInfo(bool fPrivate, u_int8_t* ski, u_int32_t asn);
static inline void put_u32(void *p, u_int32_t x) {
  x = htonl(x); memcpy(p, &x, 4); }


/**
 * Compare both given SKI Arrays. The arrays MUST be of lendth SKI_LENGTH.
 *
 * @param arr1 The first array to compare
 * @param arr2 The second array to compare.
 *
 * @return true if the arrays contain the same byte information,
 *              otherwise false.
 */
static bool cmpSKI(u_int8_t* arr1, u_int8_t* arr2)
{
  bool retVal = true;
  int idx = 0;
  for (idx = 0; idx < SKI_LENGTH; idx++)
  {
    if (arr1[idx] != arr2[idx])
    {
      retVal = false;
      break;
    }
  }
  return retVal;
}

/**
 * call openssl verify function
 *
 * @param digest: char string in which message digest contained
 * @param digest_len: message digest length
 * @param eckey_nistp256 is ECDSA key used for verification
 * @param signature: input resource for verification
 * @param signature_len: signature length
 *
 * @return status sucess  (API_BGPSEC_VERIFY_SUCCESS == 1), 
 *                failure (API_BGPSEC_VERIFY_FAILURE == 0)
 *                error   (API_BGPSEC_VERIFY_ERROR   == -1)
 */

int cl_BgpsecDoVerifySignature (u_int8_t *digest, int digest_len,
                                EC_KEY    *eckey_nistp256,
                                u_int8_t *signature, int signature_len)
{
  if (IS_DEBUG_ENABLED)
  {
    sca_debugLog(LOG_DEBUG, "Received signature: 0x:");
    printHex(signature_len, (unsigned char*)signature);
  }

  // return  1 (== API_BGPSEC_VERIFY_SUCCESS) if the signature is valid, 
  // return  0 (== API_BGPSEC_VERIFY_FAILURE) if the signature is invalid
  // return -1 (== API_BGPSEC_VERIFY_ERROR)   on error 
  int status = ECDSA_verify(0, digest, digest_len, signature, signature_len, 
                            eckey_nistp256);
  if (status == API_BGPSEC_VERIFY_ERROR)
  {
    sca_debugLog(LOG_ERR, " + [libcrypto] ECDSA_verify failure: %s\n", 
                 ERR_error_string(ERR_get_error(), NULL));
    ERR_print_errors_fp(stderr);
  }
  
  return status;
}




/**
 * same with stcl_BgpsecVerifySignatureSSL function except this one uses key information
 *
 * @param sslVerifyData: BGPSecSignData strucutre
 * @param keys: used as a container which include key info
 * @param keyCnt: the number of keys
 *
 * @return status sucess(API_BGPSEC_VERIFY_SUCCESS), failure(API_BGPSEC_VERIFY_FAILURE),
 *          error(API_BGPSEC_VERIFY_ERROR)
 */
int stcl_BgpsecVerifySignatureSSL_withKeyInfo (BGPSecSignData* sslVerifyData,
                BGPSecKey** keys, u_int16_t keyCnt)
{
    EC_KEY  *ecdsa_key=NULL;
    int status = API_BGPSEC_VERIFY_ERROR;
    int bDerPrivate=0;
    int retType=0;
    unsigned char *p = NULL;

    /* insert one of keys into EC_KEY pointer */
    if(keys && keys[keyCnt])
    {
      p = keys[keyCnt]->keyData;
      if(!p)
      {
        sca_debugLog(LOG_ERR, "keyData is NULL, verification cancel\n");
        goto err_cleanup;
      }

      /* determine whether the given key is DER or not and private or public */
      retType = IS_DER_PRIVATE(p, keys[keyCnt]->keyLength);
      if(retType == 1)
      {
        bDerPrivate = 1;
        sca_debugLog(LOG_INFO, "[%s:%d] Private key in DER\n", __FUNCTION__, __LINE__);
      }
      else if(retType == 0)
        sca_debugLog(LOG_INFO, "[%s:%d] Public key in DER\n", __FUNCTION__, __LINE__);
      else if(retType < 0)
        sca_debugLog(LOG_INFO, "[%s:%d] key is not DER format \n", __FUNCTION__, __LINE__);

      /* convert DER to Internal */
      BIO *out_err = BIO_new_fp(stderr, BIO_NOCLOSE);

      if(bDerPrivate)
      {
        ecdsa_key = d2i_ECPrivateKey(NULL, (const unsigned char**)&p, keys[keyCnt]->keyLength);
        if (!ecdsa_key )
        {
          ECerr(EC_F_ECKEY_PRIV_DECODE, EC_R_DECODE_ERROR);
          ERR_print_errors(out_err);
          sca_debugLog(LOG_ERR, " EC priv key failed \n");
          goto err_cleanup;
        }
      }
      else
      {
        EVP_PKEY *pkey_tmp;
        int eplen = keys[keyCnt]->keyLength;

        /* We have parameters now set public key */
        pkey_tmp = d2i_PUBKEY(NULL, (const unsigned char**)&p, eplen);
        if (!pkey_tmp)
        {
          ECerr(EC_F_ECKEY_PUB_DECODE, EC_R_DECODE_ERROR);
          ERR_print_errors(out_err);
          sca_debugLog(LOG_ERR, " PUBKEY pub key failed \n");
          goto err_cleanup;
        }

        ecdsa_key = EVP_PKEY_get1_EC_KEY(pkey_tmp);
        EVP_PKEY_free(pkey_tmp);

        if(ecdsa_key == NULL)
        {
          sca_debugLog(LOG_ERR, " fail to create a new eckey from EVP_PKEY \n");
          goto err_cleanup;
        }

      }

      /* check public key */
      if(EC_KEY_get0_public_key(ecdsa_key) == NULL)
      {
        ECerr(EC_F_ECKEY_PUB_DECODE, ERR_R_EC_LIB);
        sca_debugLog(LOG_ERR, "EC_KEY_get0_public_key failed \n");
        goto err_cleanup;
      }
    }
    else
      goto err_cleanup;

    /* check validity of ec key */
    if (!EC_KEY_check_key(ecdsa_key)) {
      status = API_BGPSEC_VERIFY_ERROR;
      sca_debugLog(LOG_ERR, "+ [libcrypto] EC_KEY_check failed: EC key check error \
          [current num:%d, ski:%02x, ASN:%d] \n",\
          keyCnt, *keys[keyCnt]->ski, keys[keyCnt]->asn);
      goto err_cleanup;
    }

    sca_debugLog(LOG_INFO, "+ [%s:%d] EC_KEY_check [Current Num:%d, ski:%02x, ASN:%d] --- OK \n",
        __FUNCTION__, __LINE__, keyCnt, *keys[keyCnt]->ski, keys[keyCnt]->asn);

    /* message digest and verification */
    unsigned char md[SHA256_DIGEST_LENGTH];
    cl_BgpsecOctetDigest(sslVerifyData->data, sslVerifyData->dataLength, md);
    status = cl_BgpsecDoVerifySignature (md, SHA256_DIGEST_LENGTH,
                                       ecdsa_key,
                                       sslVerifyData->signature,
                                       sslVerifyData->sigLen);

    if (status == API_BGPSEC_VERIFY_ERROR)
    {
      sca_debugLog(LOG_ERR, "+ [libcrypto] error at verifying\n");
    }
    // Removed goto stuff because it happens anyhow.

err_cleanup:
    // openssl cleanup
    if (ecdsa_key) EC_KEY_free(ecdsa_key);
    //
    // CRYPTO_cleanup_all_ex_data();
    // ERR_free_strings();
    // ERR_remove_state(0);
    return status;
}

/**
 * performs openssl sign action
 *
 * @param digest: char string in which message digest contained
 * @param digest_len: message digest length
 * @param eckey_key is ECDSA key used for signing
 * @param signature: output resource for singing
 * @param signature_len: signature length
 *
 * @return signature length or -1
 */
int cl_BgpsecECDSA_Sign (u_int8_t *digest, int digest_len,
                               EC_KEY    *ecdsa_key,
                               u_int8_t *signature, int *pSignature_len)
{

  int length=0;
  unsigned int sig_len;
  BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);

  sig_len = ECDSA_size(ecdsa_key);

  sca_debugLog(LOG_INFO, " + [libcrypto] sig length: %d \n", sig_len);

  if(ECDSA_sign(0, digest, digest_len, signature, &sig_len, ecdsa_key) != 1)
  {
    /* error */
    sca_debugLog(LOG_ERR, "+ [libcrypto] ECDSA_sing error: %s\n", \
        ERR_error_string(ERR_get_error(), NULL));
    ERR_print_errors_fp(stderr);
    goto int_err;
  }

  length = sig_len;
  *pSignature_len = sig_len;

  if (IS_DEBUG_ENABLED)
  {
    sca_debugLog(LOG_DEBUG,"Genereated Signatgure: 0x:");
    printHex(sig_len, (unsigned char*)signature);
  }

  /* verify the signature */
  if (ECDSA_verify(0, digest, digest_len, signature, sig_len, ecdsa_key) != 1)
    goto int_err;

  return length;

int_err:
  if (!length)
  {
    BIO_printf(out, " failed\n");
    sca_debugLog(LOG_ERR, " + [libcrypto] Error at signing\n");
  }
  if (ecdsa_key)
    EC_KEY_free(ecdsa_key);
  return length;
}




/**
 * Signing requrest combined with getting key function
 *
 * @param sslSignData: BGPSecSignData strucutre contains info required sining
 * @param bgpsecKey: BGPSec strucutre contains key info
 *
 * @return signature length or -1
 */
int static stBgpsecReqSigningWithKeyInfo(BGPSecSignData *sslSignData, BGPSecKey  *bgpsecKey)
{
  int ret=0;
  if(cl_SignParamWithKeySanityCheck(sslSignData, bgpsecKey) != 0)
  {
    sca_debugLog(LOG_ERR,"%s:[OUT] bgpsec Sign data or Key data structure error\n", __FUNCTION__);
    return API_BGPSEC_VERIFY_ERROR;
  }

  EC_KEY    *ecdsa_key;
  unsigned char *p = NULL;
  p = bgpsecKey->keyData;

  ecdsa_key = d2i_ECPrivateKey(NULL, (const unsigned char**)&p, bgpsecKey->keyLength);

  if (IS_DEBUG_ENABLED)
  PrintPrivPubKeyHex(ecdsa_key);

  sca_debugLog(LOG_INFO, "+ [libcrypto] [%s:%d] ec key:%p\n", __FUNCTION__, __LINE__, bgpsecKey->keyData);


  if (!EC_KEY_check_key(ecdsa_key)) {
        sca_debugLog(LOG_ERR, "+ [libcrypto][%s] EC_KEY_check failed: EC key check error\n", __FUNCTION__);
        goto int_err;
  }

  sca_debugLog(LOG_INFO, "+ [libcrypto] [%s] successfully finished to load bgpsec load key\n", __FUNCTION__);

  if (IS_DEBUG_ENABLED)
  {
    unsigned char *p=sslSignData->data;
    sca_debugLog(LOG_DEBUG,"+ [libcrypto] ---- HASH being sent [total length: %d] ----\n",
        sslSignData->dataLength);

    printHex(sslSignData->dataLength, p);
  }

  unsigned char md[SHA256_DIGEST_LENGTH];
      cl_BgpsecOctetDigest(sslSignData->data, sslSignData->dataLength, md);

      ret = cl_BgpsecECDSA_Sign (md, SHA256_DIGEST_LENGTH, ecdsa_key,
      sslSignData->signature, (int*)&sslSignData->sigLen);

  if (ecdsa_key) EC_KEY_free(ecdsa_key);

  if(ret > 0 && ret <= 72) // 72: possible max lentgh of signature length
    return API_BGPSEC_VERIFY_SUCCESS;
  else
    return API_BGPSEC_VERIFY_FAILURE;

// openssl cleanup
int_err:
  //if (ecdsa_key) EC_KEY_free(ecdsa_key);
  //
  // CRYPTO_cleanup_all_ex_data();
  // ERR_free_strings();
  // ERR_remove_state(0);
  return API_BGPSEC_VERIFY_ERROR;
}


/**
 * Signing requrest combined with id info
 *
 * @param sslSignData: BGPSecSignData strucutre contains info required sining
 * @param inID: used as an identifier for key instance
 *
 * @return signature length or -1
 */
int stBgpsecReqSigningWithID(BGPSecSignData *sslSignData, u_int8_t inID)
{
  int ret=0;
  u_int8_t keyID=0;
  EC_KEY    *ecdsa_key = NULL;

  if(cl_SignParamWithIDSanityCheck(sslSignData, inID) != 0)
  {
    sca_debugLog(LOG_ERR,"%s:[OUT] bgpsec Sign data or key ID data error\n", __FUNCTION__);
    return API_BGPSEC_VERIFY_ERROR;
  }

  keyID = inID - RET_ID_OFFSET;

  /* keyID need to have bound checking regarding to stEnbuf_Eckey */
  if(keyID > ID_NUM_MAX-1 || keyID < 0 )
  {
    sca_debugLog(LOG_INFO, "+ [libcrypto] key ID(%x) bound error \n", keyID);
    goto int_err;
  }

  /* retrieve eckey from key id */
  sca_debugLog(LOG_INFO, "+ [libcrypto] key ID:%x \n", keyID);
  ecdsa_key = stEnbuf_Eckey[keyID].ec_key;

  sca_debugLog(LOG_INFO, "+ [libcrypto] [%s:%d] ec key:%p\n", __FUNCTION__, __LINE__, ecdsa_key);

  if (!EC_KEY_check_key(ecdsa_key)) {
        sca_debugLog(LOG_ERR, "+ [libcrypto][%s] EC_KEY_check failed: EC key check error\n", __FUNCTION__);
        goto int_err;
  }

  sca_debugLog(LOG_INFO, "+ [libcrypto] [%s] successfully finished to load bgpsec load key\n", __FUNCTION__);

  if (IS_DEBUG_ENABLED)
  {
    unsigned char *p=sslSignData->data;
    sca_debugLog(LOG_DEBUG,"+ [libcrypto] ---- HASH being sent [total length: %d] ----\n",
        sslSignData->dataLength);

    printHex(sslSignData->dataLength, p);
  }


  unsigned char md[SHA256_DIGEST_LENGTH];
      cl_BgpsecOctetDigest(sslSignData->data, sslSignData->dataLength, md);

      ret = cl_BgpsecECDSA_Sign (md, SHA256_DIGEST_LENGTH, ecdsa_key,
      sslSignData->signature, (int*)&sslSignData->sigLen);

  if(ret > 0 && ret <= 72) // 72: possible max lentgh of signature length
    return API_BGPSEC_VERIFY_SUCCESS;
  else
    return API_BGPSEC_VERIFY_FAILURE;

// openssl cleanup
int_err:
  return API_BGPSEC_VERIFY_ERROR;

}


/**
 * verifies the received bgpsec path attribute with keys
 *
 * @param bpa : bgpsec path attribute info
 * @param number_keys: the number of keys given
 * @param keys: provied public keys for verification
 * @param prefix: additional information for NLRI
 * @param local_as:  additional information for NLRI
 *
 * @return on success with API_BGPSEC_VERIFY_SUCCESS or on failure(invalid) with API_BGPSEC_VERIFY_FAILURE
 *          on error with API_BGPSEC_VERIFY_ERROR
 */
int cl_BgpsecVerify (BgpsecPathAttr *bpa, u_int16_t number_keys, BGPSecKey** keys,
                    void *prefix, u_int32_t local_as)
{
  if(cl_BgpsecSanityCheck(bpa) != 0)
  {
    sca_debugLog(LOG_ERR,"%s:[OUT] bgpsec Path Attr structure error\n", __FUNCTION__);
    return API_BGPSEC_VERIFY_ERROR;
  }

  int status = API_BGPSEC_VERIFY_ERROR;
  PathSegment   *seg = bpa->pathSegments;
  SigBlock      *sb = bpa->sigBlocks;
  SigSegment    *ss = sb->sigSegments;

  struct prefix *p=(struct prefix *)prefix;
  int currNum =0;

  u_int8_t hashbuff[BGPSEC_MAX_SIG_LENGTH + 10 + BGPSEC_AFI_LENGTH];
  size_t hashLen = 0;

  u_short iter;
  int numSecurePathSegment = 0;

  /* Secure_Path length includes two octets used to express its own length field */
  iter = numSecurePathSegment =
    (bpa->securePathLen - OCTET_SECURE_PATH_LEN) / OCTET_SECURE_PATH_SEGMENT;

  /* Validation Routine */
  as_t targetAS = local_as;

  BGPSecSignData sslVerifyData = {
    .data           = hashbuff,
    .dataLength     = sizeof(hashbuff),
    .signature      = NULL,
    .sigLen         = 0,
  };

  while(iter && seg && sb && ss)
  {
    /* encapsulated and stacked at least 2 and more segments */
    if(iter > 1)
    {
      /*  #### hashbuff generation (transit) ####
       * +-----------------------------------------+
       * | Target AS Number               4 octets |
       * +-----------------------------------------+
       * | Signer's AS Number             4 octets |
       * +-----------------------------------------+
       * | pCount                         1 octet  |
       * +-----------------------------------------+
       * | Flags                          1 octet  |
       * +-----------------------------------------+
       * | Sig Field in the Next Segment (variable)|
       * +-----------------------------------------+
       */

      /* release temporary allocated pointer if it was allocated by sca_generateMSG
       * in srxcryptoapi */
      if(sslVerifyData.data != hashbuff && sslVerifyData.data)
        free(sslVerifyData.data);

      sslVerifyData.data           = hashbuff;
      sslVerifyData.dataLength     = sizeof(hashbuff);
      sslVerifyData.signature      = ss->signature;
      sslVerifyData.sigLen         = ss->sigLen;

      if(!ss->next)
      {
        sca_debugLog(LOG_ERR,"Error: bad segment arrangement, ignoring\n", __FUNCTION__);
        return API_BGPSEC_VERIFY_ERROR;
      }

      /* call srx-crypto-api function */
      sca_generateMSG2(sslVerifyData.data , (u_int8_t*)&sslVerifyData.dataLength,
          targetAS, seg->as, seg->pCount, seg->flags,
          ss->next->sigLen, ss->next->signature);

      hashLen = sslVerifyData.dataLength;
      if (IS_DEBUG_ENABLED)
      {
        sca_debugLog(LOG_DEBUG,"[IN]:%d ---- HASH recv [total length: %d] ----\n", __LINE__, hashLen);
        printHex(hashLen, hashbuff);
        char skiBuffer[BGPSEC_SKI_LENGTH * 2 + 1];
        GEN_SKI_ASCII(skiBuffer, ss->ski, BGPSEC_SKI_LENGTH);
        sca_debugLog(LOG_DEBUG,"[IN] ---- current SKI: 0x%s ----\n", skiBuffer);
      }


      // calculate current number in array
      currNum = number_keys - iter;

      if (keys && keys[currNum])
      {
        status = stcl_BgpsecVerifySignatureSSL_withKeyInfo(&sslVerifyData, keys, 
                                                           currNum);
        switch (status)
        {
          case API_BGPSEC_VERIFY_ERROR:
            sca_debugLog(LOG_ERR, "%s: An Error occured during verification of signature. Stop validation!\n", 
                                  __FUNCTION__);
            goto verify_err;
          case API_BGPSEC_VERIFY_FAILURE:
            sca_debugLog(LOG_DEBUG, "%s: Signature %d if signer AS%d is invalid - abort further validation! \n", 
                                    __FUNCTION__, currNum, seg->as);
            goto verify_err;
          case API_BGPSEC_VERIFY_SUCCESS:
            sca_debugLog(LOG_INFO,"BGPSEC Update Verification SUCCESS !!! [Signer AS:%d] \n\n",
                         seg->as);
          default:
            break;            
        }
      }
      else
      {
        // Even though in OpenSSL a missing key is an error, for SRxCryptoAPI
        // which follows BGPSEC it is a valid state to not have a particular
        
        sca_debugLog(LOG_ERR,"Error: %s: keys Not Found\n", __FUNCTION__);
        status = API_BGPSEC_VERIFY_ERROR;
        goto verify_err;
      }

      /* next target as concatenation */
      targetAS = seg->as;
    } /* end of if */

    /* last segments */
    else
    {
      /* #### hashbuff generation (origin) ####
       * +-------------------------------------+
       * | Target AS number        : 4 octec   |
       * +-------------------------------------+
       * | Origin's AS number      : 4 octec   |
       * +-------------------------------------+
       * | pCount                  : 1 octet   |
       * +-------------------------------------+
       * | Flags                   : 1 octet   |
       * +-------------------------------------+
       * | Algorithm Suite Id.     : 1 octet   |
       * +-------------------------------------+
       * | AFI                     : 2 octet   |
       * +-------------------------------------+
       * | SAFI                    : 1 octet   |
       * +-------------------------------------+
       * | NLRI Length             : 1 octet   |
       * +-------------------------------------+
       * | NLRI prefix             : (variable)|
       * +-------------------------------------+
       */

      /* release temporary allocated pointer if it was allocated by sca_generateMSG
       * in srxcryptoapi */
      if(sslVerifyData.data != hashbuff && sslVerifyData.data)
        free(sslVerifyData.data);

      sslVerifyData.data           = hashbuff;
      sslVerifyData.dataLength     = sizeof(hashbuff);
      sslVerifyData.signature      = ss->signature;
      sslVerifyData.sigLen         = ss->sigLen;

      /* call srx-crypto-api function */
      sca_generateMSG1(sslVerifyData.data, (u_int8_t*)&sslVerifyData.dataLength,
          targetAS, seg->as,
          seg->pCount, seg->flags, sb->algoSuiteId, AFI_IP, SAFI_UNICAST,
          p->prefixlen, &p->u.prefix);

      hashLen = sslVerifyData.dataLength;
     if (IS_DEBUG_ENABLED)
      {
        sca_debugLog(LOG_DEBUG,"[IN]:%d ---- HASH recv for Origin [total length: %d] ----\n", __LINE__, hashLen);
        printHex(hashLen, hashbuff);
        char skiBuffer[BGPSEC_SKI_LENGTH * 2 + 1];
        GEN_SKI_ASCII(skiBuffer, ss->ski, BGPSEC_SKI_LENGTH);
        sca_debugLog(LOG_DEBUG,"[IN] ---- current SKI: 0x%s ----\n", skiBuffer);
      }

      if(keys && *keys)
      {
        if ( API_BGPSEC_VERIFY_SUCCESS!=
            (status = stcl_BgpsecVerifySignatureSSL_withKeyInfo(&sslVerifyData, keys, (number_keys - iter))))
        {
          sca_debugLog(LOG_ERR,"%s: Failure(status:%d): bad signature, ignoring\n", __FUNCTION__,status);
          goto verify_err;
        }
        else
        {
          sca_debugLog(LOG_INFO,"BGPSEC Update Verification with key SUCCESS !!! [Origin AS:%d] \n\n",
              seg->as);
        }
      }
      else
      {
        sca_debugLog(LOG_ERR,"Error: %s: keys Not Found\n", __FUNCTION__);
        status = API_BGPSEC_VERIFY_ERROR;
        goto verify_err;
        }

    } /* end of else */


    /* next Secure_Path segment and Signature Segment */
    seg = seg->next;
    ss = ss->next;
    iter--;

  } /* end of while */

  return status;

verify_err:
  /* release temporary allocated pointer if it was allocated by sca_generateMSG
   * in srxcryptoapi */
  if(sslVerifyData.data != hashbuff && sslVerifyData.data)
  {
    free(sslVerifyData.data);
  }
  return status;

}


/**
 * @brief supports for extended validation.
 *
 * @param bpa : bgpsec path attribute info
 * @param prefix: additional information for NLRI
 * @param local_as:  additional information for NLRI
 * @param extCode:  on input: used for public key id temporarily,
 *                  on return: 1 - key not found,  0 - invalid
 *
 * @return on success with API_BGPSEC_VERIFY_SUCCESS or on failure(invalid) with API_BGPSEC_VERIFY_FAILURE
 *          on error with API_BGPSEC_VERIFY_ERROR
 */
int cl_ExtBgpsecVerify (BgpsecPathAttr *bpa, void *prefix, u_int32_t local_as, u_int8_t* extCode)
{
  if(cl_BgpsecSanityCheck(bpa) != 0)
  {
    sca_debugLog(LOG_ERR,"%s:[OUT] bgpsec Path Attr structure error\n", __FUNCTION__);
    return API_BGPSEC_VERIFY_ERROR;
  }

  int status = API_BGPSEC_VERIFY_ERROR;
  EC_KEY *ecdsa_key = NULL;

  PathSegment   *seg = bpa->pathSegments;
  SigBlock      *sb = bpa->sigBlocks;
  SigSegment    *ss = sb->sigSegments;

  static u_int8_t keyID_pub=0;
  struct prefix *p=(struct prefix *)prefix;

  // calculate current number in array
  int currNum =0;// it has yet to make mutiple input of ids, so now one by one
  bool fPrivate= false;

  u_int8_t hashbuff[BGPSEC_MAX_SIG_LENGTH + 10 + BGPSEC_AFI_LENGTH];
  size_t hashLen = 0;

  u_short iter;
  int numSecurePathSegment = 0;

  /* Secure_Path length includes two octets used to express its own length field */
  iter = numSecurePathSegment =
    (bpa->securePathLen - OCTET_SECURE_PATH_LEN) / OCTET_SECURE_PATH_SEGMENT;

  /* Validation Routine */
  as_t targetAS = local_as;

  BGPSecSignData sslVerifyData = {
    .data           = hashbuff,
    .dataLength     = hashLen,
    .signature      = ss->signature,
    .sigLen         = ss->sigLen,
  };

  BGPSecKey *outKeyInfo=NULL;
  u_int16_t num_key = 1; /* single action for now */

  while(iter && seg && sb && ss)
  {
    /* encapsulated and stacked at least 2 and more segments */
    if(iter > 1)
    {
      /*  #### hashbuff generation (transit) ####
       * +-----------------------------------------+
       * | Target AS Number               4 octets |
       * +-----------------------------------------+
       * | Signer's AS Number             4 octets |
       * +-----------------------------------------+
       * | pCount                         1 octet  |
       * +-----------------------------------------+
       * | Flags                          1 octet  |
       * +-----------------------------------------+
       * | Sig Field in the Next Segment (variable)|
       * +-----------------------------------------+
       */


      /* release temporary allocated pointer if it was allocated by sca_generateMSG
       * in srxcryptoapi */
      if(sslVerifyData.data != hashbuff && sslVerifyData.data)
        free(sslVerifyData.data);

      sslVerifyData.data           = hashbuff;
      sslVerifyData.dataLength     = sizeof(hashbuff);
      sslVerifyData.signature      = ss->signature;
      sslVerifyData.sigLen         = ss->sigLen;

      if(!ss->next)
      {
        sca_debugLog(LOG_ERR,"Error: bad segment arrangement, ignoring\n", __FUNCTION__);
        return API_BGPSEC_VERIFY_ERROR;
      }

      /* call srx-crypto-api function */
      sca_generateMSG2(sslVerifyData.data , (u_int8_t*)&sslVerifyData.dataLength,
          targetAS, seg->as, seg->pCount, seg->flags,
          ss->next->sigLen, ss->next->signature);

      hashLen = sslVerifyData.dataLength;

      if (IS_DEBUG_ENABLED)
      {
        sca_debugLog(LOG_DEBUG,"[IN]:%d ---- HASH recv [total length: %d] ----\n", __LINE__, hashLen);
        printHex(hashLen, hashbuff);
        char skiBuffer[BGPSEC_SKI_LENGTH * 2 + 1];
        GEN_SKI_ASCII(skiBuffer, ss->ski, BGPSEC_SKI_LENGTH);
        sca_debugLog(LOG_DEBUG,"[IN] ---- current SKI: 0x%s ----\n", skiBuffer);
      }

      /* find a key amongst the registered key previously */
      // TODO: Later, should be replaced with a set of ids
      Record_t *out = restoreKeyInfo(fPrivate, (u_int8_t*)ss->ski, seg->as);

      if(out)
      {
        outKeyInfo = (BGPSecKey*) malloc(sizeof(BGPSecKey));
      if(!outKeyInfo)
      {
        sca_debugLog(LOG_ERR, "[%s:%d] pubkey info mem allocation failed", __FUNCTION__, __LINE__);
        *extCode = 1;
        goto err;
      }

        memset(outKeyInfo, 0x0, sizeof(BGPSecKey));
        outKeyInfo->algoID        = BGPSEC_ALGO_ID;
        outKeyInfo->asn           = seg->as;
        memcpy(outKeyInfo->ski, ss->ski, BGPSEC_SKI_LENGTH);

        outKeyInfo->keyLength = (u_int16_t )(((BGPSecKey *)out->data)->keyLength);
        outKeyInfo->keyData = (u_int8_t *)malloc(((BGPSecKey *)out->data)->keyLength); // this pointer will be freed by caller
        memcpy(outKeyInfo->keyData, ((BGPSecKey *)out->data)->keyData, ((BGPSecKey *)out->data)->keyLength);

        sca_debugLog (LOG_DEBUG, "[%s] obtain KEY data from pubkey ID: %p\n",
            __FUNCTION__, (u_int8_t*)outKeyInfo->keyData);

        /* retrieve ec key */
        ecdsa_key = (EC_KEY *)out->data_eckey;
        if (!ecdsa_key )
        {
          sca_debugLog(LOG_ERR, "fail to retrieve a registered eckey \n");
        }
      }

      if(ecdsa_key)
      {
        /* check public key */
        if(EC_KEY_get0_public_key(ecdsa_key) == NULL)
        {
          ECerr(EC_F_ECKEY_PUB_DECODE, ERR_R_EC_LIB);
          sca_debugLog(LOG_ERR, "EC_KEY_get0_public_key failed \n");
          *extCode = 1;
          goto err;
        }
        /* check validity of ec key */
        if (!EC_KEY_check_key(ecdsa_key)) {
          sca_debugLog(LOG_ERR, "[libcrypto] EC_KEY_check failed: EC key check error\n");
          *extCode = 1;
          goto err;
      }

        sca_debugLog(LOG_INFO, "Verify directly using eckey... \n");
        unsigned char md[SHA256_DIGEST_LENGTH];
        cl_BgpsecOctetDigest(sslVerifyData.data, sslVerifyData.dataLength, md);
        status = cl_BgpsecDoVerifySignature (md, SHA256_DIGEST_LENGTH,
            ecdsa_key,
            sslVerifyData.signature,
            sslVerifyData.sigLen);

        if(status != API_BGPSEC_VERIFY_SUCCESS)
      {
          sca_debugLog(LOG_ERR, "+ [libcrypto] Failure at verifying\n");
          *extCode = 0; // invalid
        goto err;
      }
        else
        {
          sca_debugLog(LOG_INFO,"BGPSEC Update Verification SUCCESS !!! [Signer AS:%d] \n\n",
              seg->as);
        }
      }

      /* in case, the retrieved ec key fails */
      else if(outKeyInfo && outKeyInfo->keyData)
      {
        if ( API_BGPSEC_VERIFY_SUCCESS!=
            (status = stcl_BgpsecVerifySignatureSSL_withKeyInfo(&sslVerifyData, &outKeyInfo, currNum)))
        {
          sca_debugLog(LOG_ERR,"%s: Failure(status:%d): bad signature, ignoring\n", __FUNCTION__,status);
          *extCode = 0; // invalid
          goto err;
        }
        else
        {
          sca_debugLog(LOG_INFO,"BGPSEC Update Verification SUCCESS !!! [Signer AS:%d] \n\n",
              seg->as);
        }
      }
      else
      {
        sca_debugLog(LOG_ERR,"Error: %s: keys Not Found\n", __FUNCTION__);
        *extCode = 1;
        status = API_BGPSEC_VERIFY_ERROR;
        goto err;
      }

      /* release parameter resources */
      if(outKeyInfo)
      {
        if(outKeyInfo->keyData)
        {
          free(outKeyInfo->keyData);
          outKeyInfo->keyData = NULL;
        }
        free(outKeyInfo);
        outKeyInfo = NULL;
      }

      /* next target as concatenation */
      targetAS = seg->as;
    } /* end of if */

    /* last segments */
    else
    {
      /* #### hashbuff generation (origin) ####
       * +-------------------------------------+
       * | Target AS number        : 4 octec   |
       * +-------------------------------------+
       * | Origin's AS number      : 4 octec   |
       * +-------------------------------------+
       * | pCount                  : 1 octet   |
       * +-------------------------------------+
       * | Flags                   : 1 octet   |
       * +-------------------------------------+
       * | Algorithm Suite Id.     : 1 octet   |
       * +-------------------------------------+
       * | AFI                     : 2 octet   |
       * +-------------------------------------+
       * | SAFI                    : 1 octet   |
       * +-------------------------------------+
       * | NLRI Length             : 1 octet   |
       * +-------------------------------------+
       * | NLRI prefix             : (variable)|
       * +-------------------------------------+
       */


      /* release temporary allocated pointer if it was allocated by sca_generateMSG
       * in srxcryptoapi */
      if(sslVerifyData.data != hashbuff && sslVerifyData.data)
        free(sslVerifyData.data);

      sslVerifyData.data           = hashbuff;
      sslVerifyData.dataLength     = sizeof(hashbuff);
      sslVerifyData.signature      = ss->signature;
      sslVerifyData.sigLen         = ss->sigLen;

      /* call srx-crypto-api function */
      sca_generateMSG1(sslVerifyData.data, (u_int8_t*)&sslVerifyData.dataLength,
          targetAS, seg->as,
          seg->pCount, seg->flags, sb->algoSuiteId, AFI_IP, SAFI_UNICAST,
          p->prefixlen, &p->u.prefix);

      hashLen = sslVerifyData.dataLength;

      if (IS_DEBUG_ENABLED)
      {
        sca_debugLog(LOG_DEBUG,"[IN] %s:%d ---- HASH recv for Origin [total length: %d] ----\n",
            __FUNCTION__,__LINE__, hashLen);
        printHex(hashLen, hashbuff);
        char skiBuffer[BGPSEC_SKI_LENGTH * 2 + 1];
        GEN_SKI_ASCII(skiBuffer, ss->ski, BGPSEC_SKI_LENGTH);
        sca_debugLog(LOG_DEBUG,"[IN] ---- current SKI: 0x%s ----\n", skiBuffer);
      }

      /* find a key amongst the registered key previously */
      // TODO: Later, should be replaced with a set of ids
      Record_t *out = restoreKeyInfo(fPrivate, (u_int8_t*)ss->ski, seg->as);

      if(out)
      {
      outKeyInfo= (BGPSecKey*) malloc(sizeof(BGPSecKey));
      if(!outKeyInfo)
      {
        sca_debugLog(LOG_ERR, "[%s:%d] pubkey info mem allocation failed", __FUNCTION__, __LINE__);
        *extCode = 1;
        goto err;
      }

        memset(outKeyInfo, 0x0, sizeof(BGPSecKey));
        outKeyInfo->algoID        = BGPSEC_ALGO_ID;
        outKeyInfo->asn           = seg->as;
        memcpy(outKeyInfo->ski, ss->ski, BGPSEC_SKI_LENGTH);

        outKeyInfo->keyLength = (u_int16_t )(((BGPSecKey *)out->data)->keyLength);
        outKeyInfo->keyData = (u_int8_t *)malloc(((BGPSecKey *)out->data)->keyLength); // this pointer will be freed by caller
        memcpy(outKeyInfo->keyData, ((BGPSecKey *)out->data)->keyData, ((BGPSecKey *)out->data)->keyLength);

        sca_debugLog (LOG_DEBUG, "[%s] obtain KEY data from pubkey ID: %p\n",
            __FUNCTION__, (u_int8_t*)outKeyInfo->keyData);

        /* retrieve ec key */
        ecdsa_key = (EC_KEY *)out->data_eckey;
        if (!ecdsa_key )
        {
          sca_debugLog(LOG_ERR, "fail to retrieve a registered eckey \n");
        }
      }

      if(ecdsa_key)
      {
        /* check public key */
        if(EC_KEY_get0_public_key(ecdsa_key) == NULL)
        {
          ECerr(EC_F_ECKEY_PUB_DECODE, ERR_R_EC_LIB);
          sca_debugLog(LOG_ERR, "EC_KEY_get0_public_key failed \n");
          *extCode = 1;
          goto err;
        }
        /* check validity of ec key */
        if (!EC_KEY_check_key(ecdsa_key)) {
          sca_debugLog(LOG_ERR, "[libcrypto] EC_KEY_check failed: EC key check error\n");
          *extCode = 1;
          goto err;
      }

        sca_debugLog(LOG_INFO, "Verify directly using eckey... \n");
        unsigned char md[SHA256_DIGEST_LENGTH];
        cl_BgpsecOctetDigest(sslVerifyData.data, sslVerifyData.dataLength, md);
        status = cl_BgpsecDoVerifySignature (md, SHA256_DIGEST_LENGTH,
            ecdsa_key,
            sslVerifyData.signature,
            sslVerifyData.sigLen);

        if(status != API_BGPSEC_VERIFY_SUCCESS)
      {
          sca_debugLog(LOG_ERR, "+ [libcrypto] Failure at verifying\n");
          *extCode = 0; // invalid
        goto err;
      }
        else
        {
          sca_debugLog(LOG_INFO,"BGPSEC Update Verification with key SUCCESS !!! [Origin AS:%d] \n\n",
              seg->as);
        }
      }

      /* in case, the retrieved ec key fails */
      else if(outKeyInfo && outKeyInfo->keyData)
      {
        if ( API_BGPSEC_VERIFY_SUCCESS!=
            (status = stcl_BgpsecVerifySignatureSSL_withKeyInfo(&sslVerifyData, &outKeyInfo, currNum)))
        {
          sca_debugLog(LOG_ERR,"%s: Failure(status:%d): bad signature, ignoring\n", __FUNCTION__,status);
          *extCode = 0; // invalid
          goto err;
        }
        else
        {
          sca_debugLog(LOG_INFO,"BGPSEC Update Verification with key SUCCESS !!! [Origin AS:%d] \n\n",
              seg->as);
        }
      }
      else
      {
        sca_debugLog(LOG_ERR,"Error: %s: keys Not Found\n", __FUNCTION__);
        *extCode = 1;
        status = API_BGPSEC_VERIFY_ERROR;
        goto err;
      }

      /* release parameter resources */
      if(outKeyInfo)
      {
        if(outKeyInfo->keyData)
        {
          free(outKeyInfo->keyData);
          outKeyInfo->keyData = NULL;
        }
        free(outKeyInfo);
        outKeyInfo = NULL;
      }

    } /* end of else */


    /* next Secure_Path segment and Signature Segment */
    seg = seg->next;
    ss = ss->next;
    iter--;

  } /* end of while */


  return status;

err:
  /* release parameter resources */
  if(outKeyInfo)
  {
    if(outKeyInfo->keyData)
    {
      free(outKeyInfo->keyData);
      outKeyInfo->keyData = NULL;
    }
    free(outKeyInfo);
    outKeyInfo = NULL;
  }

  /* TODO: this ec key should be removed at unregisterKey or somewhere else
  if (ecdsa_key)
  {
    EC_KEY_free(ecdsa_key);
    ecdsa_key = NULL;
  }
  */
  return status;
}



/**
 * API function call for validate
 *
 * @param bpa : bgpsec path attribute info
 * @param number_keys: the number of keys given
 * @param keys: provied public keys for verification
 * @param prefix: additional information for NLRI
 * @param local_as:  additional information for NLRI
 *
 * @return an int value from the function cl_BgpsecVerify
 *  (API_BGPSEC_VERIFY_SUCCESS/API_BGPSEC_VERIFY_ERROR/API_BGPSEC_VERIFY_FAILURE)
 */
int validate (BgpsecPathAttr *bpa, u_int16_t number_keys, BGPSecKey** keys, void *prefix,
                u_int32_t local_as)
{
  return cl_BgpsecVerify (bpa, number_keys, keys, prefix, local_as);
}

/**
 * @brief support for extended validation. This function is kind of wrapper
 *          to call cl_ExtBgpsecVerify
 *
 * @param bpa : bgpsec path attribute info
 * @param prefix: additional information for NLRI
 * @param local_as:  additional information for NLRI
 * @param extCode: 1 - key not found,  0 - invalid
 *
 * @return on success with API_BGPSEC_VERIFY_SUCCESS or on failure with API_BGPSEC_VERIFY_ERROR
 */
int extValidate (BgpsecPathAttr* bpa, void *prefix, u_int32_t local_as, u_int8_t* extCode)
{
  return cl_ExtBgpsecVerify(bpa, prefix, local_as, extCode);
}

/**
 * API function call for sign_with_key
 *
 * @param bgpsec_data: contains signing info; message, signing buffer, asn etc
 * @param key: key info using signing
 *
 * @return
 */
int sign_with_key (BGPSecSignData* bgpsec_data, BGPSecKey *key)
{
  return( (key && key->keyData) ?
      stBgpsecReqSigningWithKeyInfo(bgpsec_data, key):
      API_BGPSEC_VERIFY_ERROR);
}


/**
 * API function call for sign_with_id
 *
 * @param dataLength: message length
 * @param data: message digest string used for signing
 * @param keyID: id number indicating ecdsa instance which stored previously
 * @param sigLen: the number of bytes of signature
 * @param signature: output of signing request
 *
 * @return
 */
int sign_with_id(BGPSecSignData *bgpsecSignData, u_int8_t keyID)
{
   return stBgpsecReqSigningWithID(bgpsecSignData, keyID);
}

/**
 * Sanity check for BGPSecSignData
 *
 * @param signData: BGPSecSignData strucutre instance
 * @param key: key instance info
 *
 * @return  0 on success, -1 on error
 */
int cl_SignParamSanityCheck(BGPSecSignData *signData, BGPSecKey *key)
{
  if(!signData )
    return -1;

  if(!signData->data || !signData->signature)
    return -1;

  return 0;
}

/**
 * Sanity check for BGPSecSignData and BGPSecKey
 *
 * @param signData: BGPSecSignData strucutre instance
 * @param key: key instance info
 *
 * @return  0 on success, -1 on error
 */
int cl_SignParamWithKeySanityCheck(BGPSecSignData *signData, BGPSecKey *key)
{
  if(!signData )
    return -1;

  if(!signData->data || !signData->signature)
    return -1;

  if(!key)
    return -1;

  if(!key->keyData)
    return -1;

  return 0;
}

/**
 * Sanity check for BGPSecSignData and keyID
 *
 * @param signData: BGPSecSignData strucutre instance
 * @param keyID: key storate id info
 *
 * @return  0 on success, -1 on error
 */
int cl_SignParamWithIDSanityCheck(BGPSecSignData *signData, u_int8_t keyID)
{
  if(!signData )
    return -1;

  if(!signData->data || !signData->signature)
    return -1;

  if(!keyID)
    return -1;

  return 0;
}

/**
 * Sanity check for BgpsecPathAttr
 *
 * @param bpa bgpsec path attribute info instance
 *
 * @return  0 on success, -1 on error
 */
int cl_BgpsecSanityCheck(BgpsecPathAttr *bpa)
{
  PathSegment *seg;
  SigBlock *sb;
  SigSegment *ss;

  if(!bpa)
    return -1;

  seg = bpa->pathSegments;
  sb  = bpa->sigBlocks;

  if(!seg || !sb)
    return -1;

  ss = sb->sigSegments;

  if(!ss)
    return -1;

  if(!ss->signature || !ss->ski)
    return -1;

  return 0;
}


/**
 * performs digest function
 *
 * @param octet: used as an input for digest function
 * @param octet_len: the number of octet bytes
 * @param md: output string pointer as an output
 *
 * @return md: message digest string
 */
unsigned char* cl_BgpsecOctetDigest(const unsigned char* octet, unsigned int octet_len, unsigned char* md)
{
  unsigned char result[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256ctx;
  SHA256_Init(&sha256ctx);
  SHA256_Update(&sha256ctx, octet, octet_len);
  SHA256_Final(result, &sha256ctx);

  if(md)
  {
    memcpy(md, result, SHA256_DIGEST_LENGTH);
  }
  else
    return NULL;

  if (IS_DEBUG_ENABLED)
  {
    sca_debugLog(LOG_DEBUG,"octet leng: %d\nmessage digest: 0x", octet_len);
    printHex(SHA256_DIGEST_LENGTH, md);
  }

  return md;
}



/**
 * caller for hash input function
 *
 * @param fPrivate  UTHASH for private key or public key
 * @param ec_key    ecdsa key used as data instance of record
 * @param ski
 * @param asn
 * @param inKey     input key parameter
 * @param outKeyData duplicated variable and maintained in the hash storage
 * @param filter    id bound filter
 *
 * @return  id number or -1 on error
 */
int inputKeyInfo(bool fPrivate, EC_KEY* ec_key, u_int8_t* ski, u_int32_t asn,
                 BGPSecKey* inKey, void** outKeyData, unsigned int filter)
{

  unsigned int id=0;
  BGPSecKey *bsKeyInfo;

  if(ec_key && inKey)
  {
    /* entry data preparation */
    bsKeyInfo = (BGPSecKey*)malloc(sizeof(BGPSecKey));
    if(!bsKeyInfo)
      goto err;
    bsKeyInfo->algoID = API_BGPSEC_ALGO_ID_256;
    bsKeyInfo->keyLength = inKey->keyLength;

    /* duplicate */
    bsKeyInfo->keyData = (u_int8_t *)malloc(inKey->keyLength);
    if(!bsKeyInfo->keyData)
      goto err;
    memcpy(bsKeyInfo->keyData, inKey->keyData, inKey->keyLength);

    if(outKeyData)
      *outKeyData = (void *)bsKeyInfo->keyData;

    bsKeyInfo->asn      = inKey->asn;
    memcpy(bsKeyInfo->ski, inKey->ski, SKI_LENGTH);
  }
  else
  {
    sca_debugLog(LOG_ERR, "+ [libcrypto](%s:%d) ec key is NULL\n", __FUNCTION__, __LINE__);
    return -1;
  }

  /* new entry input */
  Record_t *new = (Record_t*) malloc(sizeof(Record_t));
  memset(new, 0, sizeof(Record_t));

  new->key.asn = asn;
  new->ski = malloc(SKI_LENGTH);
  new->data_eckey = (void*)ec_key;

  if (new->ski != NULL)
  {
    memcpy(new->ski, ski, SKI_LENGTH);
    new->data = (void*)bsKeyInfo;

    /* different hash storage according to a key */
    Record_t *head;
    if(fPrivate)
    {
    HASH_ADD(hh, g_records, key, sizeof(DataKey_t), new);
      head = g_records;
    }
    else
    {
      HASH_ADD(hh, g_records_pub, key, sizeof(DataKey_t), new);
      head = g_records_pub;
    }

    id = new->hh.hashv;
    filter = filter > (((head)->hh.tbl->num_buckets) -1) ?
      (((head)->hh.tbl->num_buckets) -1) : filter;

    sca_debugLog (LOG_DEBUG,"[%s:%d] ski: %p\n",
                  __FUNCTION__, __LINE__, new->ski);
    sca_debugLog (LOG_DEBUG, "[%s] new data (bgpsec key): %p Total num of data:%d\n",
        __FUNCTION__, bsKeyInfo, (head)->hh.tbl->num_items);
    sca_debugLog (LOG_DEBUG," number of bucket:%d  hashv:%x\n", (head)->hh.tbl->num_buckets, new->hh.hashv);
    sca_debugLog (LOG_DEBUG," ha_bkt(id): %x\n", (new->hh.hashv) & (((head)->hh.tbl->num_buckets) -1) );

    return (id & filter) ;
  }

err:
  if(bsKeyInfo) free(bsKeyInfo);
  if(new) free(new);
  id = -1;
  return id;
}


/**
 * caller function for hash-find function
 *
 * @param fPrivate  UTHASH for private key or public key
 * @param ski
 * @param asn
 *
 * @return Record_t hash object or NULL on error
 */
Record_t* restoreKeyInfo(bool fPrivate, u_int8_t* ski, u_int32_t asn)
{
  BGPSecKey *outKeyInfo =NULL;

  Record_t temp, *out;
  temp.key.asn = asn;

  sca_debugLog (LOG_DEBUG, "[%s:%d] given ski:%02x asn:%ld\n",
      __FUNCTION__, __LINE__, *ski, asn);

  if(fPrivate)
  {
  HASH_FIND(hh, g_records, &temp.key, sizeof(DataKey_t), out);
  }
  else
  {
    HASH_FIND(hh, g_records_pub, &temp.key, sizeof(DataKey_t), out);
  }

  if(out)
  {
    if (cmpSKI(out->ski, ski))
    {
      sca_debugLog (LOG_DEBUG, "[%s] FOUND a key with matching SKI and ASN\n",
          __FUNCTION__);
      outKeyInfo = (BGPSecKey *) out->data;
      sca_debugLog (LOG_DEBUG, "[%s] KEY data : %p\n", __FUNCTION__, (u_int8_t*)outKeyInfo->keyData);
    }
    else
    {
      sca_debugLog (LOG_DEBUG, "[%s] FOUND a key with matching ASN(%d) but SKI is different\n",
          __FUNCTION__, out->key.asn);
      /* TODO: in case of the different SKI */
      return NULL;
    }
  }
  else
  {
    sca_debugLog (LOG_DEBUG,"(%s:%d) NOT FOUND a key\n", __FUNCTION__, __LINE__);
    return NULL;
  }

  return out;
}

/**
 * caller function for hash-find function with using id info
 *
 * @param fPrivate  UTHASH for private key or public key
 * @param ski
 * @param asn
 * @param id    hash id
 *
 * @return Record_t hash object or NULL on error
 */
Record_t* restoreKeyInfo_withID(bool fPrivate, u_int8_t* ski, u_int32_t asn, u_int32_t id)
{

  Record_t *s;
  s = fPrivate ? g_records: g_records_pub;

  for(s; s!=NULL; s=(Record_t*)(s->hh.next))
  {
    if (s->key.asn == asn && cmpSKI(s->ski, ski))
    {
      if(id == s->hh.hashv)
        sca_debugLog (LOG_DEBUG, "=== Item Found === id:%x asn: %d  ski:%s\n", id, s->key.asn, s->ski);
      else
        return NULL;
      return s;
    }
    else
    {
      sca_debugLog (LOG_DEBUG, " Item not Found \n");
      return NULL;
    }

  }
  return NULL;
}

/**
 * get hash data from the input of ski and asn
 *
 * @param asn
 * @param ski
 *
 * @return BGPSecKey instance found in hash
 */
BGPSecKey * hashKey_get_BGPSecKey(u_int32_t asn, u_int8_t* ski)
{
  unsigned int ret_hash_id=0;
  Record_t  *rec = NULL;
  BGPSecKey *tmpBsKey = NULL;

  if (!ski || !asn)
  {
    sca_debugLog(LOG_ERR, "+ [libcrypto] input parameters error\n");
    return NULL;
  }

  rec = restoreKeyInfo(0, ski, asn);
  if (rec)
  {
    tmpBsKey = (BGPSecKey *)rec->data;
    ret_hash_id = rec->hh.hashv;
    sca_debugLog (LOG_DEBUG, "[%s:%d] FOUND --> hash id : %x, tmpBsKey:%p\n",
        __FUNCTION__, __LINE__, ret_hash_id, tmpBsKey);
  }
  else
  {
    sca_debugLog(LOG_DEBUG, "+ [libcrypto] NOT FOUND\n");
  }

  return tmpBsKey;
}

/**
 * API method for registerPrivateKey
 *
 * @param outKey containes key pointer to be converted
 *
 * @return          : key pointer array
 */
u_int8_t registerPrivateKey(BGPSecKey* outKey)
{
  u_int8_t  ret_hash_id=0;
  EC_KEY    *ec_key=NULL;
  Record_t *rec=NULL;
  //BGPSecKey* bsKeyInfo = NULL;
  bool      fPrivate=true;

  if(!outKey )
  {
    sca_debugLog(LOG_ERR, "+ [libcrypto] out key container doesn't exist \n");
    return 0;
  }

  u_int8_t* ski    = outKey->ski;
  u_int32_t asn    = outKey->asn;

  if(!asn)
  {
    sca_debugLog(LOG_ERR, "+ [libcrypto] input parameters error\n");
    return 0;
  }

  sca_debugLog (LOG_DEBUG, "(%s:%d) params: ski:%02x, asn:%ld  out:%p\n",
      __FUNCTION__, __LINE__, *ski, asn, outKey);

  /*
   * first try to find if already existed or not.
   * otherwise, proceed to register
   */
  rec = restoreKeyInfo(fPrivate, ski, asn);
  if(rec)
  {
    ret_hash_id = (rec->hh.hashv & (ID_NUM_MAX-1));
    sca_debugLog (LOG_DEBUG, "[%s] ALREADY REGISTERED--> hash id : %x, BGPSecKey:%p\n",
                            __FUNCTION__, ret_hash_id, (BGPSecKey *)rec->data);
    return ret_hash_id + RET_ID_OFFSET;
  }

  /* a private ec_key from DER buffer */
  sca_debugLog (LOG_DEBUG, "(%s:%d) key_Data:%p, len:%d \n",
      __FUNCTION__, __LINE__, outKey->keyData, outKey->keyLength);

  unsigned char *p = outKey->keyData;

  if(!p)
  {
    sca_debugLog (LOG_DEBUG, "keyData is NULL\n");
    return 0;
  }

  if (IS_DEBUG_ENABLED)
  {
    sca_debugLog (LOG_DEBUG, "\n----- printing out buf hex:%p ----- {%s:%d}",
        outKey->keyData, __FUNCTION__, __LINE__);
    printHex(outKey->keyLength, outKey->keyData);
  }

  /* get EC_POINT pubkey and BN_ private key info into EC_KEY */
  ec_key = d2i_ECPrivateKey(NULL, (const unsigned char**)&p, outKey->keyLength);

  if (!ec_key )
  {
    ECerr(EC_F_ECKEY_PRIV_DECODE, EC_R_DECODE_ERROR);
    sca_debugLog(LOG_ERR, "+ [libcrypto](%s:%d) obtaining ec key error\n", __FUNCTION__,__LINE__);
    return 0;
  }

  sca_debugLog (LOG_DEBUG, "ec key : %p\n", ec_key);
  sca_debugLog (LOG_DEBUG, "ec point pub key returned : %p\n", ec_key->pub_key);
  sca_debugLog (LOG_DEBUG, "ec point private key returned : %p (dmax:%d)\n",
      ec_key->priv_key->d, ec_key->priv_key->dmax);

  if (IS_DEBUG_ENABLED)
    PrintPrivPubKeyHex(ec_key);


  /* register key info into hash */
  void *outKeyData = NULL;
  int retVal= inputKeyInfo(fPrivate, ec_key, ski, asn, outKey, &outKeyData, (ID_NUM_MAX-1));
  if(retVal == -1)
  {
    ret_hash_id = 0; //error
  }
  else
  {
    ret_hash_id = (u_int8_t)retVal;
  }

  if(!outKeyData)
  {
    sca_debugLog (LOG_ERR, "outKeyData error \n");
  }

  /* store the key into key array */

  stEnbuf_Eckey[ret_hash_id].id     = ret_hash_id;
  stEnbuf_Eckey[ret_hash_id].ec_key = (void*)ec_key;
  stEnbuf_Eckey[ret_hash_id].en_buf = (void*)outKeyData;

  sca_debugLog (LOG_DEBUG, "[%s] hash id : %x, outKey:%p outkey->keydata:%p ec_key:%p outKeyData:%p\n",
      __FUNCTION__, ret_hash_id, outKey, outKey->keyData, ec_key, outKeyData);

  /* return hash id */
  return ret_hash_id + RET_ID_OFFSET;  // 0: error, so start from 1 offset


}


/**
 * API method for registerPublicKey
 *
 * @param outKey containes key pointer to be converted
 *
 * @return          : key pointer array
 */
u_int8_t registerPublicKey(BGPSecKey* outKey)
{
  u_int8_t  ret_hash_id=0;
  EC_KEY    *ec_key=NULL;
  Record_t  *rec=NULL;
  bool      fPrivate=false;

  sca_debugLog(LOG_DEBUG, "+ [libcrypto]  registerPublicKey called \n");

  if(!outKey )
  {
      sca_debugLog(LOG_ERR, "+ [libcrypto] out Pub-key container doesn't exist \n");
      return 0;
  }

  u_int8_t* ski = outKey->ski;
  u_int32_t asn = outKey->asn;

  if(!asn)
  {
    sca_debugLog(LOG_ERR, "+ [libcrypto] pub input parameters error\n");
    return 0;
  }

  sca_debugLog (LOG_DEBUG, "(%s:%d) params: ski:%02x, asn:%ld  out:%p\n",
      __FUNCTION__, __LINE__, *ski, asn, outKey);

  /*
   * first try to find if already existed or not.
   * otherwise, proceed to register
   */
  rec = restoreKeyInfo(fPrivate, ski, asn);
  if(rec)
  {
    ret_hash_id = (rec->hh.hashv & (ID_NUM_MAX-1));

    BGPSecKey *tmpBSKey = (BGPSecKey *)rec->data;
    BGPSecKey bsKeyInfo;
    memset(&bsKeyInfo, 0x0, sizeof(BGPSecKey));
    bsKeyInfo = *tmpBSKey; /* struct copy */
    bsKeyInfo.keyData = (u_int8_t *)malloc(tmpBSKey->keyLength); // this pointer will be freed by caller
    if(bsKeyInfo.keyData)
      memcpy(bsKeyInfo.keyData, tmpBSKey->keyData, tmpBSKey->keyLength);

    /* prevent from approaching error status */
    if (outKey->keyData == NULL) outKey->keyData = bsKeyInfo.keyData;
    else
      if(bsKeyInfo.keyData) free(bsKeyInfo.keyData);
    if (outKey->keyLength == 0)  outKey->keyLength = bsKeyInfo.keyLength;

    sca_debugLog (LOG_DEBUG, "[%s] ALREADY REGISTERED--> hash id : %x, BGPSecKey:%p\n",
        __FUNCTION__, ret_hash_id, (BGPSecKey *)rec->data);
    return ret_hash_id + RET_ID_OFFSET;
  }

  /* a public ec_key from DER buffer */
  sca_debugLog (LOG_DEBUG, "(%s:%d) key_Data:%p, len:%d \n",
      __FUNCTION__, __LINE__, outKey->keyData, outKey->keyLength);

  unsigned char *p = outKey->keyData;

  if(!p)
  {
    sca_debugLog (LOG_DEBUG, "keyData is NULL\n");
    return 0;
  }

  if (IS_DEBUG_ENABLED)
  {
    sca_debugLog (LOG_DEBUG, "\n----- printing out buf hex:%p ----- {%s:%d}",
        outKey->keyData, __FUNCTION__, __LINE__);
    printHex(outKey->keyLength, outKey->keyData);
  }

  /* get EVP_PKEY pubkey from the key data and retrieve an EC_KEY object from EVP_PKEY object */
  EVP_PKEY *pkey_tmp;
  int eplen = outKey->keyLength;

  /* We have parameters now set public key */
  pkey_tmp = d2i_PUBKEY(NULL, (const unsigned char**)&p, eplen);
  if (!pkey_tmp)
  {
      ECerr(EC_F_ECKEY_PUB_DECODE, EC_R_DECODE_ERROR);
      sca_debugLog(LOG_ERR, "+ [libcrypto](%s:%d) PUBKEY pub key failed\n", __FUNCTION__,__LINE__);
      return 0;
  }
  ec_key = EVP_PKEY_get1_EC_KEY(pkey_tmp);
  EVP_PKEY_free(pkey_tmp);


  /* showing pub key info */
  sca_debugLog (LOG_DEBUG, "ec key : %p\n", ec_key);
  sca_debugLog (LOG_DEBUG, "ec point pub key returned : %p\n", ec_key->pub_key);

  if (IS_DEBUG_ENABLED)
    PrintPrivPubKeyHex(ec_key);


  /* register key info into hash */
  void *outKeyData = NULL;
  int retVal= inputKeyInfo(fPrivate, ec_key, ski, asn, outKey, &outKeyData, UINT_MAX);
  if(retVal == -1)
  {
    ret_hash_id = 0; //error
  }
  else
  {
    ret_hash_id = (u_int8_t)retVal;
  }

  if(!outKeyData)
  {
    sca_debugLog (LOG_ERR, "outKeyData error \n");
  }


  /*  TODO: store the key into key array */
#if 0 // ret_hash_id once duplicated, so that it need to have a better mechanism to store
  stEnbuf_Eckey[ret_hash_id].id     = ret_hash_id;
  stEnbuf_Eckey[ret_hash_id].ec_key = (void*)ec_key;
  stEnbuf_Eckey[ret_hash_id].en_buf = (void*)outKeyData;
#endif

  sca_debugLog (LOG_DEBUG, "[%s] hash id : %x, outKey:%p outkey->keydata:%p ec_key:%p outKeyData:%p\n",
      __FUNCTION__, ret_hash_id, outKey, outKey->keyData, ec_key, outKeyData);


  /* return hash id */
  return ret_hash_id + RET_ID_OFFSET;  // 0: error, so start from 1 offset

}

/**
 * @ remove public key data in uthash
 *
 * @param key  uthash key parameter to find
 *
 * @return 0: failure, 1: success
 */
int unregisterPublicKey(BGPSecKey* key)
{
  BGPSecKey *tmpBsKey   = NULL;

  /* Remove from uthash */
  Record_t *s;
  for(s= g_records; s!=NULL; s=(Record_t *)(s->hh.next))
  {
    tmpBsKey = s->data;
    if( memcmp(key->keyData, tmpBsKey->keyData, tmpBsKey->keyLength) == 0)
    {
      sca_debugLog(LOG_INFO, "+ [libcrypto][%s:%d] HASH record removing \n", __FUNCTION__, __LINE__);
      sca_debugLog (LOG_DEBUG," === Item Found to be deleted === id:%x keyData:%p\n",
          s->hh.hashv, tmpBsKey->keyData);
      //deleteKeyInfo(s);
      HASH_DEL(g_records_pub,  s);
      free(s);
      return 1;
    }
  }
  return 0;
}


/**
 * calling hash delete function
 *
 * @param rec   UTHASH record to be handled inside
 *
 * @return 0 on success or -1 on failure
 */
int deleteKeyInfo(Record_t *rec)
{
  if(!rec)
    return -1;

  // free and release allocated heap memory
  BGPSecKey *bsKeyInfo = rec->data;
  EC_KEY* ec_key = (EC_KEY*)bsKeyInfo->keyData;

  if (ec_key)
  {
    sca_debugLog(LOG_DEBUG, "+ [libcrypto][%s:%d] EC_KEY removing \n", __FUNCTION__, __LINE__);
    EC_KEY_free(ec_key);
  }
  if(bsKeyInfo)
  {
    sca_debugLog(LOG_DEBUG, "+ [libcrypto][%s:%d] BGPSecKey info removing \n", __FUNCTION__, __LINE__);
    free(bsKeyInfo);
  }
  if(rec->ski)
  {
    sca_debugLog(LOG_DEBUG, "+ [libcrypto][%s:%d] SKI info removing \n", __FUNCTION__, __LINE__);
    free(rec->ski);
  }

  // remove the data from HASH
  sca_debugLog(LOG_DEBUG, "+ [libcrypto][%s:%d] HASH record removing \n", __FUNCTION__, __LINE__);
  HASH_DEL(g_records, rec);
  free(rec);

  return 0;
}

/**
 * API method function for unregisterKey  -- Now this one is DEPRECATED
 *
 * @param ski
 * @param asn
 * @param keyID
 *
 * @return 0 on success
 */
u_int32_t unregisterKey (u_int8_t* ski, u_int32_t asn, u_int32_t keyID)
{
  /* first parameters health check */
  if (asn == 0)
  {
    sca_debugLog(LOG_ERR, "+ [libcrypto][%s:%d] input parameters error\n", __FUNCTION__, __LINE__);
    return 0;
  }

  unsigned int hash_id=0;
  Record_t *rec = NULL;
  BGPSecKey *bsKey = NULL;


  rec = restoreKeyInfo(0, ski, asn);
  if(rec)
  {
    bsKey = (BGPSecKey *)rec->data;
    hash_id = rec->hh.hashv;

    sca_debugLog (LOG_DEBUG, "[%s:%d] Found a key record (hash id : %x, bgpsec key info data:%p, EC_KEY:%p) \n",
        __FUNCTION__, __LINE__, hash_id, bsKey, bsKey?bsKey->keyData:NULL);

    // unregister and delete key info data from HASH
    deleteKeyInfo(rec);
  }
  else
  {
    sca_debugLog (LOG_DEBUG, "[%s:%d] Can't find a key record from HASH\n", __FUNCTION__, __LINE__);
    return 0;
  }

  return 0;
}


/**
 * API method function for unregisterPrivateKey
 *
 * @param inID indicates a unique hash element
 *
 * @return 0 on success
 */
u_int8_t unregisterPrivateKey(u_int8_t inID)
{
  EC_KEY    *ec_key     = NULL;
  BGPSecKey *tmpBsKey   = NULL;
  u_int8_t keyID = inID - RET_ID_OFFSET;
  void      *en_buf;

  sca_debugLog (LOG_DEBUG, "[%s:%d] UnregisterPrivateKey called with key id: %x \n",
      __FUNCTION__, __LINE__, keyID);

  if(keyID != stEnbuf_Eckey[keyID].id)
  {
    sca_debugLog(LOG_ERR, "keyID is different:%x \n", stEnbuf_Eckey[keyID].id);
    return 0;
  }

  ec_key = stEnbuf_Eckey[keyID].ec_key;
  en_buf = stEnbuf_Eckey[keyID].en_buf;

  /* Remove from uthash */
  Record_t *s;
  for(s= g_records; s!=NULL; s=(Record_t *)(s->hh.next))
  {
    tmpBsKey = s->data;
    if( (s->hh.hashv & (((g_records)->hh.tbl->num_buckets) -1)) == keyID )
    {
      if( en_buf == (void*)tmpBsKey->keyData )
      //if( memcmp(en_buf, (void*)tmpBsKey->keyData, tmpBsKey->keyLength) == 0)
      {
        sca_debugLog(LOG_INFO, "+ [libcrypto][%s:%d] HASH record removing \n", __FUNCTION__, __LINE__);
        sca_debugLog (LOG_DEBUG, " === Item Found to be deleted === id:%x keyData:%p\n", s->hh.hashv, en_buf);
        //deleteKeyInfo(s);
        HASH_DEL(g_records,  s);
        free(s);
      }
    }
  }

  if (ec_key)
  {
    sca_debugLog(LOG_DEBUG, "ec key pointer: %p is about to be freed\n", ec_key);
    EC_KEY_free(ec_key);
  }

  if(en_buf)
  {
    sca_debugLog(LOG_DEBUG, "DER-encoded key pointer: %p is about to be freed\n", en_buf);
    OPENSSL_free(en_buf);
  }

  stEnbuf_Eckey[keyID].ec_key = NULL;
  stEnbuf_Eckey[keyID].en_buf = NULL;
  stEnbuf_Eckey[keyID].id   = 0;

  return 0;
}

/**
 * print public key into standard output for debugging
 *
 * @param ec_key    ecdsa key pointer
 */
void PrintPrivPubKeyHex(EC_KEY* ec_key)
{
  if(!ec_key)
  {
    printf(" ec_key error \n");
    return;
  }
  if(((struct ec_key_st*)ec_key)->priv_key)
  {
    printf("\n ----- [%s] printing out private key hex ----- \n", __FUNCTION__);
    int i=0;
    for(i=0; i<((struct ec_key_st*)ec_key)->priv_key->dmax; i++)
    {
      printf("%x ", (int)(((struct ec_key_st*)ec_key)->priv_key->d)[i]);
    }
    printf("\n\n");
  }

  printf("\n ----- [%s] printing out pub key hex ----- \n", __FUNCTION__);
  BN_CTX *ctx;
  ctx = BN_CTX_new();
  char * cc = EC_POINT_point2hex(ec_key->group, ec_key->pub_key, POINT_CONVERSION_UNCOMPRESSED/*4*/, ctx);
  printf("pub: %s\n", cc);
  printf("\n\n");
}

/**
 * determines whether input string is DER format
 *
 * @param p containes string pointer as an input
 * @param length: string length
 *
 * @return  1: private
 *          0: public
 *          negative: not DER format
 */
int IS_DER_PRIVATE(unsigned char *p, unsigned short length)
{
#define ID_SEQUENCE         0x30
#define ID_INTEGER          0x02
#define ID_OCTET_STRING     0x04

  unsigned char pos = 0;

  if(!p)
  {
    sca_debugLog(LOG_ERR, "buff is NULL\n");
    return -1;
  }
  if (p[pos++] != ID_SEQUENCE)
  {
    sca_debugLog(LOG_ERR, "Not DER data\n");
    return -1;
  }

  unsigned char  init_len = 0;
  unsigned short int_len = 0;
  unsigned char subseq_len =0;

  /* ITU-T Rec. X.690, 8.1.3.5: initial octet as a long term length octet indicator */
  init_len = p[pos++]; // offset(01): eigher total length or initial octet as a long term octet

  if(length < 127 && !(init_len & 0x80))
  {
    /* DER: SEQUENCE 0x30,  INTEGER 0x02, and OCTET_STRING 0x04 indicator position */
    if(p[pos] == ID_INTEGER) // offet(02)
    {
      pos++;
      int_len = p[pos++];
      pos += int_len;

      if(p[pos] == ID_OCTET_STRING)
      {
        sca_debugLog(LOG_INFO, "Private octet string in DER\n");
        return 1;
      }
    }

    /* DER: SEQUENCE 0x30, SEQUENCE 0x30 indicator position */
    else if(p[pos++] == ID_SEQUENCE) // offet(02)
    {
      sca_debugLog(LOG_INFO, "Public octet string in DER\n");
      return 0;
    }
  }
  else /* octet length is larger than 127 octec */
  {
    subseq_len = init_len & 0x7f; // the number of subsequent octet length
    pos += subseq_len;

    if(p[pos] == ID_INTEGER)
    {
      pos++;
      int_len = p[pos++];
      pos += int_len;

      if(p[pos++] == ID_OCTET_STRING)
      {
        sca_debugLog(LOG_INFO, "Private octet string in DER (length > 127)\n");
        return 1;
      }
    }
    else if(p[pos] == ID_SEQUENCE)
    {
      sca_debugLog(LOG_INFO, "Public octet string in DER (length > 127)\n");
      return 0;
    }
  }

  return -1;
}

/**
 * This method determines if the API provides the extended public key
 * management. In this case the extended validation method extValidate can be
 * called.
 *
 * @return 0: does not provide complete extended functionality
 *         1: does provide extended functionality
 */
int isExtended()
{
  sca_debugLog (LOG_DEBUG, "Called 'isExtended'\n");
  return 1;
}
/**
 * Return 1 if this API allows the storage of private keys, otherwise 0.
 *
 * @return 0: Does not provide private key storage
 */
int isPrivateKeyStorage()
{
  sca_debugLog (LOG_DEBUG, "Called 'isPrivateKeyStroage'\n");
  return 1;
}

/**
 * Generate a debugging hex printout.
 *
 * @param len the buffer length
 * @param buff the buffer to be printed out.
 */
__attribute__((always_inline)) inline void printHex(int len, unsigned char* buff)
{
  int i;
  for(i=0; i < len; i++ )
  {
    if(i%16 ==0) printf("\n");
    printf("%02x ", buff[i]);
  }
  printf("\n");
}

/**
 * This init method has no function at all
 *
 * @param value value will be ignored
 *
 * @return 1 for success
 *
 * @since 0.1.2.0
 */
int init(const char* value)
{
  // Just to be compliant with the specification
  return 1;
}
