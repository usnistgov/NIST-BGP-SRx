
#ifndef _BGPSEC_OPENSSL_H
#define _BGPSEC_OPENSSL_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */


#ifndef NULL
# define NULL (void *)0
#endif

#include <sys/types.h>
#include "../srxcryptoapi.h"
#include <stdarg.h>
#include <string.h>

/* Openssl ecdsa include files */
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>

/* Macro Definitions */
#define API_BGPSEC_VERIFY_SUCCESS       0
#define API_BGPSEC_VERIFY_ERROR         1
#define API_BGPSEC_VERIFY_FAILURE       2

#define API_BGPSEC_SUCCESS 0
#define API_BGPSEC_FAILURE -1

#define API_BGPSEC_ALGO_ID_256          1
#define API_BGPSEC_OPENSSL_ID_SHA256_ECDSA_P_256 NID_X9_62_prime256v1
#define API_BGPSEC_DEFAULT_CURVE API_BGPSEC_ALGO_ID_256

#define DEFAULT_KEYFILE_EXT   "key"
#define DEFAULT_CERTFILE_EXT  "cert"
#define DEFAULT_KEYBFILE_EXT  "key.bin"
#define DEFAULT_CERTBFILE_EXT "cert.bin"

#define API_DISABLE_LOAD_PRIV_KEY      0
#define API_ENABLE_LOAD_PRIV_KEY       1

#define BGPSEC_SKI_LENGTH           20
#define BGPSEC_ALGO_ID              1
#define BGPSEC_ALGO_ID_LENGTH       1
#define BGPSEC_MAX_SIG_LENGTH       128
#define BGPSEC_MAX_INFO_ATTR_LENGTH 0


#define OCTET_SECURE_PATH_SEGMENT   6
#define OCTET_SECURE_PATH_LEN       2
#define OCTET_ALGORITHM_ID          1
#define OCTET_SIG_BLOCK_LEN         2
#define OCTET_SIGNATURE_LEN         2

/* debug macro */
#define TERM_DEBUG LOG_DEBUG//0x07
#define IS_DEBUG_ENABLED (term_debug == (TERM_DEBUG))

#define RET_ID_OFFSET 1
#define ID_NUM_MAX 32

typedef u_int32_t as_t;

/* Macro Definition */
#define GEN_SKI_ASCII(buf, ski, ski_len)        \
do {                                        \
  char* cp = buf;                           \
  int i;                                    \
  for(i=0; i<ski_len; i++) {                \
    sprintf(cp, "%02X", (u_int8_t)ski[i]);  \
    cp+=2;                                  \
  }                                         \
  buf[sizeof(buf)-1] = '\0';                \
} while(0)

#define PSIZE(a) (((a) + 7) / (8))


////////////////////////////////////////////////////////////////////////////////
// Crypto Interface
////////////////////////////////////////////////////////////////////////////////

int validate(BgpsecPathAttr *bpa, u_int16_t number_keys,
             BGPSecKey** keys, void *data, u_int32_t localAS);

int sign_with_key(BGPSecSignData* bgpsec_data, BGPSecKey* key);

int sign_with_id(u_int16_t dataLength, u_int8_t* data, u_int8_t keyID,
                      u_int16_t sigLen, u_int8_t* signature);


/*  function declaration for openssl related functions */
int cl_BgpsecDoVerifySignature (u_int8_t *, int , EC_KEY    *, int , u_int8_t *, int );
int cl_BgpsecSetEcKey(const char *, EC_KEY **, int , int );
int cl_BgpsecSetEcPrivateKey(const char *, EC_KEY **, int );
int cl_BgpsecSetEcPublicKey(const char *, EC_KEY **, int );
int cl_BgpsecECDSA_Sign (u_int8_t *, int , EC_KEY *, u_int8_t *, int );
EVP_PKEY * cl_GetPrivateKey(const char *);
X509 * cl_GetPublicKey(const char *);
int cl_BgpsecVerify (BgpsecPathAttr *, u_int16_t , BGPSecKey** , void *, u_int32_t);
int cl_BgpsecSanityCheck(BgpsecPathAttr *);
int cl_SignParamSanityCheck(BGPSecSignData *, BGPSecKey *);
unsigned char* cl_BgpsecOctetDigest(const unsigned char* , unsigned int , unsigned char* );
int IS_DER_PRIVATE(unsigned char *p, unsigned short length);

/*
   this structure is defined in 'ec_lcl.h',
   but this file is not included in the openssl-ecdsa installed packages
 */
struct ec_key_st {
  int version;

  EC_GROUP *group;

  EC_POINT  *pub_key;
  BIGNUM    *priv_key;

  unsigned int enc_flag;
  point_conversion_form_t conv_form;

  int references;

  void *method_data;  /* was EC_EXTRA_DATA */
} /* EC_KEY */;

#include <netinet/in.h>
struct prefix
{
  u_char family;
  u_char prefixlen;
  union
  {
    u_char prefix;
    struct in_addr prefix4;
#ifdef HAVE_IPV6
    struct in6_addr prefix6;
#endif /* HAVE_IPV6 */
    struct
    {
      struct in_addr id;
      struct in_addr adv_router;
    } lp;
    u_char val[8];
  } u __attribute__ ((aligned (8)));
};


/* hash data processing */
//#include "bgpsec_openssl/uthash.h"
#include <uthash.h>
typedef struct {
  unsigned int asn;
} DataKey_t;

typedef struct {
  DataKey_t key;
  u_int8_t* ski;
  void *data;
  UT_hash_handle hh;
} Record_t;

struct KeyInfoData
{
  u_int32_t keyID;
  u_int32_t asn;
};      // key ID info containier

#endif /* _SRXCRYPTOAPI_H*/
