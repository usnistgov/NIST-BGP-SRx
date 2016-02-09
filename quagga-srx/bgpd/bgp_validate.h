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
 * Provides functionality for BGPSEC path validation.
 *
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *   0.1.4.3 - 2015/10/09 - oborchert
 *             * NIST Header applied.
 *   0.1.0.0 - 2015 - kyehwanl
 *             * File Generated.
 */
#ifndef _QUAGGA_BGP_VALIDATE_H
#define _QUAGGA_BGP_VALIDATE_H

#ifdef USE_SRX

#define BGPSEC_SKI_LENGTH           20
#define BGPSEC_ALGO_ID              1
#define BGPSEC_ALGO_ID_LENGTH       1
#define BGPSEC_MAX_SIG_LENGTH       128
#define BGPSEC_AFI_LENGTH           1
#define BGPSEC_MAX_INFO_ATTR_LENGTH 0


#define BGPSEC_SUCCESS 0
#define BGPSEC_FAILURE -1

#define BGPSEC_ALGORITHM_SHA256_ECDSA_P_256 1
#define BGPSEC_OPENSSL_ID_SHA256_ECDSA_P_256 NID_X9_62_prime256v1
#define BGPSEC_DEFAULT_CURVE BGPSEC_ALGORITHM_SHA256_ECDSA_P_256

#define DEFAULT_KEY_REPO_PATH "/var/lib/bgpsec-keys/"
#define DEFAULT_KEYFILE_EXT   "key"
#define DEFAULT_CERTFILE_EXT  "cert"
//#define DEFAULT_KEYBFILE_EXT  "key.bin"
//#define DEFAULT_CERTBFILE_EXT "cert.bin"

#define BGPSEC_VERIFY_SUCCESS       1
#define BGPSEC_VERIFY_ERROR         -1
#define BGPSEC_VERIFY_MISMATCH      0

#define OCTET_SECURE_PATH_SEGMENT   6
#define OCTET_SECURE_PATH_LEN       2
#define OCTET_ALGORITHM_ID          1
#define OCTET_SIG_BLOCK_LEN         2
#define OCTET_SIGNATURE_LEN         2

/* BGPSEC_PATH segment data in abstracted form, no limit is placed on length */
struct PathSegment
{
  struct PathSegment    *next;
  u_int32_t             as;
  u_int8_t              pCount;
  u_int8_t              flags;
  unsigned long         refcnt;
};

struct SigSegment
{
  struct SigSegment     *next;
  u_char                *ski;
  u_int16_t             sigLen;
  u_char                *signature;
  unsigned long         refcnt;
};

struct SigBlock
{
  struct SigBlock       *next;
  u_int16_t             sigBlockLen;
  u_int8_t              algoSuiteId;
  struct SigSegment     *sigSegments;
  unsigned long         refcnt;
};

/* BGPSEC path may be include some BGPSEC Segments.  */
struct BgpsecPathAttr
{
  size_t                securePathLen;

  /* segment data */
  struct PathSegment    *pathSegments;
  struct SigBlock       *sigBlocks;

  /* Reference count to this bgpsec path.  */
  unsigned long         refcnt;
};


/* BGPSEC protocol pdu format structure */
struct BgpsecPdu
{
  size_t      len_SecurePath;
  u_int32_t   asNum;
  u_int8_t    pCount;
  u_int8_t    flags;
  u_int16_t   len_SigBlock;
  u_int8_t    algoSuiteId;
  u_char      *ski;
  u_int16_t   len_Sig;
  u_char      *signature;
};


static inline void
put_u32(void *p, u_int32_t x)
{
  x = htonl(x);
  memcpy(p, &x, 4);
}

extern int bgpsecSignDataWithAsciiSKI();
struct BgpsecPathAttr *bgpsec_path_intern (struct BgpsecPathAttr *bpa);
void bgpsec_path_unintern (struct BgpsecPathAttr **pbpa);
void bgpsec_path_free (struct BgpsecPathAttr *bpa);
void bgpsec_path_attr_finish (void);
void bgpsec_path_attr_init (void);
int bgpsec_path_attr_cmp (const void *arg1, const void *arg2);
unsigned int bgpsec_path_attr_key_make (void *p);
struct BgpsecPathAttr * bgpsecDup(struct BgpsecPathAttr *orig);
void concatPathSegment(struct PathSegment * const , struct PathSegment * const);
void concatSigSegment(struct SigSegment* const , struct SigSegment * const);
void concatSigBlock(struct SigBlock* const , struct SigBlock * const);
extern int bgpsecVerifyCaller(struct peer *, struct BgpsecPathAttr *, struct prefix );

int bgpsecPathAttribute(struct bgp *, struct peer *, struct aspath *, struct prefix *,
                        struct stream *, struct BgpsecPathAttr *);
int bgpsecVerifySingle(struct peer *, struct BgpsecPathAttr *, struct prefix);
int bgpsecVerify(struct peer *, struct BgpsecPathAttr *, struct prefix);
int bgpsecSanityCheck(struct BgpsecPathAttr *);
struct BgpsecPathAttr *bgpsec_parse(struct peer *, struct stream *, size_t,
                                    afi_t, struct bgp_nlri *, int*);
struct BgpsecPathAttr * bgpsec_parse_iBGP(struct peer *, struct stream *, size_t);
int bgpsecPathAttribute_iBGP(struct bgp *, struct peer *, struct aspath *,
                        struct prefix *, struct stream *, struct BgpsecPathAttr *);
void test_print(struct BgpsecPdu , size_t *, char *, char* , size_t );
void print_signature(struct BgpsecPathAttr *);
unsigned char hex2bin_byte(char* );

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


#endif /* USE_SRX */
#endif /* !_QUAGGA_BGP_VALIDATE_H */
