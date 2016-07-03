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
 * @version 0.4.2.0
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *   0.4.2.0 - 2016/06/14 - oborchert
 *             * Added documentation to functions and modified the parameters
 *               slightly.
 *             * Added free_SCAHashMessage
 *             * Renamed bgpsecPathAttribute to constructBGPSecPathAttribute to
 *               be more self explanatory.
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


#define BGPSEC_VERIFY_ERROR         -1
#define BGPSEC_VERIFY_INVALID       0
#define BGPSEC_VERIFY_SUCCESS       1

#define BGPSEC_MAX_SIGBLOCK         2

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
  u_int8_t    pCount;
  u_int8_t    flags;
  u_int32_t   asNum;
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
/**
 * Returns the pointer to the internal crypto api.
 *  
 * @return Returns the pointer to the internal crypto api
 */
SRxCryptoAPI* getSrxCAPI();
int bgpsec_path_attr_cmp (const void *arg1, const void *arg2);
unsigned int bgpsec_path_attr_key_make (void *p);
/**
 * This function duplicate the original attribute and its sub structures into a 
 * new instance or generate a new empty one if requested. Freeing the memory
 * of the original one does NOT affect the duplicate.
 * 
 * @param orig The original bgpsec path attribute (can be NULL)
 * @param newIfNULL generate a new empty structure if the original one is NULL.
 * 
 * @return A copy of the given structure or a new one if the original is NULL 
 *         and the attribute newIfNULL is set to true.
 */
struct BgpsecPathAttr * bgpsecDup(struct BgpsecPathAttr *orig, bool newIfNULL);

void concatPathSegment(struct PathSegment * const , struct PathSegment * const);
void concatSigSegment(struct SigSegment* const , struct SigSegment * const);
void concatSigBlock(struct SigBlock* const , struct SigBlock * const);

/**
 * @brief bgpsecVerify library function caller from external calling,
 * i.e., bgp_info_set_validation_result() at bgp_route.c
 *
 * @param peer The peer information
 * @param attr The attribtue itself
 * @param p The refix
 * @param status The status information
 *
 * @return BGPSEC_VERIFY_ERROR, BGPSEC_VERIFY_INVALID, BGPSEC_VERIFY_SUCCESS
 */
extern int bgpsecVerifyCaller(struct peer *peer, struct attr *attr, 
                              struct prefix p, sca_status_t* status);

/**
 * Construct the BGPSEC Path attribute. This includes signing the as path if it 
 * is not signed already.
 * This function writes the data into the stream.
 * 
 * @param bgp    The bgp session
 * @param peer   The peer information
 * @param aspath Pointer to the as path.
 * @param p      The prefix
 * @param s      The stream
 * @param attr   The bgp attribute. 
 *
 * @return : total number of bgpsec Secure_Path + Signature_Block
 *      TODO: new_bpa must be cleared, otherwise the memory leak
 */
int constructBGPSecPathAttribute(struct bgp *bgp, struct peer *peer, 
                                 struct aspath *aspath, struct prefix* p,
                                 struct stream *s, struct attr *attr,
                                 u_int8_t flags, u_int8_t pCount,
                                 SCA_Signature** signature, int numSignatures);

int bgpsecSanityCheck(struct BgpsecPathAttr *);

/**
 * This function parses the byte stream and generates the internal
 * bgpsecPathAttr structure. In case the handed update is malformed no
 * bgpsecPathAttr is generated and the return value is NULL
 *
 * @param attr The attribute.
 * @param peer The bgpsec session information
 * @param s The stream containing the attribute information.
 * @param length total length of bgpsec pdu including Secure_Path and Signature_Block
 *
 * @return The BgpsecPathAttr as pointer structure or NULL in case the BGPSEC
 *         attribute is malformed. 
 */
struct BgpsecPathAttr* bgpsec_parse(struct attr *attr, struct peer *peer, 
                                    struct stream* s, size_t length);

/**
 * This method does call the signing of the BGPSEC path attribute. This method
 * assumes that the peer is NOT an iBGP peer.
 * 
 * @param bgp The bgp session.
 * @param peer The peer to sign it too
 * @param pfx The prefix to sign over (only for origin anouncements)
 * @param attr The attribute containing the path information.
 * @param pCount The pCount of this update
 * @param flags the update flags.
 * 
 * @return The generated signature. If managed by the SrxCryptoAPI module
 *         then it must be freed by the crypto module, otherwise it can be freed
 *         using sca_freeSignature or manual using free etc.
 * 
 * @see srxcryptoapi.h:sca_freeSignature
 */
SCA_Signature* signBGPSecPathAttr(struct bgp* bgp, struct peer* peer, 
                                  struct prefix* pfx, struct attr* attr, 
                                  u_int8_t pCount, u_int8_t flags);

/**
 * This function is a wrapper for the corresponding CAPI function. This function
 * is needed to allow the memory management performed by the CAPI itself.
 * 
 * @param message The hashInput to be freed.
 * 
 * @since 0.4.2.0
 */
void freeSCA_HashMessage(SCA_HashMessage* message);



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
