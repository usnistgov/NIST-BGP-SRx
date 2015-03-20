
#include <zebra.h>
#ifdef USE_SRX

#include "log.h"
#include "hash.h"
#include "jhash.h"
#include "memory.h"
#include "vector.h"
#include "prefix.h"
#include "log.h"
#include "stream.h"
#include "vty.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_validate.h"

#ifdef USE_SRX_CRYPTO_API
#include "srxcryptoapi.h"
SRxCryptoAPI *g_capi;
#define RET_ID_OFFSET 1
#endif

/* Hash for bgpsec path.  This is the top level structure of BGPSEC AS path. */
static struct hash *bgpsechash;
// Forward declarations
static void * ski_new(void);
static void *signature_new(size_t size);
static struct PathSegment* pathSegment_New(void);
static struct SigSegment* sigSegment_New(void);
static struct SigBlock* sigBlock_New(void);
static void bgpsec_sigBlock_free_all (struct SigBlock *sb);
static void bgpsec_sigBlock_free (struct SigBlock *sb);
static void sigSegment_free_all(struct SigSegment *ss);
static void sigSegment_free(struct SigSegment *ss);
static void bgpsec_path_segment_free_all (struct PathSegment *seg);
static void bgpsec_path_segment_free (struct PathSegment *seg);
static struct BgpsecPathAttr * bgpsec_path_attr_new (void);
static void * bgpsec_path_hash_alloc (void *arg);

/* If two aspath have same value then return 1 else return 0 */
int bgpsec_path_attr_cmp (const void *arg1, const void *arg2)
{
  const struct PathSegment *seg1 = ((const struct BgpsecPathAttr *)arg1)->pathSegments;
  const struct PathSegment *seg2 = ((const struct BgpsecPathAttr *)arg2)->pathSegments;

  const struct SigBlock *sb1 = ((const struct BgpsecPathAttr *)arg1)->sigBlocks;
  const struct SigBlock *sb2 = ((const struct BgpsecPathAttr *)arg2)->sigBlocks;

  while (seg1 || seg2)
    {
      if ((!seg1 && seg2) || (seg1 && !seg2))
	return 0;
      if (seg1->as != seg2->as)
        return 0;
      if (seg1->pCount != seg2->pCount)
        return 0;
      if (seg1->flags != seg2->flags)
          return 0;
      seg1 = seg1->next;
      seg2 = seg2->next;
    }

  while (sb1 || sb2)
    {
      if ((!sb1 && sb2) || (sb1 && !sb2))
	return 0;
      if (sb1->sigBlockLen != sb2->sigBlockLen)
        return 0;
      if (sb1->algoSuiteId != sb2->algoSuiteId)
        return 0;
      /* TODO: need to have more better comparing  using SKI and signature
       * not only using sigSegments
       * Because comparing sigSegemts are just address comparing, so it need to compare more
       * concrete data like sigSegments->ski, ski_leng and signature */
      if (sb1->sigSegments != sb2->sigSegments)
          return 0;
      sb1 = sb1->next;
      sb2 = sb2->next;
    }
  return 1;
}


/* Make hash value by raw bgpsec path attr data. */
unsigned int bgpsec_path_attr_key_make (void *p)
{
  struct BgpsecPathAttr *bpa = (struct BgpsecPathAttr *) p;
  struct PathSegment *seg = bpa->pathSegments;
  struct SigBlock *sb = bpa->sigBlocks;
  struct SigSegment *ss;
  unsigned int key = 0;

  if (BGP_DEBUG (bgpsec, BGPSEC_DETAIL))
  {
    zlog_debug("[BGPSEC] [%s]: bpa:%p, seg:%p, sb:%p sigSeg:%p AS:%d ", \
        __FUNCTION__, bpa, seg, sb, sb->sigSegments, seg->as);
  }

  if (sb)
  {
    ss = sb->sigSegments;
    key += jhash(sb, 4, 0);
    key += jhash (ss->signature, ss->sigLen, 0);
  }
  /*
  else if(seg)
  {
    u_int32_t as = seg->as;

    key += (as & 0xff000000) >> 24;
    key += (as & 0x00ff0000) >> 16;
    key += (as & 0x0000ff00) >> 8;
    key += (as & 0x000000ff);
  }
  */
  else
  {
#define MIX(val)	key = jhash_1word(val, key)
    MIX(bpa->securePathLen);
    key += jhash(bpa->pathSegments, 4, 0);
    key += jhash(bpa->sigBlocks, 4, 0);
  }

  if (BGP_DEBUG (bgpsec, BGPSEC_DETAIL))
  {
    zlog_debug("[BGPSEC] [%s]:  - - key = =:%d, index:%d", \
        __FUNCTION__, key, key % 32767);
  }
  return key;
}

/* AS path hash initialize. */
void bgpsec_path_attr_init (void)
{
  // aspath_init initialize its aspath hash as many as the number of 32767 hashes, so follows the same number
  bgpsechash = hash_create_size (32767, bgpsec_path_attr_key_make, bgpsec_path_attr_cmp);

#ifdef USE_SRX_CRYPTO_API
  g_capi = malloc(sizeof(SRxCryptoAPI));
  g_capi->libHandle = NULL;
  g_capi->configFile = NULL;
  g_capi->registerPrivateKey = NULL;
  g_capi->unregisterPrivateKey = NULL;
  g_capi->sign_with_id = NULL;
  g_capi->sign_with_key = NULL;
  g_capi->validate = NULL;
  if(srxCryptoInit(g_capi) == 0)
  {
    zlog_err("[BGPSEC] SRxCryptoAPI not initialized!\n");
  }
#endif
}

void bgpsec_path_attr_finish (void)
{
  hash_free (bgpsechash);
  bgpsechash = NULL;
}

static void * bgpsec_path_hash_alloc (void *arg)
{
  const struct BgpsecPathAttr *bpa = arg;
  struct BgpsecPathAttr *new;
  struct PathSegment *newSeg, *origSeg;

  /* Malformed AS path value. */
  assert (bpa->sigBlocks);
  assert (bpa->pathSegments);
  if (! bpa->sigBlocks->sigSegments)
    return NULL;

  /* New aspath structure is needed. */
  new = bgpsec_path_attr_new();
  new->securePathLen    = bpa->securePathLen;
  new->pathSegments     = pathSegment_New();

  /* pathSegment allocation according to the number of segments */
  origSeg   = bpa->pathSegments;
  newSeg    = new->pathSegments;
  while(origSeg)
  {
    *newSeg  = *origSeg; //struct copy

    if(origSeg->next)
    {
      newSeg->next = pathSegment_New();
      newSeg = newSeg->next;
    }

    origSeg = origSeg->next;
  }

  /* sigBlock allocation according to the number of segments */
  struct SigSegment *newSig, *origSig;
  if(bpa->sigBlocks)
  {
    new->sigBlocks = sigBlock_New();
    *new->sigBlocks = *bpa->sigBlocks; // sigBlock struct copy

    newSig = new->sigBlocks->sigSegments = sigSegment_New();
    origSig = bpa->sigBlocks->sigSegments;

    while (origSig)
    {
      *newSig = *origSig;     // sigSegment strcut copy

      /* ski allocation and copy from arg */
      if(origSig->ski)
      {
        newSig->ski = calloc (1, BGPSEC_SKI_LENGTH);
        memcpy(newSig->ski, origSig->ski, BGPSEC_SKI_LENGTH);
      }

      /* signature allocation and copy from arg */
      if(origSig->signature)
      {
        newSig->signature = calloc (1, origSig->sigLen);
        memcpy(newSig->signature, origSig->signature, origSig->sigLen);
      }

      if(origSig->next)
      {
        newSig->next = sigSegment_New();
        newSig = newSig->next;
      }

      origSig = origSig->next;
    } /* while */
  } /* if - sigBlock */

  new->refcnt = 0;
  return new;
}

static struct BgpsecPathAttr * bgpsec_path_attr_new (void)
{
  struct BgpsecPathAttr *new;
  new = XCALLOC (MTYPE_BGPSEC_PATH, sizeof (struct BgpsecPathAttr));
  memset(new, 0x00, sizeof(struct BgpsecPathAttr));
  return new;
}

static struct BgpsecPathAttr * bgpsec_path_attr_all_new(void)
{

  struct BgpsecPathAttr *bpa;
  struct PathSegment *seg;
  struct SigBlock *sb;
  struct SigSegment *ss;

  bpa = bgpsec_path_attr_new();
  seg = bpa->pathSegments = pathSegment_New();
  sb = bpa->sigBlocks = sigBlock_New();
  ss = sb->sigSegments = sigSegment_New();
  if(ss && seg) ;

  return bpa;
}

static void bgpsec_path_segment_free (struct PathSegment *seg)
{
  if (!seg)
    return;

  //memset (seg, 0x00, sizeof(struct PathSegment ));
  XFREE (MTYPE_BGPSEC_PATH_SEG, seg);

  return;
}

/* free entire chain of segments */
static void bgpsec_path_segment_free_all (struct PathSegment *seg)
{
  struct PathSegment *prev;

  while (seg)
    {
      prev = seg;
      seg = seg->next;
      bgpsec_path_segment_free (prev);
    }
}

static void sigSegment_free(struct SigSegment *ss)
{
  if (!ss)
    return;

  /* free for ski and signature */
  if(ss->ski)
    free(ss->ski);

  if(ss->signature)
    free(ss->signature);

  memset (ss, 0x00, sizeof(struct SigSegment ));

  /* but here, call xfree for Signature Segment itself */
  XFREE (MTYPE_BGPSEC_SIG_SEG, ss);
  return;
}

static void sigSegment_free_all(struct SigSegment *ss)
{
  struct SigSegment *prev;

  while (ss)
  {
    prev = ss;
    ss = ss->next;
    sigSegment_free(prev);
  }
}

static void bgpsec_sigBlock_free (struct SigBlock *sb)
{
  if (!sb)
    return;

  sigSegment_free_all(sb->sigSegments);

  //memset (sb, 0x00, sizeof(struct SigBlock));
  XFREE (MTYPE_BGPSEC_SIG_BLK, sb);

  return;
}

/* free entire chain of Signature_Block segments */
static void bgpsec_sigBlock_free_all (struct SigBlock *sb)
{
  struct SigBlock *prev;

  while (sb)
  {
    prev = sb;
    sb = sb->next;
    bgpsec_sigBlock_free (prev);
  }
}

/* Free BGPSEC path attr structure. */
void bgpsec_path_free (struct BgpsecPathAttr *bpa)
{
  if (!bpa)
    return;

  if (bpa->pathSegments)
    bgpsec_path_segment_free_all (bpa->pathSegments);

  if (bpa->sigBlocks)
    bgpsec_sigBlock_free_all (bpa->sigBlocks);

  //memset(bpa, 0x00, sizeof(struct BgpsecPathAttr));
  XFREE (MTYPE_BGPSEC_PATH, bpa);

  return;
}


/* Unintern bgpsec path attr from bgpsec path attr bucket. */
void bgpsec_path_unintern (struct BgpsecPathAttr **pbpa)
{
  if (BGP_DEBUG (bgpsec, BGPSEC_DETAIL))
    zlog_debug("[BGPSEC]  bgpsec_path_unintern function called");
  struct BgpsecPathAttr *ret;
  struct BgpsecPathAttr *bpa = *pbpa;

  if (bpa->refcnt)
    bpa->refcnt--;

  if (bpa->refcnt == 0)
    {
      /* This bgpsec path attr must exist in bgpsec path attr hash table. */
      ret = hash_release (bgpsechash, bpa);
      assert (ret != NULL);
      if (BGP_DEBUG (bgpsec, BGPSEC_DETAIL))
        zlog_debug("[BGPSEC] [%s] bpa: %p will be uninterned ", __FUNCTION__, bpa);
      bgpsec_path_free (bpa);
      *pbpa = NULL;
    }
}


/* Intern allocated bgpsec path attr. */
struct BgpsecPathAttr *bgpsec_path_intern (struct BgpsecPathAttr *bpa)
{
  struct BgpsecPathAttr *find;

  /* Assert this BGPSEC path attr structure is not interned. */
  assert (bpa->refcnt == 0);

  /* Check bgpsec path attr hash. */
  find = hash_get (bgpsechash, bpa, bgpsec_path_hash_alloc);

#ifdef DEBUG_TEST
  if (BGP_DEBUG (bgpsec, BGPSEC_DETAIL))
    zlog_debug("[BGPSEC]  [%s]: find: %p (refcnt:%ld) Vs bpa: %p",\
        __FUNCTION__, find, find->refcnt, bpa);
#endif

  if (find != bpa)
    bgpsec_path_free (bpa);

  find->refcnt++;

  return find;
}


/**
 * @brief
 *
 * @param
 *
 * @return
 */
static struct PathSegment* pathSegment_New(void)
{
  struct PathSegment *new;
  new = XCALLOC (MTYPE_BGPSEC_PATH_SEG, sizeof (struct PathSegment));
  memset(new, 0x00, sizeof(struct PathSegment));

  return new;
}

/* ski allocation */
static void * ski_new(void)
{
  return calloc (1, BGPSEC_SKI_LENGTH);
}

/* signature allocation */
static void *signature_new(size_t size)
{
    return calloc (1, size);
}

static struct SigSegment* sigSegment_New(void)
{

  struct SigSegment *new;
  new = XCALLOC (MTYPE_BGPSEC_SIG_SEG, sizeof (struct SigSegment));
  memset(new, 0x00, sizeof(struct SigSegment));

  return new;
}

static struct SigBlock* sigBlock_New(void)
{
  struct SigBlock *new;
  new = XCALLOC (MTYPE_BGPSEC_SIG_BLK, sizeof (struct SigBlock));
  memset(new, 0x00, sizeof(struct SigBlock));

  return new;
}


/**
 * This function parses the byte stream and generates the internal
 * bgpsecPathAttr structure. In case the handed update is malformed no
 * bgpsecPathAttr is generated and the return value is
 *
 * @param s
 * @param length : total length of bgpsec pdu including Secure_Path and Signature_Block
 *
 * @return
 */
struct BgpsecPathAttr * bgpsec_parse(struct peer *peer, struct stream *s,
                                     size_t length, int *errCode)
{
  struct BgpsecPdu pdu;
  u_char *startp, *endp;
  size_t start_getp, start_endp, spp, sbp;

  memset (&pdu, 0x00, sizeof(struct BgpsecPdu));

  /* sanity check */
  if (STREAM_READABLE(s) < length
      || length <= 0)
  {
    zlog_err("bad bgpsec packet - length mismatch");
    return NULL;
  }

  startp = BGP_INPUT_PNT (peer); // current address pointer
  start_getp = stream_get_getp (s);
  start_endp = stream_get_endp (s);
  endp = startp + length;

  if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
    zlog_debug("[IN] %p -  startp: %p-- getp:%d endp:%d -- endp(startp+length):%p length:%d ", \
        stream_pnt(s), startp, start_getp, start_endp, endp, length);

  /* get prefix from nlri */
  struct prefix p;
  int psize;
  size_t nlrip = start_getp + length;

  p.family = AF_INET;
  p.prefixlen = stream_getc_from(s, nlrip++);
  psize = PSIZE (p.prefixlen);

  u_int32_t nlri=0;

  int i;
  for(i=0; i<psize; i++)
  {
    nlri |= stream_getc_from(s, nlrip+i) <<  8 *i;
  }

  if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
    zlog_debug("[IN] - -- - nlri: %08x ntolh(nlri): %08x", nlri, ntohl(nlri));

  memcpy (&p.u.prefix, &nlri, psize);

  if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
    zlog_debug("[IN] prefixlen:%d psize:%d nlri:%08x p.u.prefix:%08x",
        p.prefixlen, psize, nlri, p.u.prefix);

  int numSecurePathSegment = 0;
  //u_char *bptr;

  if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
    zlog_debug("[IN] peer as:%d peer->local_as:%d Secure_Path Len:%d",\
        peer->as, peer->local_as, stream_getw_from(s, start_getp));

  /* calculation of total aspath length using SecurePath Len */
  u_int16_t spl = stream_getw_from(s, start_getp), numSeg=0;
  if( (spl-OCTET_SECURE_PATH_LEN) % OCTET_SECURE_PATH_SEGMENT != 0)
  {
    zlog_err(" SecurePath Length parsing error");
    return NULL;
  }
  numSeg = (spl - OCTET_SECURE_PATH_LEN) / OCTET_SECURE_PATH_SEGMENT;

  struct BgpsecPathAttr *bpa = NULL, *ret = NULL;
  //struct BgpsecPathAttr *new_bpa;
  struct PathSegment *seg;
  struct SigBlock *sb;
  struct SigSegment *ss;

  /*
   * If this is the originating AS
   */
  if(numSeg < 2)
  {
    /* single different version */
    bpa = bgpsec_path_attr_new();
    seg = bpa->pathSegments = pathSegment_New();
    sb = bpa->sigBlocks = sigBlock_New();
    ss = sb->sigSegments = sigSegment_New();
    ss->ski = ski_new();


    if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
      zlog_debug("[IN] bpa:%p, seg:%p, sb:%p, ss:%p", \
          bpa, bpa->pathSegments, bpa->sigBlocks, bpa->sigBlocks->sigSegments);

    /* Secure_Path */
    bpa->securePathLen = stream_getw(s);
    spp = stream_get_endp (s); // secure path pointer
    seg->as           = stream_getl(s);
    seg->pCount          = stream_getc(s);
    seg->flags           = stream_getc(s);
    seg->next           = NULL;

    /* Signature_Blocks */
    sbp = stream_get_endp (s); // signature block pointer
    sb->sigBlockLen     = stream_getw(s);
    sb->algoSuiteId     = stream_getc(s);
    sb->next            = NULL;

    if(spp && sbp && start_endp && endp) ; // for later use

    /* Signature Segment under Signature_Block */
    //bptr = stream_pnt(s);
    stream_get(ss->ski, s, BGPSEC_SKI_LENGTH);
    ss->sigLen           = stream_getw(s);
    ss->signature = signature_new(ss->sigLen);
    stream_get(ss->signature, s, ss->sigLen);


#ifdef USE_SRX_CRYPTO_API
    BGPSecKey *outKeyInfo=NULL;
    u_int16_t num_key = 1;

    /* call the library function --> bgpsecVerify */
    if (g_capi->libHandle == NULL)
    {
      *errCode = BGPSEC_VERIFY_ERROR;
      zlog_debug("[%s:%d] api handle error", __FUNCTION__, __LINE__);
      goto ValidateFail;
    }

    if(!outKeyInfo)
    {
      if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
        zlog_debug("[%s:%d] calling validation function WITHOUT keys ", __FUNCTION__, __LINE__);

      /* call the library function --> bgpsecVerify */
      if( g_capi->validate((BgpsecPathAttr*)bpa, 0, NULL, &p, peer->local_as) != BGPSEC_VERIFY_SUCCESS)
      {
        *errCode = BGPSEC_VERIFY_ERROR;
        goto ValidateFail;
      }
    }
    else
    {
      if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
        zlog_debug("[%s:%d] calling validation function with keys ", __FUNCTION__, __LINE__);
      if( g_capi->validate((BgpsecPathAttr*)bpa, num_key, &outKeyInfo, &p, peer->local_as) != BGPSEC_VERIFY_SUCCESS)
      {
        *errCode = BGPSEC_VERIFY_ERROR;
        goto ValidateFail;
      }
    }
#else
    //if( bgpsecVerify(peer, bpa, p) != BGPSEC_VERIFY_SUCCESS)
      //goto ValidateFail;
#endif

    /* bgpsec parsed info intern */
    ret = bpa;

    if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
      zlog_debug("[IN] %s: [INTERNed] bgpsec path attr: %p",\
          __FUNCTION__, bpa);

  } /* end of if */

  /*
   * in case not origin as, which means transit router
   */
  else
  {
    u_short iter;
    struct PathSegment  *prev = NULL, *head = NULL;

    /* BGPSEC_Path Attribute and others */
    bpa = bgpsec_path_attr_new();

    /* Secure_Path len */
    bpa->securePathLen = stream_getw(s);

    /* Secure_Path length includes two octets used to express its own length field */
    iter = numSecurePathSegment =
      (bpa->securePathLen - OCTET_SECURE_PATH_LEN) / OCTET_SECURE_PATH_SEGMENT;

    /* read the multiple Secure_Path Segments */
    while(iter)
    {
      seg = pathSegment_New();

      /* concatenating */
      if(prev)
        prev->next = seg;
      else
        bpa->pathSegments = head = seg;

      seg->as = stream_getl (s);
      seg->pCount = stream_getc(s);
      seg->flags = stream_getc(s);

      if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
        zlog_debug("[IN]  Secure_Path segments? --> %d AS:%d", iter, seg->as);

      prev = seg;

      iter--;

    } /* end of while */

    /*
     * TODO: the code for parsing the 2nd Signature Block(sb2)
     * But, here, just assumed one Sigature Block received.
    */
    struct SigSegment *ss_prev = NULL, *ss_head = NULL;
    sb = bpa->sigBlocks = sigBlock_New();   // new Signature_Block instance
    sb->sigBlockLen     = stream_getw(s);   // Signature_Block Length
    sb->algoSuiteId     = stream_getc(s);   // Algorithm Suite Identifier
    ss = NULL;

    iter = numSecurePathSegment;    // reset iterration

    /* read the multiple Signature_Segments */
    while(iter)
    {
      if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
        zlog_debug("[IN]  iteration of SigSegment:%d ", iter);

      /* create instances */
      ss = sigSegment_New();
      ss->ski = ski_new();

      stream_get(ss->ski, s, BGPSEC_SKI_LENGTH);    // SKI
      ss->sigLen           = stream_getw(s);        // Signature Length
      ss->signature = signature_new(ss->sigLen);
      stream_get(ss->signature, s, ss->sigLen);     // signauture

      /* concatenating */
      if(ss_prev)
        ss_prev->next = ss;
      else
        sb->sigSegments = ss_head = ss;

      ss_prev = ss;

      iter--;

    } /* end of while */

#ifdef USE_SRX_CRYPTO_API
    BGPSecKey *outKeyInfo[numSecurePathSegment];
    memset(outKeyInfo, 0, numSecurePathSegment * sizeof(BGPSecKey*));

    /* call the library function --> bgpsecVerify */
    if (g_capi->libHandle == NULL)
    {
      *errCode = BGPSEC_VERIFY_ERROR;
      goto ValidateFail;
    }

    /* TODO: more robust function to check all key pointers in array below */
    //IS_KEYINFO_OK
    if(!outKeyInfo[0])
    {
      if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
        zlog_debug("[%s:%d] calling validation function WITHOUT keys ", __FUNCTION__, __LINE__);

      /* call the library function --> bgpsecVerify */
      if( g_capi->validate((BgpsecPathAttr*)bpa, 0, NULL, &p, peer->local_as)\
          != BGPSEC_VERIFY_SUCCESS)
      {
        *errCode = BGPSEC_VERIFY_ERROR;
        goto ValidateFail;
      }
    }
    else
    {
      if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
        zlog_debug("[%s:%d] calling validation function with keys ", __FUNCTION__, __LINE__);
      if( g_capi->validate((BgpsecPathAttr*)bpa, numSecurePathSegment, \
            outKeyInfo, &p, peer->local_as) != BGPSEC_VERIFY_SUCCESS)
      {
        *errCode = BGPSEC_VERIFY_ERROR;
        goto ValidateFail;
      }
    }

    /* release all resources - keyInfoData or others */
    //if(keyInfo) free(keyInfo);
#else
    //if( bgpsecVerify(peer, bpa, p) != BGPSEC_VERIFY_SUCCESS)
      //goto ValidateFail;
#endif

    /* bgpsec parsed info intern */
    //new_bpa = bgpsec_path_intern(bpa);
    //new_bpa = bpa;
    //ret = new_bpa;
    ret = bpa;

    if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
      zlog_debug("[IN]  %s: return value(final bpa): %p", __FUNCTION__, bpa);
  } /* end of else */


  return ret;

ValidateFail:
  /* clearing due to error */
  // bgpsec-protocol-draft section5.2
  if (BGP_DEBUG (bgpsec, BGPSEC))
    zlog_debug("[BGPSEC]  %s: Vaildation Failed !! (bpa): %p Error Code: %d",\
        __FUNCTION__, bpa, *errCode);
  return bpa;
//  bgpsec_path_free (bpa);
//  return NULL;
}

struct BgpsecPathAttr * bgpsec_parse_iBGP(struct peer *peer, struct stream *s,
                                          size_t length)
{
  u_char *startp, *endp;
  size_t start_getp, start_endp, spp, sbp;
  struct BgpsecPathAttr *bpa =NULL, *ret = NULL;
  struct PathSegment *seg;
  struct SigBlock *sb;
  struct SigSegment *ss;
  //u_char *bptr;

  startp = BGP_INPUT_PNT (peer); // current address pointer
  start_getp = stream_get_getp (s);
  start_endp = stream_get_endp (s);
  endp = startp + length;

  if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
    zlog_debug("[IN] [%s] start", __FUNCTION__);

  /* sanity check */
  if (STREAM_READABLE(s) < length
      || length <= 0)
  {
    zlog_err("bad bgpsec packet - length mismatch");
    return NULL;
  }

  /* get prefix from nlri */
  struct prefix p;
  int psize;
  size_t nlrip = start_getp + length;

  p.prefixlen = stream_getc_from(s, nlrip++);
  psize = PSIZE (p.prefixlen);

  u_int32_t nlri=0;

  int i;
  for(i=0; i<psize; i++)
  {
    nlri |= stream_getc_from(s, nlrip+i) <<  8 *i;
  }

  if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
    zlog_debug("[IN] - -- - nlri: %08x ntolh(nlri): %08x", nlri, ntohl(nlri));

  memcpy (&p.u.prefix, &nlri, psize);

  if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
    zlog_debug("[IN] prefixlen:%d psize:%d nlri:%08x p.u.prefix:%08x",
        p.prefixlen, psize, nlri, p.u.prefix );

  /* calculation of total aspath length using SecurePath Len */
  u_int16_t spl = stream_getw_from(s, start_getp);


  /*
   * If this message is from the originating AS in iBGP peers
   */
  if(spl == (OCTET_SECURE_PATH_SEGMENT + OCTET_SECURE_PATH_LEN)
      && length <= 14) /* 14 : bgpsec message size of bgpsecPathAttribute_iBGP() */
  {
    if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
      zlog_debug("[IN] originating AS in iBGP peers");
    bpa = bgpsec_path_attr_new();
    seg = bpa->pathSegments = pathSegment_New();
    sb = bpa->sigBlocks = sigBlock_New();
    ss = sb->sigSegments = sigSegment_New();
    //ss->ski = ski_new();

    /* Secure_Path */
    bpa->securePathLen = stream_getw(s);
    spp = stream_get_endp (s); // secure path pointer
    seg->as             = stream_getl(s);
    seg->pCount         = stream_getc(s);
    seg->flags          = stream_getc(s);
    seg->next           = NULL;

    /* Signature_Blocks */
    sbp = stream_get_endp (s); // signature block pointer
    sb->sigBlockLen     = stream_getw(s);
    sb->algoSuiteId     = stream_getc(s);
    sb->next            = NULL;

    if(spp && sbp && start_endp && endp) ; // for later use

    /* Signature Segment under Signature_Block */
    //bptr = stream_pnt(s);
    ss->ski[0]          = stream_getc(s); // dummy in iBGP
    ss->sigLen          = stream_getc(s); // dummy
    ss->signature[0]    = stream_getc(s); // dummy
  }

  /* else this message is NOT from the Original AS in iBGP peers */
  else
  {
    if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
      zlog_debug("[IN] transit AS in iBGP peers");
    u_short iter;
    int numSecurePathSegment = 0;
    struct PathSegment  *prev = NULL, *head = NULL;

    /* BGPSEC_Path Attribute and others */
    bpa = bgpsec_path_attr_new();

    /* Secure_Path len */
    bpa->securePathLen = stream_getw(s);

    /* Secure_Path length includes two octets used to express its own length field */
    iter = numSecurePathSegment =
      (bpa->securePathLen - OCTET_SECURE_PATH_LEN) / OCTET_SECURE_PATH_SEGMENT;


    /* read the multiple Secure_Path Segments */
    while(iter)
    {
      seg = pathSegment_New();

      /* concatenating */
      if(prev)
        prev->next = seg;
      else
        bpa->pathSegments = head = seg;

      seg->as = stream_getl (s);
      seg->pCount = stream_getc(s);
      seg->flags = stream_getc(s);

      if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
        zlog_debug("[IN]  Secure_Path segments? --> %d AS:%d", iter, seg->as);

      prev = seg;

      iter--;

    } /* end of while */


    /*
     * TODO: the code for parsing the 2nd Signature Block(sb2)
     * But, here, just assumed one Sigature Block received.
     */
    struct SigSegment *ss_prev = NULL, *ss_head = NULL;
    sb = bpa->sigBlocks = sigBlock_New();   // new Signature_Block instance
    sb->sigBlockLen     = stream_getw(s);   // Signature_Block Length
    sb->algoSuiteId     = stream_getc(s);   // Algorithm Suite Identifier
    ss = NULL;

    iter = numSecurePathSegment;    // reset iterration

    /* read the multiple Signature_Segments */
    while(iter)
    {
      if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
        zlog_debug("[IN]  iteration of SigSegment:%d ", iter);

      /* create instances */
      ss = sigSegment_New();
      ss->ski = ski_new();

      stream_get(ss->ski, s, BGPSEC_SKI_LENGTH);    // SKI
      ss->sigLen           = stream_getw(s);        // Signature Length
      ss->signature = signature_new(ss->sigLen);
      stream_get(ss->signature, s, ss->sigLen);     // signauture

      /* concatenating */
      if(ss_prev)
        ss_prev->next = ss;
      else
        sb->sigSegments = ss_head = ss;

      ss_prev = ss;

      iter--;

    } /* end of while */

  } /* end of else */

  ret = bpa;
  return ret;
}


/**
 * @brief
 *
 * @param bgp
 * @param peer
 * @param p
 * @param s
 *
 * @return : total number of bgpsec Secure_Path + Signature_Block
 *      TODO: new_bpa tmpBpa must be cleared, otherwise the memory leak
 */
int bgpsecPathAttribute(struct bgp *bgp, struct peer *peer,
                        struct aspath *aspath, struct prefix *p, struct stream *s,
                        struct BgpsecPathAttr *bpa)
{
  size_t cp;
  u_int8_t sigbuff[BGPSEC_MAX_SIG_LENGTH];
  /* hashbuff must also be >= 24, but this should be >= 24 */
  u_int8_t hashbuff[BGPSEC_MAX_SIG_LENGTH + 10];
  u_int8_t bski[BGPSEC_SKI_LENGTH];
  u_int8_t pCount = 0;
  u_int8_t spFlags = 0x00;
  int sig_length = 0;
  unsigned int i;

#define OFFSET_BGP_FLAG 4
#define OFFSET_BGP_ATTR 3
  cp = stream_get_endp (s);
  u_char fBgpAttr = stream_getc_from(s, cp - OFFSET_BGP_ATTR );
  u_char fBgpFlag = stream_getc_from(s, cp - OFFSET_BGP_FLAG );
  /* clean out any previous data in buffers */
  bzero(sigbuff, BGPSEC_MAX_SIG_LENGTH);
  bzero(hashbuff, (BGPSEC_MAX_SIG_LENGTH + 10));
  bzero(bski, BGPSEC_SKI_LENGTH);

  as_t remoteAS = peer->as;
  as_t localAS = bgp->as;
  as_t oas  = aspath_origin_as (aspath);

  if(bgp->bgpsec_ski == NULL)
  {
    zlog_err(" bgpsec SKI error: converting configuration SKI to binary");
    zlog_err("[1] bgp->bgpsec_ski is NULL");
    return -1;
  }

  /* bgpsec SKI : converting configuration SKI to binary */
  for(i=0; i< BGPSEC_SKI_LENGTH; i++)
    bski[i] = hex2bin_byte(bgp->bgpsec_ski+(i*2));

  if(aspath->segments == NULL)
    return -1;

  if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
  {
    zlog_debug("[OUT] duplicated bgpsec_aspath:%p aspath->segments:%p", aspath, aspath->segments);
    if((aspath!=NULL) && (aspath->segments != NULL))
    {
      zlog_debug("[OUT] aspath[%p] segments length: %d type:%d ref counter:%ld str:%s", \
          aspath, aspath->segments->length, aspath->segments->type, \
          aspath->refcnt, aspath->str);
      zlog_debug("[OUT] as : %d %d", aspath->segments->as[0], aspath->segments->as[1]);
    }
    zlog_debug("[OUT] ATTR:cp[%d]: 0x%02X FLAG:cp[%d]: 0x%02X ",
        cp-OFFSET_BGP_ATTR, fBgpAttr, cp-OFFSET_BGP_FLAG, fBgpFlag );
  }

  // TODO: enable this after error debuggin
#if 1 //  error debugging for aspath  goes 0
  /* in case of 2nd iBGP router, (iBGP -- iBGP --> eBGP) */
  int fInternalBgpsecPathAttr = 0;
  if(aspath->segments->length > 0)
    if(bpa && bpa->pathSegments->as == 0 \
        && bpa->sigBlocks->sigSegments->ski == NULL \
        && bpa->sigBlocks->sigSegments->signature ==NULL )
      fInternalBgpsecPathAttr = 1;

  /* if this is the original AS for the NLRI */
  if( (aspath->segments->length == 1 && !bpa)
      || fInternalBgpsecPathAttr)
#else
  /* if this is the original AS for the NLRI */
  if(aspath->segments->length == 1 && !bpa)
#endif
  {

    /* Sequence of octets to be signed (Origin)
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
     * | NLRI Length             : 1 octet   |
     * +-------------------------------------+
     * | NLRI prefix             : (variable)|
     * +-------------------------------------+
     */

    pCount = 1;
    /* create data to sign */
    put_u32(hashbuff, remoteAS);
    put_u32(hashbuff+4, oas);


    if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
      zlog_debug("[OUT] ++ origin AS: %d remote AS:%d local AS: %d", oas, remoteAS, localAS);

    /* pCount of 1, and no confed flag handling yet */
    hashbuff[8] = pCount;
    hashbuff[9] = 0x00;
    hashbuff[10] = BGPSEC_ALGO_ID;
    hashbuff[11] = p->prefixlen; // NLRI length

    size_t psize = PSIZE (p->prefixlen);
    memcpy((hashbuff+12), &p->u.prefix, psize); // NLRI prefix

    if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
      zlog_debug("[OUT] prefix_length: %d psize: %d, prefix: 0x%08x", \
          p->prefixlen, psize, p->u.prefix);

#ifdef USE_SRX_CRYPTO_API
    u_int8_t keyID=0;
    BGPSecKey* outKeyInfo=NULL;

    BGPSecSignData bgpsecSignData = {
      .dataLength       = (12+psize),
      .data             = hashbuff,
      .algoID           = BGPSEC_ALGO_ID,
      .sigLen           = BGPSEC_MAX_SIG_LENGTH,
      .signature        = sigbuff,
    };

    bgpsecSignData.ski = (u_int8_t *)malloc(BGPSEC_SKI_LENGTH);
    memcpy(bgpsecSignData.ski, bski, BGPSEC_SKI_LENGTH);

    /* Register Private Key information */
    outKeyInfo= (BGPSecKey*) malloc(sizeof(BGPSecKey));
    if(!outKeyInfo)
    {
      if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
        zlog_err("[%s:%d] mem allocation failed", __FUNCTION__, __LINE__);
    }
    else
    {
      memset(outKeyInfo, 0x0, sizeof(BGPSecKey));
      outKeyInfo->algoID        = BGPSEC_ALGO_ID;
      outKeyInfo->asn           = localAS;
      memcpy(outKeyInfo->ski, bski, BGPSEC_SKI_LENGTH);

      /* load key info */
      if(sca_loadKey(outKeyInfo, 1) == 0)
      {
        if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
          zlog_err("[%s:%d] failed to load key", __FUNCTION__, __LINE__);
        outKeyInfo->keyData = NULL;
        outKeyInfo->keyLength = 0;
      }

      /* call register function in srx crypto api */
      keyID = g_capi->registerPrivateKey(outKeyInfo);

      if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
      {
        if(outKeyInfo && outKeyInfo->keyData)
          zlog_debug("[OUT] out key: %p, ec key:%p key_id:%x", \
              outKeyInfo, outKeyInfo->keyData, keyID - RET_ID_OFFSET);
      }
    }

#ifdef SIGN_WITH_ID_ENABLED
    sig_length = g_capi->libHandle == NULL ? 0
                 : g_capi->sign_with_id((12+psize), hashbuff, keyID, BGPSEC_MAX_SIG_LENGTH, sigbuff);
#else /* SIGN_WITH_ID_ENABLED */
    sig_length = g_capi->libHandle == NULL ? 0
                 : g_capi->sign_with_key(&bgpsecSignData, outKeyInfo);
#endif /* SIGN_WITH_ID_ENABLED */

    /* release parameter resources */
    if(bgpsecSignData.ski)
      free(bgpsecSignData.ski);
    if(outKeyInfo)
    {
      if(outKeyInfo->keyData)
        free(outKeyInfo->keyData);
      free(outKeyInfo);
    }
#endif /* USE_SRX_CRYPTO_API */

    if ( 1 >= sig_length )
    {
      if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
        zlog_err("[OUT] bgpsec_sign:%d>%d:o: signing failed", localAS, remoteAS);
      return -1;
    }

    if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
    {
      zlog_debug("[OUT] signature print");
      /* signature print out */
      for(i=0; i<(unsigned int)sig_length; i++ )
      {
        if(i%16 ==0) printf("\n");
        printf("%02x ", (unsigned char)sigbuff[i]);
      }
      printf("\n");
    }


    u_int16_t sig_segments_len = 0;
    sig_segments_len = OCTET_SIG_BLOCK_LEN + OCTET_ALGORITHM_ID + \
                       sig_length + BGPSEC_SKI_LENGTH + OCTET_SIGNATURE_LEN;

    if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
      zlog_debug("[OUT] sig segments len: 0x%02x sig_len: 0x%02x", sig_segments_len, sig_length );

    /* add new bgpsec sig attr */
    /* Secure Path Length */
    stream_putw (s, 8);       // 8 = Secure_Path len(2) + Secure_Path segment(6)

    /* Secure Path Segment */
    stream_putl (s, (u_int32_t) localAS);       // AS number
    stream_putc (s, pCount);                    // pcount =1
    stream_putc (s, spFlags);                   // Secure Path Segment Flag

    /* Signature Block */
    stream_putw (s, sig_segments_len);          // Signature_Block Length
    stream_putc (s, BGPSEC_ALGO_ID);            // Algorithm Suite Identifier

    /* Signature Segments */
    stream_put (s, bski, BGPSEC_SKI_LENGTH);    // Subject Key Identifier
    stream_putw (s, sig_length);                // Signature Length
    stream_put (s, sigbuff, sig_length);        // Signature

  } /* if this is the original AS for the NLRI */


  /* else we are Not the Original AS */
  /* copy and add secure path, add info, add signature to signature
     segment list */
  else if((aspath->segments->length > 1)
      || (aspath->segments->length == 1 && bpa)) // 2nd case for iBGP transmitting router 'from' peer is eBGP
  {

    if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
      zlog_debug("[OUT] -- This part more than 2 BGPSEC nodes -- ");
    u_short  aspathLen = aspath->segments->length;

    /* Sanity check */
    if(bgpsecSanityCheck(bpa) != 0)
    {
      if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
        zlog_debug("[OUT] bgpsec Path Attr structure error ");
      return -1;
    }

    struct BgpsecPathAttr *tmpBpa;//   = *bpa;
    struct PathSegment *tmpSeg, *pntSeg;//   = *bpa->pathSegments;
    struct SigBlock *tmpSb, *pntSb;//   = *bpa->sigBlocks;
    struct SigSegment *tmpSs, *pntSs;//   = *bpa->sigBlocks->sigSegments;

    /* duplicate bgpsecPathAttr structure including sub-structures,
     * result in a new BgpsecPathAttr instance */
    struct BgpsecPathAttr *new_bpa = bgpsecDup(bpa);
    if(!new_bpa)
      return -1;

    /*   Sequence of octets to be signed (transit)
     * +-----------------------------------------+
     * | Target AS Number               4 octets |
     * +-----------------------------------------+
     * | Signer's AS Number             4 octet s|
     * +-----------------------------------------+
     * | pCount                         1 octet  |
     * +-----------------------------------------+
     * | Flags                          1 octet  |
     * +-----------------------------------------+
     * | Most Recent Sig Field         (variable)|
     * +-----------------------------------------+
     */

    /* create data to sign */
    size_t sigSegLen = new_bpa->sigBlocks->sigSegments->sigLen;
    put_u32(hashbuff, remoteAS);
    put_u32(hashbuff+4, localAS);
    /* pCount of 1, and no confed flag handling yet */
    pCount = 1;
    hashbuff[8] = pCount;   // pCount
    hashbuff[9] = 0x00;     // Flags
    memcpy(hashbuff+10, new_bpa->sigBlocks->sigSegments->signature, sigSegLen);

    size_t totalHashLen = 10 + sigSegLen;

    if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
    {
      zlog_debug("[OUT] ---- HASH sending total length: %d----", totalHashLen);
      for(i=0; i < totalHashLen; i++ )
      {
        if(i%16 ==0) printf("\n");
        printf("%02x ", hashbuff[i]);
      }
      printf("\n");
    }

#ifdef USE_SRX_CRYPTO_API
    u_int32_t keyID=0;
    BGPSecKey* outKeyInfo=NULL;

    BGPSecSignData bgpsecSignData = {
      .dataLength       = totalHashLen,
      .data             = hashbuff,
      .algoID           = BGPSEC_ALGO_ID,
      .sigLen           = BGPSEC_MAX_SIG_LENGTH,
      .signature        = sigbuff,
    };

    bgpsecSignData.ski = (u_int8_t *)malloc(BGPSEC_SKI_LENGTH);
    memcpy(bgpsecSignData.ski, bski, BGPSEC_SKI_LENGTH);

    /* Register Private Key information */
    outKeyInfo= (BGPSecKey*) malloc(sizeof(BGPSecKey));
    if(!outKeyInfo)
    {
      if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
        zlog_err("[%s:%d] mem allocation failed", __FUNCTION__, __LINE__);
    }
    else
    {
      memset(outKeyInfo, 0x0, sizeof(BGPSecKey));
      outKeyInfo->algoID        = BGPSEC_ALGO_ID;
      outKeyInfo->asn           = localAS;
      memcpy(outKeyInfo->ski, bski, BGPSEC_SKI_LENGTH);

      /* load key info */
      if(sca_loadKey(outKeyInfo, 1) == 0)
      {
        if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
          zlog_err("[%s:%d] failed to load key", __FUNCTION__, __LINE__);
        outKeyInfo->keyData = NULL;
        outKeyInfo->keyLength = 0;
      }

      /* call register function in srx crypto api */
      keyID = g_capi->registerPrivateKey(outKeyInfo);

      if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
      {
        if(outKeyInfo && outKeyInfo->keyData)
          zlog_debug("[OUT] out key: %p, ec key:%p key_id:%x", \
              outKeyInfo, outKeyInfo->keyData, keyID - RET_ID_OFFSET);
      }
    }

#ifdef SIGN_WITH_ID_ENABLED
    sig_length = g_capi->libHandle == NULL ? 0
                 : g_capi->sign_with_id(totalHashLen, hashbuff, keyID, BGPSEC_MAX_SIG_LENGTH, sigbuff);
#else /* SIGN_WITH_ID_ENABLED */
    sig_length = g_capi->libHandle == NULL ? 0
                 : g_capi->sign_with_key(&bgpsecSignData, outKeyInfo);
#endif /* SIGN_WITH_ID_ENABLED */

    /* release parameter resources */
    if(bgpsecSignData.ski)
      free(bgpsecSignData.ski);

    if(outKeyInfo)
    {
      if(outKeyInfo->keyData)
        free(outKeyInfo->keyData);
      free(outKeyInfo);
    }
#endif /* USE_SRX_CRYPTO_API */

    if ( 1 >= sig_length )
    {
      if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
        zlog_err("[OUT] bgpsec_sign:%d>%d:o: signing failed", localAS, remoteAS);
      return -1;
    }

    if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
    {
      zlog_debug("[OUT] signature print");
      /* signature print out */
      for( i=0; i< (unsigned int)sig_length; i++ )
      {
        if(i%16 ==0) printf("\n");
        printf("%02x ", (unsigned char)sigbuff[i]);
      }
      printf("\n");
    }

    /* first, fill in and concatenate this router information */
    /* BGPSEC_Path attribute and Secure_Path structures */
    tmpBpa = bgpsec_path_attr_new();
    tmpBpa->securePathLen = aspathLen * OCTET_SECURE_PATH_SEGMENT + OCTET_SECURE_PATH_LEN;
    tmpBpa->pathSegments = tmpSeg = pathSegment_New();

    /* Secure_Path Segments structure */
    tmpSeg->next = new_bpa->pathSegments; // prepend the list of Path_Segment in the 1st position
    tmpSeg->as = localAS;
    tmpSeg->pCount = 1;
    tmpSeg->flags = spFlags;

    /* Signature_Block structure */
    tmpBpa->sigBlocks = tmpSb = sigBlock_New();
    tmpSb->sigBlockLen = 0;                    // this field will be filled blow
    tmpSb->algoSuiteId = BGPSEC_ALGO_ID;       // algorith ID
    tmpSb->sigSegments = tmpSs = sigSegment_New();

    /* Signature Segment blocks */
    tmpSs->next  = new_bpa->sigBlocks->sigSegments; // prepend the list of Sig Segment in the 1st position
    tmpSs->ski = ski_new();
    memcpy(tmpSs->ski, bski, BGPSEC_SKI_LENGTH); // SKI extension of this RPKI router certificate that is used to verify the signature
    tmpSs->sigLen = sig_length;
    tmpSs->signature = signature_new(sig_length);
    memcpy(tmpSs->signature, sigbuff, sig_length);


    if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
      zlog_debug("[OUT] bpa(param):%p new_bpa(duplicated):%p, tmpBpa(final concat):%p",\
          bpa, new_bpa, tmpBpa);

    /* fill in the PDU's with all according to the BGPSEC protocols
     * Secure_Path, Signature_Block and Signature Segment */
    size_t sizep_PathLen = stream_get_endp (s); // Secure_Path length pointer
    stream_putw (s, 0);       // 8 = Secure_Path len(2) + Secure_Path segment(6)

    pntSeg = tmpSeg;
    u_short iter = aspathLen;
    u_short numSecurePathTotal = OCTET_SECURE_PATH_LEN; // initial value

    //while(iter && pntSeg)
    while(pntSeg)
    {
      stream_putl (s, (u_int32_t) pntSeg->as);       // AS number
      stream_putc (s, pntSeg->pCount);                    // pcount =1
      stream_putc (s, pntSeg->flags);                   // Secure Path Segment Flag

      numSecurePathTotal += OCTET_SECURE_PATH_SEGMENT;
      iter--;

      if(pntSeg->next == NULL)
        break;

      pntSeg = pntSeg->next;
    }
    //stream_putw_at (s, sizep_PathLen, tmpBpa->securePathLen); // Secure_Path Len
    stream_putw_at (s, sizep_PathLen, numSecurePathTotal); // Secure_Path Len


    /* fill in Signature_Block */
    pntSb = tmpSb;
    pntSs = tmpSs;
    iter  = aspathLen;
    size_t sizep_SigBlkLen = stream_get_endp (s); // Signature_Block length pointer
    u_short numSigTotal =0;

    while(pntSb)
    {
      stream_putw (s, 0);                           // Signature_Block dummy value
      stream_putc (s, pntSb->algoSuiteId);          // Algorithm Suite Identifier

      /* Signature Segments */
      //while(iter && pntSs)
      while(pntSs)
      {
        stream_put (s, pntSs->ski, BGPSEC_SKI_LENGTH);    // Subject Key Identifier

        if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
        {
          for(i=0; i<BGPSEC_SKI_LENGTH; i++ )
          {
            printf("%02x ", (unsigned char)pntSs->ski[i]);
          }
          printf("  --- SKI \n");
        }

        stream_putw (s, pntSs->sigLen);                     // Signature Length
        stream_put (s, pntSs->signature, pntSs->sigLen);    // Signature

        numSigTotal += pntSs->sigLen;
        iter--;
        pntSs = pntSs->next;
      }

      pntSb = pntSb->next;
    }

    /* Signature_Block Len */
    stream_putw_at (s, sizep_SigBlkLen, numSigTotal + \
        OCTET_SIG_BLOCK_LEN + OCTET_ALGORITHM_ID + \
        aspathLen * (BGPSEC_SKI_LENGTH + OCTET_SIGNATURE_LEN));

    if (BGP_DEBUG (bgpsec, BGPSEC_DETAIL))
    {
      zlog_debug("[BGPSEC] segments test - from: bpa:%p", bpa);
      struct PathSegment *tmp_seg = bpa->pathSegments;
      struct SigSegment *tmp_sig = bpa->sigBlocks->sigSegments;

      for(i=0; tmp_seg; i++, tmp_seg = tmp_seg->next)
      {
        printf("path_seg[%d]:%p -->  ", i, tmp_seg);
      }
      printf("\n");

      for(i=0; tmp_sig; i++, tmp_sig = tmp_sig->next)
      {
        printf("sig_seg [%d]:%p -->  ", i, tmp_sig);
      }
      printf("\n");
    }

    /* release temporary instance */
    bgpsec_path_free(tmpBpa);

  } /* end of else if */


  /* 2nd case for iBGP transmitting router */
  //else if(aspath->segments->length == 1 && bpa) {}

  else
  {
    return -1;
  }

  return stream_get_endp (s) - cp;
}

/* send bgpsec Path Attribute for iBGP peers */
int bgpsecPathAttribute_iBGP(struct bgp *bgp, struct peer *peer,
                        struct aspath *aspath, struct prefix *p, struct stream *s,
                        struct BgpsecPathAttr *bpa)
{

  size_t cp;
  u_int8_t pCount = 0;
  u_int8_t spFlags = 0x00;
  int sig_length = 0;
  u_int16_t sig_segments_len = 0;
  int i;

  cp = stream_get_endp (s);
  as_t localAS = bgp->as;

  /* if this is the original AS for the NLRI in iBGP peers */
  /* a new BGPSEC_Path attribute with zero Secure_Path segments and zero
     Signature_Segments.  */
  //if(aspath->segments->length == 1)
  if(bpa == NULL)
  {
    if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
      zlog_debug("[OUT] [%s]null bpa, so that send NULL values", __FUNCTION__);

    localAS = 0;
    pCount = 0;
    sig_segments_len = 2 + sig_length + BGPSEC_ALGO_ID_LENGTH +3; // with no ski length

    stream_putw (s, OCTET_SECURE_PATH_SEGMENT + OCTET_SECURE_PATH_LEN);

    /* Secure Path Segment */
    stream_putl (s, (u_int32_t) localAS);       // AS number
    stream_putc (s, pCount);                    // pcount =1
    stream_putc (s, spFlags);                   // Secure Path Segment Flag

    /* Signature Block */
    stream_putw (s, sig_segments_len);          // Signaturea_Block Length
    stream_putc (s, BGPSEC_ALGO_ID);            // Algorithm Suite Identifier

    /* Signature Segments */
    stream_putc (s, 0x00);    // Subject Key Identifier
    stream_putc (s, 0x00);    // Signature Length
    stream_putc (s, 0x00);    // Signature
  }


  /* else we are Not the Original AS in iBGP peers */
  /* copying the BGPSEC_Path attribute from the received update message */
  else
  {
    if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
      zlog_debug("[OUT] [%s] copy and send bgpsecPathAttr values", __FUNCTION__);

    //struct BgpsecPathAttr *pntBpa;
    struct PathSegment *pntSeg;
    struct SigBlock *pntSb;
    struct SigSegment *pntSs;

    u_short  aspathLen = aspath->segments->length;

    /* duplicate bgpsecPathAttr structure including sub-structures,
     * result in a new BgpsecPathAttr instance */
    struct BgpsecPathAttr *new_bpa = bgpsecDup(bpa);
    if(!new_bpa)
      return -1;

    /* fill in the PDU's with all according to the BGPSEC protocols
     * Secure_Path, Signature_Block and Signature Segment */
    size_t sizep_PathLen = stream_get_endp (s); // Secure_Path length pointer
    stream_putw (s, 0);       // 8 = Secure_Path len(2) + Secure_Path segment(6)

    u_short iter = aspathLen;
    //pntBpa = new_bpa;
    pntSeg = new_bpa->pathSegments;

    while(iter && pntSeg)
    {
      stream_putl (s, (u_int32_t) pntSeg->as);       // AS number
      stream_putc (s, pntSeg->pCount);                    // pcount =1
      stream_putc (s, pntSeg->flags);                   // Secure Path Segment Flag

      iter--;

      if(pntSeg->next == NULL)
        break;

      pntSeg = pntSeg->next;
    }
    stream_putw_at (s, sizep_PathLen, new_bpa->securePathLen); // Secure_Path Len


    /* fill in Signature_Block */
    pntSb = new_bpa->sigBlocks;
    pntSs = new_bpa->sigBlocks->sigSegments;
    iter  = aspathLen;
    //size_t sizep_SigBlkLen = stream_get_endp (s); // Signature_Block length pointer
    u_short numSigTotal =0;

    while(pntSb)
    {
      stream_putw (s, pntSb->sigBlockLen);          // Signature_Block length
      stream_putc (s, pntSb->algoSuiteId);          // Algorithm Suite Identifier

      /* Signature Segments */
      while(iter && pntSs)
      {
        stream_put (s, pntSs->ski, BGPSEC_SKI_LENGTH);    // Subject Key Identifier

        if (BGP_DEBUG (bgpsec, BGPSEC_OUT) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
        {
          for(i=0; i<BGPSEC_SKI_LENGTH; i++ )
          {
            printf("%02x ", (unsigned char)pntSs->ski[i]);
          }
          printf("  --- SKI \n");
        }

        stream_putw (s, pntSs->sigLen);                     // Signature Length
        stream_put (s, pntSs->signature, pntSs->sigLen);    // Signature

        numSigTotal += pntSs->sigLen;
        iter--;
        pntSs = pntSs->next;
      }

      pntSb = pntSb->next;
    }

    /* release temporary instance */
    bgpsec_path_free(new_bpa);

  } /* end of else */

  return stream_get_endp (s) - cp;

}


/**
 * @brief bgpsecVerify library function caller from external calling,
 * i.e., bgp_info_set_validation_result() at bgp_route.c
 *
 * @param peer
 * @param bpa
 * @param p
 *
 * @return
            BGPSEC_VERIFY_SUCCESS       0
            BGPSEC_VERIFY_ERROR         1
            BGPSEC_VERIFY_MISMATCH      2
 */
extern int bgpsecVerifyCaller(struct peer *peer, struct BgpsecPathAttr *bpa, struct prefix p)
{
#ifdef USE_SRX_CRYPTO_API

  int retVal;

  /* call the library function --> bgpsecVerify */
  if (g_capi->libHandle == NULL)
  {
    retVal = BGPSEC_VERIFY_ERROR;
  }
  else if( (retVal =  g_capi->validate((BgpsecPathAttr*)bpa, 0, NULL, &p, peer->local_as)) != BGPSEC_VERIFY_SUCCESS)
  {
    retVal = BGPSEC_VERIFY_ERROR;

    /* clearing due to error */
    //zlog_debug("[BGPSEC] clean up BGPSEC path attribute");
    //bgpsec_path_free (bpa);
    // --> change above, because even though validation failed, bpa should be remained in aspath interned structure
  }

  return retVal;
#else
  return 0;
#endif
}


void test_print(struct BgpsecPdu pdu, size_t *bptr, char *sigbuff, char* hashbuff, size_t psize)
{
    unsigned int i=0;
    printf(" \n %s: \n ", __FUNCTION__);
    printf("Secure_Path length: %d", pdu.len_SecurePath);
    printf(" - ASnum: %d \n", pdu.asNum);
    printf(" - pcount: %d \n", pdu.pCount);
    printf(" - flags: %d \n\n", pdu.flags);
    printf("Signature_Block length: %d(0x%02x) \n", pdu.len_SigBlock, pdu.len_SigBlock);
    printf(" - Algorithm Suite ID: %d \n", pdu.algoSuiteId);
    printf(" - SKI: %p [bptr:%p]\n", pdu.ski, bptr);
    for(;i<BGPSEC_SKI_LENGTH; i++)
      printf("%02X ", *pdu.ski++);
    printf("\n");
    printf(" - sig length: %d \n", pdu.len_Sig);
    printf(" - signature: \n");

    for(i=0; i<pdu.len_Sig; i++ )
    {
      if(i%16 ==0) printf("\n");
      printf("%02x ", (unsigned char)sigbuff[i]);
    }
    printf("\n");
    for( i=0; i<psize; i++)
      printf("%02x ", hashbuff[12+i]);
    printf(" -- hash prefix\n");

    printf("-- all verify hashbuff\n");
    for(i=0; i<12+psize; i++)
      printf("%02x ", hashbuff[i]);
    printf("\n");
}



void print_signature(struct BgpsecPathAttr *bpa)
{
  //struct BgpsecPathAttr *new_bpa;
  struct PathSegment *seg = bpa->pathSegments;
  struct SigBlock *sb = bpa->sigBlocks;
  struct SigSegment *ss = sb->sigSegments;

  if(seg && sb && ss);

  int i;
  int sig_length = ss->sigLen;
  /* signature print out */
    for(i=0; i<sig_length; i++ )
    {
      if(i%16 ==0) printf("\n");
      printf("%02x ", (unsigned char)ss->signature[i]);
    }
    printf(" - from[%s]\n", __FUNCTION__);

}

int bgpsecSanityCheck(struct BgpsecPathAttr *bpa)
{
  struct PathSegment *seg;
  struct SigBlock *sb;
  struct SigSegment *ss;

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

/* This function duplicate the original attribute into a new instance
 * - all pointer address of src will not be copied into a new, with just
 *   copy by value.
 */
struct BgpsecPathAttr * bgpsecDup(struct BgpsecPathAttr *orig)
{
  if(bgpsecSanityCheck(orig) != 0)
    return NULL;

  /* pointer links */
  struct BgpsecPathAttr *new = bgpsec_path_attr_all_new();

  new->securePathLen = orig->securePathLen;

  /* concatenation of Path_Segment */
  concatPathSegment(new->pathSegments, orig->pathSegments);

  /* concatenation of Sigature_Blocks and Signature_Segment inside this function */
  concatSigBlock(new->sigBlocks, orig->sigBlocks);

  return new;

}

void concatSigSegment(struct SigSegment* const new, struct SigSegment * const orig)
{
  struct SigSegment *src = orig;
  struct SigSegment *pnt = new;

  while(pnt)
  {
    /* ski allocation and copy from original */
    pnt->ski = calloc (1, BGPSEC_SKI_LENGTH);
    assert(src->ski);
    memcpy(pnt->ski, src->ski, BGPSEC_SKI_LENGTH);

    pnt->sigLen = src->sigLen;

    /* signature allocation and copy from original */
    pnt->signature = calloc (1, src->sigLen);
    assert(src->signature);
    memcpy(pnt->signature, src->signature, src->sigLen);

    if(src->next)
    {
      src       = src->next;
      pnt->next = sigSegment_New();
    }

    pnt = pnt->next;
  }

}

void concatSigBlock(struct SigBlock* const new, struct SigBlock * const orig)
{

  struct SigBlock *src = orig;
  struct SigBlock *pnt = new;

  while(pnt)
  {
    pnt->sigBlockLen = src->sigBlockLen;
    pnt->algoSuiteId = src->algoSuiteId;

    concatSigSegment(pnt->sigSegments, src->sigSegments);

    if(src->next)
    {
      src       = src->next;
      pnt->next = sigBlock_New();
    }

    pnt = pnt->next;
  }

}

void concatPathSegment(struct PathSegment * const new_seg,
                       struct PathSegment * const orig)
{

  /* concatenation of path segemnts */
  struct PathSegment *src = orig;
  struct PathSegment *pntSeg = new_seg;

  while(pntSeg)
  {
    pntSeg->as       = src->as;
    pntSeg->pCount   = src->pCount;
    pntSeg->flags    = src->flags;

    if(src->next)
    {
      src = src->next;
      pntSeg->next = pathSegment_New();
    }

    pntSeg = pntSeg->next;
  }

}


/**
 * @brief convert into binary value, faster than stdio functions
 *
 * @param in one byte of hex ascii
 *
 * @return one byte of binary data
 */
#define CHAR_CONV_CONST     0x37
#define DIGIT_CONV_CONST    0x30
#define LEN_BYTE_NIBBLE     0x02

unsigned char hex2bin_byte(char* in)
{
  unsigned char result=0;
  int i=0;
  for(i=0; i < LEN_BYTE_NIBBLE; i++)
  {
    if(in[i] > 0x40)
      result |= ((in[i] - CHAR_CONV_CONST) & 0x0f) << (4-(i*4));
    else if(in[i] > 0x30 && in[i] < 0x40)
      result |= (in[i] - DIGIT_CONV_CONST) << (4-(i*4));
  }
  return result;
}






#endif /* USE_SRX */
