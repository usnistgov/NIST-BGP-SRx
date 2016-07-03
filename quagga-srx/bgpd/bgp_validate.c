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

#include <srx/srxcryptoapi.h>
SRxCryptoAPI *g_capi;
#define RET_ID_OFFSET 1

/* Hash for bgpsec path.  This is the top level structure of BGPSEC AS path. */
static struct hash *bgpsechash;
// Forward declarations
static u_int8_t* ski_new();
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

/* 
 * Initialize the bgpsec path hash - similar to the as path hash and initializes
 * the srx-crypto-api
 * 
 */
void bgpsec_path_attr_init()
{
 // @TODO: If no crypto is performed on the router side (e.g. srx-server does
 //        crypto - then the API might not need to be initialized.)
 //        One exception though, if we keep signing here even with the use of 
 //        srx-server.
  // aspath_init initialize its aspath hash as many as the number of 32767 hashes, so follows the same number
  bgpsechash = hash_create_size (32767, bgpsec_path_attr_key_make, bgpsec_path_attr_cmp);
  g_capi = malloc(sizeof(SRxCryptoAPI));
  memset (g_capi, 0, sizeof(SRxCryptoAPI));
  sca_status_t sca_status = API_STATUS_OK;

  if(srxCryptoInit(g_capi, &sca_status) == API_FAILURE);
  {
    zlog_err("[BGPSEC] SRxCryptoAPI not initialized (0x%X)!\n", sca_status);
  }
}

/**
 * Returns the pointer to the internal crypto api.
 *  
 * @return Returns the pointer to the internal crypto api
 */
SRxCryptoAPI* getSrxCAPI()
{
  return g_capi;
}

/**
 * Clean the hash
 */
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

/**
 * Instantiate an initialize a new BgpsecPathAttr instance.
 * 
 * @return the new instantiated BgpsecPathAttr.
 * 
 * @see bgpsec_path_free
 */
static struct BgpsecPathAttr * bgpsec_path_attr_new (void)
{
  struct BgpsecPathAttr *new;
  new = XCALLOC (MTYPE_BGPSEC_PATH, sizeof (struct BgpsecPathAttr));
  memset(new, 0x0, sizeof(struct BgpsecPathAttr));
  return new;
}

/**
 * Create a complete BgpsecPathAttr structure including all internal 
 * allocations to the pointers. 
 *  
 * @return A fully instantiated BgpsecPathAttr.
 * 
 * @see bgpsec_path_free
 */
static struct BgpsecPathAttr * bgpsec_path_attr_all_new(void)
{
  struct BgpsecPathAttr *bpa;

  bpa = bgpsec_path_attr_new();
  bpa->pathSegments           = pathSegment_New();
  bpa->sigBlocks              = sigBlock_New();
  bpa->sigBlocks->sigSegments = sigSegment_New();

  return bpa;
}

/**
 * Free the path segment of the segment structure.
 * 
 * @param seg The secure path segment to be freed
 * 
 * @see pathSegment_New
 */
static void bgpsec_path_segment_free (struct PathSegment *seg)
{
  if (seg != NULL)
  {
    memset(seg, 0, sizeof(struct PathSegment));
    XFREE (MTYPE_BGPSEC_PATH_SEG, seg);
  }

  return;
}

/** 
 * Free entire chain of segments.
 * 
 * @param seg The chain of signature segments.
 */
static void bgpsec_path_segment_free_all (struct PathSegment *seg)
{
  struct PathSegment *prev;

  while (seg != NULL)
  {
    prev = seg;
    seg = seg->next;
    bgpsec_path_segment_free (prev);
  }
}

/**
 * Frees the allocated memory for the given signature segment.
 * 
 * @param ss The signature segment to be freed.
 * 
 * @see sigSegment_New
 * 
 */
static void sigSegment_free(struct SigSegment *ss)
{
  if (ss != NULL)
  {
   // Free the ski 
   if (ss->ski != NULL)
   {
     memset( ss->ski, 0, SKI_LENGTH);
     free(ss->ski);
   }
   
   // Free the signature
   if (ss->signature != NULL)
   {
     memset(ss->signature, 0, ss->sigLen);
     free(ss->signature);
   }
   
   memset (ss, 0, sizeof(struct SigSegment));
   /* but here, call xfree for Signature Segment itself */
   XFREE (MTYPE_BGPSEC_SIG_SEG, ss);
  }
}

/**
 * Free the complete signature segment chain
 * 
 * @param ss The signature segment chain.
 */
static void sigSegment_free_all(struct SigSegment *ss)
{
  struct SigSegment *prev;

  while (ss != NULL)
  {
    prev = ss;
    ss = ss->next;
    sigSegment_free(prev);
  }
}

/**
 * Free the signature block of the list structure
 * 
 * @param sb The signature block to be freed.
 * 
 * @see sigBlock_New
 */
static void bgpsec_sigBlock_free (struct SigBlock *sb)
{
  if (sb != NULL)
  {
    // First free all signature segments
    sigSegment_free_all(sb->sigSegments);
    memset (sb, 0, sizeof(struct SigBlock));
    XFREE (MTYPE_BGPSEC_SIG_BLK, sb);
  }
}

/**
 * free entire chain of Signature_Block segments 
 * 
 * @param sb Free all signature blocks.
 */
static void bgpsec_sigBlock_free_all (struct SigBlock *sb)
{
  struct SigBlock *prev;

  while (sb != NULL)
  {
    prev = sb;
    sb = sb->next;
    bgpsec_sigBlock_free (prev);
  }
}

/** 
 * Free BGPSEC path attr structure. 
 * 
 * @param bgp The complete 
 * 
 * @see bgpsec_path_attr_all_new
 */
void bgpsec_path_free (struct BgpsecPathAttr *bpa)
{
  if (bpa != NULL)
  {
    bgpsec_path_segment_free_all (bpa->pathSegments);
    bgpsec_sigBlock_free_all (bpa->sigBlocks);

    memset(bpa, 0, sizeof(struct BgpsecPathAttr));
    XFREE (MTYPE_BGPSEC_PATH, bpa);
  }
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
 * Allocates memory for the new secure path segment
 *
 * @return Return a newly allocates secure path segment
 * 
 * @see bgpsec_path_segment_free
 */
static struct PathSegment* pathSegment_New(void)
{
  struct PathSegment *new;
  new = XCALLOC (MTYPE_BGPSEC_PATH_SEG, sizeof (struct PathSegment));
  memset(new, 0x00, sizeof(struct PathSegment));

  return new;
}

/**
 * Generates and returns a zero initialized ski of length SKI_LENGTH
 * 
 * @return Generates and returns a zero initialized ski of length SKI_LENGTH
 */
static u_int8_t* ski_new()
{
  u_int8_t* ski = malloc (SKI_LENGTH);
  memset(ski, 0, SKI_LENGTH);
  return ski;
}

/* signature allocation */
static void *signature_new(size_t size)
{
  u_int8_t* signature;
  signature = XMALLOC(MTYPE_BGPSEC_SIGNATURE, size);
  memset(signature, 0, size);
  return signature;
//  return calloc (1, size);
}

/**
 * Create a new signature segment for the pointer structure.
 * 
 * @return The signature segment.
 * 
 * @see sigSegment_free
 */
static struct SigSegment* sigSegment_New(void)
{

  struct SigSegment *new;
  new = XCALLOC (MTYPE_BGPSEC_SIG_SEG, sizeof (struct SigSegment));
  memset(new, 0x00, sizeof(struct SigSegment));

  return new;
}

/**
 * Generate a new Signature Block for the pinter structure.
 * 
 * @return The new created signature block
 * 
 * @see bgpsec_sigBlock_free
 */
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
                                    struct stream *s, size_t length)
{
  // @INFO:  The pointer structure makes sense for generation of the sending out
  //         attribute.
  u_char* startp = NULL;
  u_char* endp   = NULL;
//  struct stream *s = peer->ibuf; 
  size_t start_getp = 0;
  size_t start_endp = 0;
  // This is the secure path pointer
  size_t spp = 0;
  // This is the secure block pointer
  size_t sbp = 0;
  
  /* sanity check */
  // @TODO: Add the correct sanity check as specified in the DRAFT, This means
  //        Check the existence of max 2 signature blocks etc.
  if ((STREAM_READABLE(s) < length) || (length <= 0))
  {
    zlog_err("bad bgpsec packet - length mismatch");
    return NULL;
  }

  startp     = BGP_INPUT_PNT (peer); // current address pointer
  start_getp = stream_get_getp (s);
  start_endp = stream_get_endp (s);
  endp       = startp + length;

  if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
  {
    zlog_debug("[IN] %p -  startp: %p-- getp:%d endp:%d -- endp(startp+length):%p length:%d ", \
        stream_pnt(s), startp, (int)start_getp, (int)start_endp, endp, (int)length);
  }

  // Retrieving the prefix is not needed anymore, this function just does 
  // Syntax check and generation of the helper structure.  
  int numSecurePathSegment = 0;

  if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
  {
    zlog_debug("[IN] peer as:%d peer->local_as:%d Secure_Path Len:%d",\
        peer->as, peer->local_as, stream_getw_from(s, start_getp));
  }

  /* calculation of total aspath length using SecurePath Len */
  u_int16_t spl    = stream_getw_from(s, start_getp);
  u_int16_t numSeg = 0;
  
  if ( (spl-OCTET_SECURE_PATH_LEN) % OCTET_SECURE_PATH_SEGMENT != 0)
  {
    zlog_err(" SecurePath Length parsing error");
    return NULL;
  }
  
  numSeg = (spl - OCTET_SECURE_PATH_LEN) / OCTET_SECURE_PATH_SEGMENT;

  struct BgpsecPathAttr* bpa = NULL;
  struct PathSegment *seg;
  struct SigBlock    *sb;
  
  bool syntaxError = false;

  /*
   * If this is the originating AS
   */
  // @INFO: OK this is wrong. if numSeg is < 2 this does not mean that this is 
  // the originator. numSeg is also < 2 if this is the second hop. I will modify
  // the code in such that it uses the iteration in both parts. 
  /*
   * in case not origin as, which means transit router
   */
  // It is a transit AS, it received this attribute.
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
    // Check we have enough bytes left
    if (STREAM_READABLE(s) < OCTET_SECURE_PATH_SEGMENT)
    {
      syntaxError = true;
      break;
    }
    seg = pathSegment_New();

    /* concatenating */
    if (prev)
    {
      prev->next = seg;
    }
    else
    {
      bpa->pathSegments = head = seg;
    }

    // Moved AS down, DRAFT 15
    seg->pCount = stream_getc(s);
    seg->flags  = stream_getc(s);
    seg->as     = stream_getl(s);

    if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
    {
      zlog_debug("[IN]  Secure_Path segment --> %d AS:%d", iter, seg->as);
    }

    prev = seg;

    iter--;
  } /* end of while */

  // @INFO: I don't really know the meaning of the comment below but for now,
  // I let it stand and do check during debug what is going on. Also very 
  // important here is to make sure that we have a maximum of 2 signature blocks
  // if we have more, we encountered a syntax error and have to clean up all our
  // data.
  /*
   * TODO: the code for parsing the 2nd Signature Block(sb2)
   * But, here, just assumed one Sigature Block received.
  */
  struct SigSegment *ss_prev = NULL, *ss_curr = NULL;
  
  // @INFO Now add my change of parsing through the signature block. Also add 
  // the RFC required syntax check.
  if (STREAM_READABLE(s) < 1)
  {
    syntaxError = true;
  }
  
  int numSigBlocks = 0;
  while (STREAM_READABLE(s) > 0)
  {
    numSigBlocks++;
    if (numSigBlocks > BGPSEC_MAX_SIGBLOCK)
    {
      syntaxError = true;
      break;
    }
    // Now generate the BgpsecPathAttribtue Signature block structure. 
    if (bpa->sigBlocks == NULL)
    {
      // This is the first signature block
      sb = bpa->sigBlocks = sigBlock_New(); // new Signature_Block instance
    }
    else
    {      
      sb->next = sigBlock_New();
      sb = sb->next;      
    }
    
    sb->sigBlockLen = stream_getw(s);   // Signature_Block Length incl. this field.
    if ((sb->sigBlockLen-2) > STREAM_READABLE(s))
    {
      // Length field contains invalid value.
      syntaxError = true;
      break;
    }
    sb->algoSuiteId     = stream_getc(s);   // Algorithm Suite Identifier
    // The remaining bytes for the signature segments
    u_int16_t remainingBytes = sb->sigBlockLen - 3; 

    if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
    {
      zlog_debug("[IN] Secure_Block --> %d, AlgoID: %u, Length: %u", 
                 numSigBlocks, sb->algoSuiteId, sb->sigBlockLen);
    }

    int numSignatures = 0;
  // @INFO: Actually according to the RFC we need to parse according to the 
  // block length, not blindly through the number of segments. This is false.
  // Only this way we can detect a structural error with the update.
    while (remainingBytes > 0)
    {
      numSignatures++;
      if (sb->sigSegments == NULL)
      {
        sb->sigSegments = sigSegment_New();
        ss_prev = NULL;
        ss_curr = sb->sigSegments;
      }
      else
      {
        ss_prev->next = sigSegment_New();
        ss_curr = ss_prev->next;
      }
      ss_prev = ss_curr;
      
      ss_curr->ski = ski_new();
      stream_get(ss_curr->ski, s, SKI_LENGTH); // SKI
      remainingBytes -= SKI_LENGTH;
      ss_curr->sigLen = stream_getw(s);        // Signature Length
      remainingBytes -= 2;
      
      if (STREAM_READABLE(s) < ss_curr->sigLen)
      {
        // Invalid signature length 
        zlog_err("Bad bgpsec signatUre length: bigger than remaining byte");
        syntaxError = true;
        break;
      }
      
      ss_curr->signature = signature_new(ss_curr->sigLen);
      stream_get(ss_curr->signature, s, ss_curr->sigLen);     // signature   
      remainingBytes -= ss_curr->sigLen;
      
      if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
      {
        zlog_debug("[IN]    signature --> %d, Length: %u", 
                   numSignatures, ss_curr->sigLen);
      }   
    }
    if (numSignatures != numSecurePathSegment)
    {
      zlog_err("Number signatures does not match number secure path segments");
      syntaxError = true;
      break;
    }
  }
  
  if (syntaxError)
  {
    // cleanup
    bgpsec_path_free(bpa);
    bpa = NULL;
  }
  
  if (BGP_DEBUG (bgpsec, BGPSEC_IN) || BGP_DEBUG(bgpsec, BGPSEC_DETAIL))
  {
    zlog_debug("[IN]  %s: return value(final bpa): %p", __FUNCTION__, bpa);
  }
  
  return bpa;
}

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
                                  u_int8_t pCount, u_int8_t flags)
{
  // @TODO: The current implementation only deals with one hash message,
  //        modify this by using both - Then remove the two defines below
#define BLOCK_0 0
#define BLOCK_1 1
  
  if (bgp->srxCAPI == NULL)
  {
    return NULL;
  }
  
  // If this is the originator, nothing might exist yet, no bgpsec_path_attr,
  // no valdata etc. If nothing exist we have to build it, it it exists
  // we can use it. 

  as_t targetAS = htonl(peer->as);
  as_t localAS  = htonl(bgp->as);

  // @TODO: here we would need some more info about a pCount > 0  
  SCA_BGPSEC_SecurePathSegment spSeg;
  spSeg.pCount = pCount;
  spSeg.flags  = flags;
  spSeg.asn    = htonl(bgp->as);
  
  // Removed ski str to bin conversion. this is now done during configuration.
    
  if (attr->bgpsec_validationData == NULL)
  {
    // This will be the case if the update never was send out before - it mainly
    // is an origination..
    attr->bgpsec_validationData = malloc(sizeof(SCA_BGPSecValidationData));
    memset(attr->bgpsec_validationData, 0, sizeof(SCA_BGPSecValidationData));
  }
  // @TODO: I think [0] cannot be NULL and [1] be filled. At least this would
  //        not make sense. At this point we anyhow only work with [0] until one
  //        of the near future updates.
  
  // The idea here is that if we have no hash message, the API needs to generate
  // it. Now lets make sure the API has all information needed to do so.
  if (attr->bgpsec_validationData->hashMessage[0] == NULL)
  {
    // So the validation data is not available - check if we have a bgpsec path
    // attribute where we can generate the hash message from.
    if (attr->bgpsec_validationData->bgpsec_path_attr == NULL)
    {
      // Ok it seems we don't have any data prepared. This is the case if we
      // originate an update. Store the data needed.
      if (attr->bgpsec_validationData->nlri == NULL)
      {
        // @TODO Maybe use XMALLOC with a Quagga MEMORY type
        attr->bgpsec_validationData->nlri = malloc(sizeof(SCA_Prefix));
        memset(attr->bgpsec_validationData->nlri, 0, sizeof(SCA_Prefix));
        attr->bgpsec_validationData->nlri->afi    = htons(family2afi(pfx->family));
        attr->bgpsec_validationData->nlri->safi   = SAFI_UNICAST;

        attr->bgpsec_validationData->nlri->length = (u_int8_t)pfx->prefixlen;
        int bLen = (pfx->prefixlen + 7) / 8;
        memcpy(attr->bgpsec_validationData->nlri->addr.ip, pfx->u.val, bLen);
      }
      
    }
  }
  
  SCA_BGPSecSignData  scaSignData;
  memset (&scaSignData, 0, sizeof(SCA_BGPSecSignData));

  // Use the algorithm ID associated with the specified private key.
  scaSignData.algorithmID = bgp->srx_bgpsec_key[bgp->srx_bgpsec_active_key].algoID;
  scaSignData.myHost      = &spSeg;
  scaSignData.peerAS      = targetAS;
  scaSignData.nlri        = attr->bgpsec_validationData->nlri;
  scaSignData.ski         = bgp->srx_bgpsec_key[bgp->srx_bgpsec_active_key].ski;
  scaSignData.status      = API_STATUS_OK;
  // Get the hash Message, if it was received and already validated, the 
  // hashMessage will not be NULL. If it is null, the signature algorithm
  // assumes it is an origination.
  scaSignData.hashMessage = attr->bgpsec_validationData->hashMessage[BLOCK_0];
  scaSignData.signature   = NULL;
  
  // Now do the signing. If it fails, cleanup what needs to be clean up
  // and return 0
  if (bgp->srxCAPI->sign(&scaSignData) == API_FAILURE)
  {
    zlog_err("[BGPSEC] Signing the bgpsec path to peer %u failed status (0x%X)\n",
            peer->as, scaSignData.status);
    if (attr->bgpsec_validationData->hashMessage[BLOCK_0] == NULL)
    {
      // We only need to clean up if the validation data was generated during 
      // this call
      if (!bgp->srxCAPI->freeHashMessage(scaSignData.hashMessage))
      {
        // Now try to clean up - Normally we should not get here in the first
        // place.
        freeSCA_HashMessage(scaSignData.hashMessage);
      }
      scaSignData.hashMessage = NULL;
    }
    return 0;
  }
  
  if (attr->bgpsec_validationData->hashMessage[BLOCK_0] != scaSignData.hashMessage)
  {
    if (attr->bgpsec_validationData->hashMessage[BLOCK_0] != NULL)
    {
      if (!bgp->srxCAPI->freeHashMessage(attr->bgpsec_validationData->hashMessage[BLOCK_0]));
      {
        freeSCA_HashMessage(attr->bgpsec_validationData->hashMessage[BLOCK_0]);
      }
      attr->bgpsec_validationData->hashMessage[BLOCK_0] = NULL;
    }
    
    // Now set the new hash message.
    attr->bgpsec_validationData->hashMessage[BLOCK_0] = scaSignData.hashMessage;
  }
  
  return scaSignData.signature;
}

/**
 * Construct the BGPSEC Path attribute. This includes signing the as path if it 
 * is not signed already.
 * This function writes the data into the stream.
 * 
 * @param bgp    The bgp session
 * @param peer   The peer information
 * @param aspath Pointer to the bgp4 as path representing the bgpsec path.
 * @param p      The prefix
 * @param s      The stream
 * @param attr   The bgp attribute. 
 *
 * @return The length of the attribtue
 */
int constructBGPSecPathAttribute(struct bgp *bgp, struct peer *peer, 
                                 struct aspath *aspath, struct prefix* p,
                                 struct stream *s, struct attr *attr,
                                 u_int8_t flags, u_int8_t pCount,
                                 SCA_Signature** signatures, int numSignatures)
{ 
  size_t attrLenPtr = stream_get_endp(s);
  // We already established that we do bgpsec and if internal, We already 
  // forwarded the traffic.
  //  
  struct BgpsecPathAttr* bpa = bgpsecDup(attr->bgpsecPathAttr, true);
  // Create the secure path
  uint16_t secPathLen = LEN_SECPATHSEGMENT 
                        + ((bpa->securePathLen == 0) ? 2 : bpa->securePathLen);
  stream_putw (s, secPathLen);
  
  // Now add my own signature path segment
  int numPathSegments = 1;
  stream_putc (s, pCount);
  stream_putc (s, flags);
  stream_putl (s, bgp->as); // Check if these values have to be put in network format.
  struct PathSegment* pSeg = bpa->pathSegments;
  while (pSeg != NULL)
  {
    numPathSegments++;
    stream_putc (s, pSeg->pCount);
    stream_putc (s, pSeg->flags);
    stream_putl (s, pSeg->as);
    pSeg = pSeg->next;
  }

  int sigIdx = 0;
  struct SigBlock* sigBlock = NULL;  
  // The prevBlock is used to allow removing the signature block.
  // if we remove a signature block we might need to allow taking it out of the 
  // list. OK currently the list MUST NOT exceed two segments but this might 
  // change in the future - So I just prepare that.
  struct SigBlock* prevBlock = NULL;
  // Now add the signature block(s) - one for each signature generated.
  SCA_Signature* signature = NULL;
  for (sigIdx = 0; sigIdx < numSignatures; sigIdx++)
  {
    sigBlock  = bpa->sigBlocks;
    prevBlock = sigBlock;
    signature = signatures[sigIdx];
    
    // Now locate the correct signature block that matches the signature.
    // What about if we have more signature block with the same signature ID?????
    // Maybe we have to remove the block once we found it?
    while ((sigBlock != NULL) && (sigBlock->algoSuiteId != signature->algoID))
    {
      sigBlock  = sigBlock->next;
      prevBlock = sigBlock;
    }
    if (sigBlock == NULL)
    {
      if (numPathSegments != 1)
      {
        zlog_err("[BGPSEC] no path segments, something went completely wrong!\n");
        return 0;
      }
      // OK we are originating. 
      
      // Now generate a signature block for the signature we just generated
      sigBlock  = sigBlock_New();
      prevBlock = NULL;
      sigBlock->algoSuiteId = signature->algoID;
    }    
    
    // store the stream position to later determine the length of the block
    size_t sbPointer = stream_get_endp (s);
    stream_putw (s, 0); // Store a dummy as signature block length and come back
                        // and store the correct value.
    stream_putc (s, sigBlock->algoSuiteId);
    
    // Now store latest generated signature
    stream_put  (s, signature->ski, SKI_LENGTH);
    stream_putw (s, signature->sigLen);
    stream_put  (s, signature->sigBuff, signature->sigLen);
    
    // Now add the remaining signatures to the block
    struct SigSegment* sigSeg = sigBlock->sigSegments;
    while (sigSeg != NULL)
    {
      stream_put  (s, sigSeg->ski, SKI_LENGTH);
      stream_putw (s, sigSeg->sigLen);
      stream_put  (s, sigSeg->signature, sigSeg->sigLen);
      sigSeg = sigSeg->next;
    }
    
    // Now calculate the signatrue block length
    size_t sbEndPointer = stream_get_endp(s);
    uint16_t sbLength = (uint16_t)(sbEndPointer - sbPointer);
    //stream_putw_at (s, sizep_PathLen, tmpBpa->securePathLen); // Secure_Path Len
    stream_putw_at (s, sbPointer, sbLength); // Secure_Path Len
    
    if (bpa->sigBlocks == sigBlock)
    { // This block was the first one, move the head
      bpa->sigBlocks = sigBlock->next;
    } 
    else if (prevBlock != NULL)            
    { // The block was not the first one. In case the list exceeds two blocks we
      // might be somewhere in the middle. Now point the previous block to the
      // next one
      prevBlock->next = sigBlock->next;
    }
    // Now we can remove the signature block
    bgpsec_sigBlock_free(sigBlock);
    sigBlock = NULL;
  }
  // Now set the length of the attribute
  size_t endPtr = stream_get_endp(s);
  uint16_t attrLen = (uint16_t)(endPtr - attrLenPtr);
  bgpsec_path_free(bpa);
  bpa = NULL;
  
  return attrLen;
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


/**
 * Print the given information using std-io
 *
 * @param bpa The BgpsecPathAttr.
 */
void print_signature(struct BgpsecPathAttr *bpa)
{
  //struct BgpsecPathAttr *new_bpa;
  struct PathSegment *seg = bpa->pathSegments;
  struct SigBlock *sb = bpa->sigBlocks;
  struct SigSegment *ss = sb->sigSegments;

  if(seg && sb && ss);

  int i;
  int sig_length = ss->sigLen;

  if(zlog_default->maxlvl[ZLOG_DEST_STDOUT] > 0)
  {
  /* signature print out */
    for(i=0; i<sig_length; i++ )
    {
      if(i%16 ==0) printf("\n");
      printf("%02x ", (unsigned char)ss->signature[i]);
    }
    printf(" - from[%s]\n", __FUNCTION__);
  }
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
struct BgpsecPathAttr * bgpsecDup(struct BgpsecPathAttr *orig, bool newIfNULL)
{
  struct BgpsecPathAttr* new = NULL;
  
  if(bgpsecSanityCheck(orig) == 0)
  {  
    /* pointer links */
    new = bgpsec_path_attr_all_new();

    new->securePathLen = orig->securePathLen;

    /* concatenation of Path_Segment */
    concatPathSegment(new->pathSegments, orig->pathSegments);

    /* concatenation of Sigature_Blocks and Signature_Segment inside this function */
    concatSigBlock(new->sigBlocks, orig->sigBlocks);
  }
  else if ((new == NULL) && newIfNULL)
  {
    new = bgpsec_path_attr_new();
  }
  
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

/**
 * This function is a wrapper for the corresponding CAPI function. This function
 * is needed to allow the memory management performed by the CAPI itself.
 * 
 * @param message The hashInput to be freed.
 * 
 * @since 0.4.2.0
 */
void freeSCA_HashMessage(SCA_HashMessage* message)
{
  if (g_capi != NULL)
  {
    if (g_capi->freeHashMessage(message))
    {
      message = NULL;
    }
  }
  if (message != NULL)
  {
    sca_freeHashInput(message);
  }
}




#endif /* USE_SRX */
