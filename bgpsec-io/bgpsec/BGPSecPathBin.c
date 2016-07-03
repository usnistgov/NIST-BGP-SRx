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
 * This software allows to generate the BGPSEC Path attribute as binary stream.
 * The path will be fully signed as long as all keys are available.
 *
* @version 0.2.0.0
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.0.0 - 2016/06/02 - oborchert
 *            * Merged modifications from 0.1.1.1 branch for measurement 
 *              framework
 *          - 2016/05/13 - oborchert
 *            * Fixed segmentation fault for as path with 4 or more unique ASns 
 *              BZ968
 *          - 2016/05/10 - oborchert
 *            * Fixed compiler warnings BZ950
 *  0.1.1.0 - 2016/05/03 - oborchert
 *            * Fixed position of public fake key in signDraft13
 *          - 2016/04/21 - oborchert
 *            * Added indicator if fake signature was used
 *          - 2016/04/15 - oborchert
 *            * Fixed invalid prefix handling in _signDraft13
 *          - 2016/03/26 - oborchert
 *            * Added list parameters to retrieve the keys used for signing.
 *          - 3016/03/24 - oborchert
 *            * Removed data type confusion for function generateBGPSecAttr
 *          - 2016/03/21 - oborchert
 *            * Fixed invalid value conversion in hash generation. Use network
 *              representation instead of host representation.
 *            * To remove confusion between the different BGPSEC path types the
 *              method printBGPSECPathAttribute now requires a
 *              BGPSecPathAttribute pointer rather than a u_int8_t pointer.
 *          - 2016/03/11 - oborchert
 *            * Fixed error with attribute length in signature processing.
 *              Rewrote some of the code.
 *  0.1.0.0 - 2015/07/31 - oborchert
 *            * Created File.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <netinet/in.h>
#include <srx/srxcryptoapi.h>
#include "ASList.h"
#include "ASNTokenizer.h"
#include "Crypto.h"
#include "antd-util/linked_list.h"
#include "bgpsec/BGPSecPathBin.h"
#include "bgp/printer/BGPHeaderPrinter.h"
#include "bgp/printer/BGPPrinterUtil.h"
#include "updateStackUtil.h"


#define CT_BLOCKS   1

#define AS_DELIM " ,"

/** Contains the internally used data stream. */
static u_int8_t* INT_DATA = NULL;
/** Contains the size of the internally used data stream. */
static u_int16_t INT_DATA_SIZE = 0;

/** Temporary signature block (first 2 byte contain the used size) */
static u_int8_t* TMP_SIGBLOCK = NULL;
/** Contains the total size of the temporary signature block. */
static u_int16_t TMP_SIGBLOCK_SIZE = 0;

/** The initial size of the path attribute is 10K*/
#define INIT_SIZE  3000
#define EXTRA_BUFF 1000

static int _fillSignatureBlock(u_int8_t* data, AlgoParam* algo, int ctSegments, 
                               u_int32_t nextAS, BGPSEC_PrefixHdr* prefix,
                               tPSegList* spSeg, TASList* asList);

static int _fillSecurePath(u_int8_t* data, char* asPath, int ctSegments);

/**
 * initialize the data stream and create it if not done already.
 */
void initData()
{
  if (INT_DATA_SIZE == 0)
  {
    INT_DATA_SIZE = INIT_SIZE;
    INT_DATA = malloc(INT_DATA_SIZE);
    memset(INT_DATA, 0, INT_DATA_SIZE);
    TMP_SIGBLOCK_SIZE = INIT_SIZE;
    TMP_SIGBLOCK = malloc (TMP_SIGBLOCK_SIZE);
    memset(TMP_SIGBLOCK, 0, TMP_SIGBLOCK_SIZE);
  }
  else
  {
    BGPSEC_PathAttribute* attr = (BGPSEC_PathAttribute*)INT_DATA;
    if (attr->attrLength != 0)
    {
      // Only initialize the memory previously used.
      u_int16_t len = ntohs(attr->attrLength);
      memset(INT_DATA, 0, len);
      memset(TMP_SIGBLOCK, 0, TMP_SIGBLOCK_SIZE);
    }
  }
}

/**
 * Release the system allocated memory
 */
void releaseData()
{
  if (INT_DATA_SIZE > 0)
  {
    INT_DATA_SIZE = 0;
    free(INT_DATA);
    INT_DATA = NULL;
    TMP_SIGBLOCK_SIZE = 0;
    free(TMP_SIGBLOCK);
    TMP_SIGBLOCK = NULL;
  }
}

/**
 * Retrieve the SKI for the given ASN and store it in the given buffer. The SKI
 * must not be longer than 20 bytes.
 * 
 * @param buff The buffer, must be at least 20 bytes long.
 * @param asn the ASN the SKI is looked up for.
 */
void setSKI(u_int8_t* buff, u_int32_t asn)
{
  // Here load the SKI for the given ASN. The SKI is a 20 byte binary stream.
  char* ptr = (char*)buff;
  int i;
  
  for (i = 0; i < 5; i++)
  {
    ptr += sprintf(ptr, "%0X40", asn);
  }
}

/**
 * Resize the given memory to the new size and if bigger initialize the new
 * memory with 0.
 * 
 * @param ptr the memory to be resized.
 * @param origSize the Original Size of the memory.
 * @param newSize the new size of the memory.
 * 
 * @return The memory.
 */
static void* _my_realloc (void* ptr, size_t origSize, size_t newSize)
{
  void* hlpr = realloc (ptr, newSize);
  if (hlpr != NULL)
  {
    int diff = newSize - origSize;  
    ptr = hlpr;
    if (diff > 0)
    {
      hlpr = ptr + origSize;
      memset (hlpr, 0, diff);
    }
  }
  return ptr;
}

/**
 * Forward the secure path segment list to the last element.
 *  
 * @param list the secure path segment list.
 * 
 * @return the tail of the list 
 */
static tPSegList* _forwardPSegList (tPSegList* list)
{  
  if (list != NULL)
  {
    while (list->to != NULL)
    {
      list = list->to;
    }
  } 
  
  return list;  
}

/**
 * Rewind the secure path segment list to the origin.
 *  
 * @param list the secure path segment list.
 * 
 * @return the head of the list 
 */
static tPSegList* _rewindPSegList (tPSegList* list)
{  
  if (list != NULL)
  {
    while (list->from != NULL)
    {
      list = list->from;
    }
  } 
  
  return list;  
}

/**
 * Free the list including the generated signature.
 * 
 * @param list the path segments to be cleared.
 */
static void _freePSegList (tPSegList* list)
{
  tPSegList* next;
  
  if (list != NULL)
  {
    _rewindPSegList(list);
    
    while (list != NULL)
    {
      next = list->to;
      free(list->signature);
      list->signature = NULL;
      list->from      = NULL;
      list->asInfo    = NULL;
      list->to        = NULL;
      free(list);
      list = next;
    }
  }
}

/**
 * Create a helper list for the Path segments. This list is needed for the 
 * signing algorithm and allows to walk through the list back and forth.
 * What this list does is it takes the SecurePath which is ordered from 
 * current AS towards origin as and forts it as origin with (from=NULL) to 
 * last AS (to=NULL)
 *  
 * @param segment The binary stream with the Secure Path segments in it. 
 * @param ctSegments Number of segments in the stream.
 * 
 * @return 
 */
static tPSegList* _createPSegList(BGPSEC_SecurePathSegment* segment, 
                                  int ctSegments)
{
  // put a list over the path segments.
  tPSegList* segList = malloc(sizeof(tPSegList));
  memset(segList, 0, sizeof(tPSegList));
  tPSegList* segListElem = NULL;
  int idx;
  // Create a list containing the path segments. This allows to generate the 
  // hashes and sign them. The Path segments are sorted towards the origin but
  // the signatures have to be generated away from the origin.
  for (idx = 0; idx < ctSegments; idx++)
  {
    if (segListElem == NULL)
    {
      segListElem = segList;
    }
    else
    {
      segListElem->from = malloc(sizeof(tPSegList));
      memset(segListElem->from, 0, sizeof(tPSegList));
      segListElem->from->to = segListElem;
      segListElem = segListElem->from;
    }
    segListElem->spSeg = segment;
    segment++;
  }  
  if (segListElem != NULL)
  {
    segList = segListElem;
  }
  
  return segList;
}

/**
 * Generate the BGPSec Path attribute byte stream. All values inside the stream 
 * are written in network format, all parameters are given in host format.
 * In case the peer is iBGP the returned path will..
 *   a) not be signed sign to the given peer for transit paths
 *   b) not be generated for originations.
 * 
 * @param useGlobal use internal data stream (not thread safe but faster)
 * @param asPath (optional) a comma or blank separated string containing the AS 
 *               path (origin is the right most AS), Can be empty or NULL.
 * @param segmentCt OUT variable that returns the number of path / signature 
 *               segments this BGPSec path attribute contains.
 * @param bgp_conf The configuration of the bgp session.
 * @param prefix The prefix to be used. Depending on the AFI value it will be 
 *               typecast to either BGPSEC_V4Prefix or BGPSEC_V6Prefix
 * @param asList The AS list
 * 
 * @return Return the BGPSEC path attribute or NULL if the path generation 
 *         failed or the peer is iBGP and the path would be an origination.
 */
BGP_PathAttribute* generateBGPSecAttr(bool useGlobal, char* asPath, 
                                      u_int32_t* segmentCt, 
                                      BGP_SessionConf* bgp_conf,
                                      BGPSEC_PrefixHdr* prefix, TASList* asList)
{
  // Contains the attributes data
  u_int8_t* data = NULL;
  // Contains the temporary data for the signature block.
  u_int8_t* tmp_data = NULL;
  u_int8_t* ptr = NULL;
  int ctSegments = 0;
  
  char* longPath = convertAsnPath(asPath);;
  bool iBGP = bgp_conf->asn == bgp_conf->peerAS;     
  char* myPath = NULL;
  
  if (iBGP)
  {
    if (strlen(longPath) == 0)
    {
      // This is an origin announcement to an iBGP peer, Don't generate path 
      // segments
      free(longPath);
      longPath = NULL;
      return NULL;
    }
    else
    {
      // This is an origin transit, don't add the own as to the path, hand it 
      // over as it was received.
      myPath = strdup(longPath);
    }
  }
  else
  {
    // Add myself to the path if the peer is not iBGP (same as as myself)
    int digits   = (int)(log10(bgp_conf->asn)) + 1; // 1 for round up
    int strLen   = strlen(longPath) + digits + 2;   // blank and \0
    myPath = malloc(strLen);
    snprintf (myPath, strLen, "%u %s", bgp_conf->asn, longPath);
  }
  // Clean up helper structure.
  free(longPath);
  longPath = NULL;
  
  u_int32_t asn, prevASN = 0;  
  // Check the number of distinct consecutive ASes
  asntok(myPath);
  while (asntok_next(&asn))
  {
    if (asn != prevASN)
    {
      ctSegments++;
    }
    prevASN = asn;
  }
  asntok_reset();
  
  int sizeSegments    = sizeof(BGPSEC_SecurePathSegment) * ctSegments;
  // This is the attribute Size only including the signature segments but not
  // the signature blocks. They need to be added as they are processed.
  u_int16_t attrLength = sizeof(BGPSEC_SecurePath)  + sizeSegments;
  u_int16_t tmp_size = 0;

  // Prepare the attribute memory
  if (useGlobal) 
  {
    initData();
    data = INT_DATA;
    tmp_data = TMP_SIGBLOCK;
    tmp_size = INT_DATA_SIZE;
  }
  else
  {
    data = malloc(attrLength+EXTRA_BUFF);
    memset(data, 0, attrLength+EXTRA_BUFF);
    tmp_data = malloc(TMP_SIGBLOCK_SIZE+EXTRA_BUFF);
    memset(tmp_data, 0, TMP_SIGBLOCK_SIZE+EXTRA_BUFF);    
    tmp_size = attrLength+EXTRA_BUFF;           
  }
  // Check that the memory is large enough
  if (attrLength > tmp_size)
  {
    int newSize = attrLength + EXTRA_BUFF;
    data      = _my_realloc(data, tmp_size, newSize);
    tmp_data  = _my_realloc(tmp_data, tmp_size, newSize);
    tmp_size    = newSize;
    if (useGlobal)
    {
      INT_DATA      = data;
      INT_DATA_SIZE = newSize;
      TMP_SIGBLOCK      = tmp_data;
      TMP_SIGBLOCK_SIZE = newSize;
    }
  }
  
  ptr = data;
  
  BGPSEC_PathAttribute* attr = (BGPSEC_PathAttribute*)data;
  attr->pathattr.attr_flags      = BGP_UPD_A_FLAGS_BGPSEC;
  attr->pathattr.attr_type_code  = BGP_UPD_A_TYPE_BGPSEC;
  attr->attrLength = 0; // Will be set later on.
// taken out to make allow later on to test if set at all.
//  attr->attrLength = htons(attrLength);
  
  // Move pointer to start of SecurePath
  ptr += sizeof(BGPSEC_PathAttribute);
  
 // Fill the Secure Path
  BGPSEC_SecurePathSegment* pathSegments = (BGPSEC_SecurePathSegment*)
                                              (ptr + sizeof(BGPSEC_SecurePath)); 
  
  ptr += _fillSecurePath(ptr, myPath, ctSegments);
  tPSegList* segList = _createPSegList(pathSegments, ctSegments);
  
  // Now process the signature blocks, one by one (max 2))
  
  int block = 0;
  u_int16_t tmpBlockLength = 0;
  u_int16_t totalSigBlockLength = 0;
  AlgoParam* useAlgoParam = &bgp_conf->algoParam;
  
  while (useAlgoParam != NULL)
  {
    if (block != 0)
    {
      // Rewind the segment list to the origin (only for block > 0 - block 0 is 
      // rewinded already)
      segList = _rewindPSegList(segList);
    }
    
    tmpBlockLength = _fillSignatureBlock(tmp_data, useAlgoParam, ctSegments, 
                                         bgp_conf->peerAS, prefix, segList, 
                                         asList);
    if (tmpBlockLength != 0)
    {
      totalSigBlockLength += tmpBlockLength;
      
      attrLength += tmpBlockLength;

      // Make sure the memory buffer is large enough, otherwise adjust it.
      if (attrLength > tmp_size)
      {
        printf ("WARNING: needed to increase memory\n");
        size_t offset = ptr - data;
        int newSize = attrLength + EXTRA_BUFF;
        data     = _my_realloc(data, tmp_size, newSize);
        tmp_data = _my_realloc(data, tmp_size, newSize);
        tmp_size = newSize;
        ptr = data + offset; // reset the ptr - changes only ptr if data could not
                             // be extended and new memory had to be allocated. 
        if (useGlobal)
        {
          // Just in case the pointer values changes, reset them.
          INT_DATA          = data;
          INT_DATA_SIZE     = tmp_size;
          TMP_SIGBLOCK      = tmp_data;
          TMP_SIGBLOCK_SIZE = newSize;
        }
      }

      memcpy(ptr, tmp_data, tmpBlockLength);
      ptr += tmpBlockLength;
    }
    
    // Move to next algorithm.
    useAlgoParam = useAlgoParam->next;
    block++;
  }
    
  attr->attrLength = htons(attrLength);
  
  if (!useGlobal)
  { 
    free (tmp_data);
    tmp_data = NULL;
  }
  
  if (totalSigBlockLength == 0)
  {
    printf ("ERROR: No Signatures where generated for AS path: \"%d %s\"\n",
            bgp_conf->peerAS, myPath);
    
    if (!useGlobal)
    {
      // Free allocated data memory if managed here
      free (data);
      free (tmp_data);
    }
    else
    {
      memset (data, 0, attrLength);      
      memset (tmp_data, 0, tmp_size);      
    }
    data = NULL;
    attr = NULL;
  }
  
  _freePSegList(segList);
  asntok_clear();
  free(myPath);
  myPath = NULL;
  
  if (segmentCt != NULL)
  {
    *segmentCt = ctSegments;
  }
  return (BGP_PathAttribute*)attr;
}

/**
 * Get the Secure_Path Block. The given data buffer must be of efficient size.
 * 
 * @param data the data block where the 
 * @param asPath The AS path as string, items separated by blank.
 * @param ctSegments Count of segments in the path.
 * 
 * @return The length of the secure path in byte.
 */
static int _fillSecurePath(u_int8_t* data, char* asPath, int ctSegments)
{
  u_int32_t asn = 0;  
  BGPSEC_SecurePath* secPath = (BGPSEC_SecurePath*)data;
  u_int16_t sec_pLength = sizeof (BGPSEC_SecurePath) + 
                          (ctSegments * sizeof(BGPSEC_SecurePathSegment));
  secPath->length = htons(sec_pLength); // length of the secure path
  // Move Pointer to Path Segments
  data += sizeof(BGPSEC_SecurePath);
  
  // the template pointer used for the securePath segment
  BGPSEC_SecurePathSegment* spSeg;
  int segment;  
  asntok_next(&asn);
  bool go = true;
  for (segment = 0; go & (segment < ctSegments); segment++)
  {
    spSeg = (BGPSEC_SecurePathSegment*)data; 
    spSeg->asn    = asn; // First store it as host format, then convert later 
    spSeg->pCount = 0;
    spSeg->flags  = 0;
    while (go && (spSeg->asn == asn))
    {
      spSeg->pCount++;
      go = asntok_next(&asn);
    }
    spSeg->asn = htonl(spSeg->asn);  // Now convert to network format.
    
    // Now move pointer to next Path segment or beginning of Signature Block if 
    // no further path segment exists.
    data += sizeof(BGPSEC_SecurePathSegment);
  }
  
  return sec_pLength;
}

/**
 * Add the fake signature / key information to the list segment.
 * 
 * @param segListElem The list segment that has to be 'fake' signed!
 * @param algoParam The algorithm parameter with the fake information.
 * @param keyPos The position in the keyStorage where the fake key should be
 *               stored - only if algoParam->addPubKeys == true. 
 */
static void __addFakeData(tPSegList* segListElem, AlgoParam* algoParam, 
                          int keyPos)
{
  segListElem->sigLen    = algoParam->fake_sigLen;
  segListElem->signature = malloc(algoParam->fake_sigLen);
  memcpy(segListElem->signature, algoParam->fake_signature, 
                                 algoParam->fake_sigLen);
  if (algoParam->addPubKeys)
  {
    // Add required fake key - needed for CAPI calls
    algoParam->pubKey[keyPos] = &algoParam->fake_key;
    algoParam->pubKeysStored++;
  }
  // The Key for the SKI must somehow be added using the TASList.

  // indicate that a fake signature was used.
  algoParam->fakeUsed = true;  
}

/**
 * This function generates the HASH for each signature along the path stored
 * in segList and generates the signature. All of this is stored in the 
 * segList for later processing. The Hash is generated according to draft No. 15
 * The pointer to the keys used for signing will be stored in the algoParam
 * 
 * @param segList A simplified path list containing all info needed for the hash.
 * @param prefix The prefix
 * @param nextAS The next/peer ASN (host representation)
 * @param algo   The algorithm parameter.
 * @param asList The list containing all keys and SKI's
 * @param testSignature Allow to have the signature tested upon creation.
 * 
 * @return 1 for success and 0 for failure
 */
static int _signDraft15(tPSegList* segList, BGPSEC_PrefixHdr* prefix, 
                        u_int32_t nextAS, AlgoParam* algoParam, TASList* asList,
                        bool testSignature)
{
  int success = 1;
  
  // Size of the hash buffer
  int size = 0;
  // The hash buffer - will be reassigned in ich iteration
  u_int8_t* hashbuff = NULL;
  // Size of the previous hash buffer
  int prevSize = 0;
  // The previous hash needed for the iteration.
  u_int8_t* prevHash  = NULL;
  
  // A helper pointer
  u_int8_t* ptr = NULL;
  tPSegList* segListElem = segList;
  
  // The following variables are used in the while loop.
  int pLenInBytes   = 0;
  Tpl15Hash1* hash1 = NULL;
  u_int8_t*  pfxPtr = NULL;
  
  int noKeys = 0;
  // Count the segments to determine the number of keys
  if (algoParam->addPubKeys)
  {
    while (segListElem != NULL)
    {
      noKeys++;
      segListElem = segListElem->to;
    }    
    segListElem = segList;
  }
  
  while (success != 0 && segListElem != NULL)
  {
    if (segListElem->from == NULL)
    { 
      // Now we generate the initial signature over the prefix and origin 
      // including some origin related parameters.
      pLenInBytes = numBytes(prefix->length);
      size = sizeof(Tpl15Hash1)+pLenInBytes;
      hashbuff = malloc(size);
      ptr = hashbuff;
      hash1 = (Tpl15Hash1*)hashbuff;
      // For the hash use host format, not network format.
      hash1->targetAS = segListElem->to == NULL 
                        ? htonl(nextAS) : segListElem->to->spSeg->asn;
      hash1->pathSegment1.pCount = segListElem->spSeg->pCount;
      hash1->pathSegment1.flags  = segListElem->spSeg->flags;
      hash1->pathSegment1.asn    = segListElem->spSeg->asn;
      hash1->algoID   = algoParam->algoID;
      hash1->afi      = prefix->afi;
      hash1->safi     = prefix->safi; 
      hash1->pLen     = prefix->length;
      // Now fill the bytes of the prefix
      ptr += sizeof(Tpl15Hash1);
      // Now get the start position of the prefix within the header. We know the 
      // number of bytes to be copied into the hash. then just copy!
      pfxPtr = ((u_int8_t*)prefix)+sizeof(BGPSEC_PrefixHdr);      
      memcpy(ptr, pfxPtr, pLenInBytes);
      
      // Initialize for this run to indicate no fake is used yet
      algoParam->fakeUsed = false;
      
      // Sign the hash and store the signature and length in the segListElement.
      success = CRYPTO_createSignature(asList, segListElem, hashbuff, size, 
                                       algoParam->algoID, testSignature);
      if (success != 0)
      {
        if (algoParam->addPubKeys)
        {
          TASInfo* info = getListInfo(asList, segListElem->asInfo->key.asn, 
                                     segListElem->asInfo->key.algoID, false);
          algoParam->pubKey[--noKeys] = info != NULL ? &info->key : NULL;
          algoParam->pubKeysStored++;
        }        
      }
      else if (algoParam->ns_mode == NS_FAKE)
      {
        // Fake the signature and possibly the fake key.
        __addFakeData(segListElem, algoParam, --noKeys);
        // Now where we faked the result, lets call it success!
        success = 1;
      }
           
      prevSize = size;
      prevHash = hashbuff;
      size     = 0;
      hashbuff = NULL;
      ptr      = NULL;      
    }
    else
    {
      // Now generate the new buffer size:
      size = sizeof(Tpl15Hash3) + segListElem->from->sigLen
             + sizeof(Tpl15Hash2) + prevSize;
      hashbuff = malloc(size);
      ptr      = hashbuff;
      Tpl15Hash3* hash3 = (Tpl15Hash3*)ptr;
      hash3->targetAS = segListElem->to == NULL 
                        ? htonl(nextAS) : segListElem->to->spSeg->asn;
      // Now add the previous signature
      // Get the AS info if needed.
      if (segListElem->from->asInfo != NULL)
      {
        memcpy(hash3->signature_n_1.ski, segListElem->from->asInfo->key.ski, 
               SKI_LENGTH);
      }
      else
      {
        // No key information are available, in this case we might copy the 
        // SKI of the fake key.
        if (algoParam->fakeUsed)
        {
          memcpy(hash3->signature_n_1.ski, algoParam->fake_key.ski, SKI_LENGTH);        
        }
        else
        {
          printf("ERROR: no ski found for signature - 0x00!\n");
          memset(hash3->signature_n_1.ski, 0, SKI_LENGTH);
        }
      }
      hash3->signature_n_1.siglen = htons(segListElem->from->sigLen);            
      ptr += sizeof(Tpl15Hash3);
      
      // Now add the actual signature
      memcpy(ptr, segListElem->from->signature, segListElem->from->sigLen);
      ptr += segListElem->from->sigLen;

      // Now fill the current hosts information
      Tpl15Hash2* hash2 = (Tpl15Hash2*)ptr;
      hash2->pCount = segListElem->spSeg->pCount;
      hash2->flags  = segListElem->spSeg->flags;
      ptr += sizeof(Tpl15Hash2);
      
      // Now copy the previous cache information.
      memcpy(ptr, prevHash, prevSize);
      
      // Sign the hash and store the signature and length in the segListElement.
      success = CRYPTO_createSignature(asList, segListElem, hashbuff, size, 
                                       algoParam->algoID, testSignature);
      if (success != 0)
      {
        if (algoParam->addPubKeys)
        {
          TASInfo* info = getListInfo(asList, segListElem->asInfo->key.asn, 
                                     segListElem->asInfo->key.algoID, false);
          algoParam->pubKey[--noKeys] = info != NULL ? &info->key : NULL;
          algoParam->pubKeysStored++;
        }
      }
      else if (algoParam->ns_mode == NS_FAKE)
      {               
        // Fake the signature and possibly the fake key
        __addFakeData(segListElem, algoParam, --noKeys);
        // Now where we faked the result, lets call it success!
        success = 1;
      }
      
//      printf("-------------------------------------------------------\n");
//      printf("Sign as AS %u:\n", ntohl(hash3->targetAS));
//      PRNTHEX("BGPSecPathBin: Signature (intermediate)", segListElem->signature, 
//              segListElem->sigLen);
//      PRNTHEX("BGPSecPathBin: Hashbuff (intermediate)", hashbuff, size);
//      printf("-------------------------------------------------------\n");
      
      free (prevHash);      
      prevHash = hashbuff;
      prevSize = size;
      hashbuff = NULL;
      size     = 0;
      ptr      = NULL;
    }
    // Move to the next in the path
    segListElem = segListElem->to;
  }
  
  if (prevHash != NULL)
  {
    free (prevHash);
    prevHash = NULL;
    prevSize = 0;
  }
  
  return success;  
}

/**
 * Get the signature block. The block is written in the buffer data which must 
 * be of sufficient size.
 * 
 * @param data The data buffer where the data is written into
 * @param algo The algorithm parameter.
 * @param ctSegments The number of segments to be processed
 * @param nextAS The peer where to sign the data to (host format).
 * @param prefix The prefix - all values in host format
 * @param spSeg The pointer to the first secure path segment in the data stream
 * @param asList The list containing all keys and SKI's
 * 
 * @return the length of this signature block in bytes of zero "0" if not all
 *         signatures could be generated.
 */
static int _fillSignatureBlock(u_int8_t* data, AlgoParam* algo, int ctSegments, 
                               u_int32_t nextAS, BGPSEC_PrefixHdr* prefix,
                               tPSegList* spSegList, TASList* asList)
{
  // Currently contains the required size for the signature block header plus
  // the length for each SKI and the size for each signature length field. The 
  // only portion missing is the actual length of each signature. 
  u_int16_t sigBlockLength = sizeof(BGPSEC_SignatureBlock)
                             + ctSegments * (sizeof(BGPSEC_SignatureSegment));

  BGPSEC_SignatureBlock*   sigBlock = (BGPSEC_SignatureBlock*)data;
  BGPSEC_SignatureSegment* sigSeg = NULL;
    
  sigBlock->length = 0; // will be set at the end.
  sigBlock->algoID = algo->algoID;
  
  // Move pointer to the signature segments.
  data += sizeof(BGPSEC_SignatureBlock);

  algo->pubKeysStored = 0;
  // Initialize fake setting just in case it is needed.
  algo->fakeUsed      = false;

  // Now move through the path starting by the origin, generate each hash
  // and sign it.
  if (!_signDraft15(spSegList, prefix, nextAS, algo, asList, true))
  {
    sigBlockLength = 0;
    sigBlock->algoID = 0;
  }
  else
  {
    spSegList = _forwardPSegList(spSegList);

    // Now Write the signature block into the data buffer by walking through the 
    // segment list, last signature first, origin signature last.
    while (spSegList != NULL)
    {
      // First lay the template over the buffer
      sigSeg = (BGPSEC_SignatureSegment*)data;

      // Now if available store the SKI
      if (spSegList->asInfo != NULL) // Might be NUL id key not found!
      {
        memcpy(sigSeg->ski, spSegList->asInfo->key.ski, SKI_LENGTH);    
      }
      else
      {
        if (algo->fakeUsed)
        {
          // No need to check the ns_mode, fakeUsed only can be set in fake mode
          // Now add the fake SKI : BZ912
          memcpy(sigSeg->ski, algo->fake_key.ski, SKI_LENGTH);    
        }
      }

      // Now set the signature length and move the buffer pointer
      sigSeg->siglen = htons(spSegList->sigLen);
      data += sizeof(BGPSEC_SignatureSegment);

      // If the signature exists (length > 0) copy the signature into the buffer
      if (spSegList->sigLen > 0 )
      {
        memcpy(data, spSegList->signature, spSegList->sigLen);
        // move the buffer pointer over the signature
        data += spSegList->sigLen;

        // Add the signature size to the block length (was not done before)
        sigBlockLength += spSegList->sigLen;

        // free the signature from the segment list
        free (spSegList->signature);
        spSegList->signature = NULL;
        spSegList->sigLen = 0;
        // Also cleanup the key info
        spSegList->asInfo = NULL;
      }

      // Now move to the next list element and free the current one.
      spSegList = spSegList->from;
    }

    // Now store the block length
    sigBlock->length = htons(sigBlockLength);
  }
  
  return sigBlockLength;
}

/**
 * Free the test data stream only if it is not the global stream. In case it
 * is the global stream the data will be errased only. To free the global
 * data stream call releaseData().
 * 
 * @param data The data to be freed
 */
void freeData(u_int8_t* data)
{
  if (data != NULL)
  {
    if (data == INT_DATA)
    {
      BGPSEC_PathAttribute* attr = (BGPSEC_PathAttribute*)data;
      memset(data, 0, ntohs(attr->attrLength));
    }
    else
    {
      free (data);
    }
  }
}

/**
 * Print the given bgpsec path attribute.
 * 
 * @param attr the BGPSEC path attribute to be printed
 * @param prefix the prefix to be printed (can be NULL).
 * @param title the title to be used (can be NULL)
 */
void __printBGPSEC_PathAttr(BGPSEC_PathAttribute* attr, char* prefix, char* title)
{
  u_int8_t* data = (u_int8_t*)attr;
  u_int16_t attrLength = ntohs(attr->attrLength);
  u_int8_t* end = data + attrLength;
  char sep;
  char tabStr[STR_MAX];
  memset (tabStr, '\0', STR_MAX);
  printf ("BGPSec Path Attribute\n");
  printf (" +--flags:  %1x\n", attr->pathattr.attr_flags);
  printf (" +--type:   %u\n", attr->pathattr.attr_type_code);
  printf (" +--Length: %u\n", attrLength);
  data += sizeof(BGPSEC_PathAttribute);
  u_int8_t* ptr = data;
  
  BGPSEC_SecurePath* sp = (BGPSEC_SecurePath*)ptr;
  u_int16_t length = ntohs(sp->length);
  printf (" +--SecurePath:\n");  
  printf (" |     +--Length: %u\n", length);
  ptr += sizeof(BGPSEC_SecurePath);  
  length -= sizeof(BGPSEC_SecurePath);

  BGPSEC_SecurePathSegment* spSeg;
  while (length > 0)
  {
    spSeg = (BGPSEC_SecurePathSegment*)ptr;
    length -= sizeof(BGPSEC_SecurePathSegment);
    ptr += sizeof(BGPSEC_SecurePathSegment);
    sep = length > 0 ? '|' : ' ';
    printf (" |     +--PathSegment\n");
    printf (" |     %c     +--asn:    %u\n", sep, ntohl(spSeg->asn));
    printf (" |     %c     +--pcount: %u\n", sep, spSeg->pCount);
    printf (" |     %c     +--flags:  %u\n", sep, spSeg->flags);
  }
    
  while (ptr < end)
  {
    BGPSEC_SignatureBlock* block = (BGPSEC_SignatureBlock*)ptr;
    char sep = (ptr + ntohs(block->length) == end) ? ' ' : '|';      
    printf (" +--SignatureBlock\n");
    printf (" %c     +--Length: %u\n", sep, ntohs(block->length));
    printf (" %c     +--AlgoID: %u\n", sep, block->algoID);
    ptr += sizeof(BGPSEC_SignatureBlock);
    
    BGPSEC_SignatureSegment* sigSegment;
    int sigBlockLen = ntohs(block->length) - sizeof(BGPSEC_SignatureBlock);
    int signatureLen = 0;
    while (sigBlockLen > 0)
    {
      sigSegment = (BGPSEC_SignatureSegment*)ptr;
      char sep2 = (sigSegment->siglen + sizeof(BGPSEC_SignatureSegment)) 
                  < sigBlockLen ? '|' : ' ';
      printf (" %c     +--SignatureBlockSegment\n", sep);
      printf (" %c     %c      +--SKI: ", sep, sep2);
      snprintf(tabStr, STR_MAX, " %c     %c      |       %c", sep, sep2, '\0');
      printHex(sigSegment->ski, sizeof(sigSegment->ski), tabStr);
      signatureLen = ntohs(sigSegment->siglen);
      printf (" %c     %c      +--Sig Length: %u\n", sep, sep2, signatureLen);
      ptr += sizeof(BGPSEC_SignatureSegment);
      printf (" %c     %c      +--Signature: ", sep, sep2);
      snprintf(tabStr, STR_MAX, " %c     %c      |             %c", sep, sep2, 
               '\0');
      printHex(ptr, signatureLen, tabStr);
      ptr += signatureLen;
      sigBlockLen -= (sizeof(BGPSEC_SignatureSegment) + signatureLen);
    }
  }
}
