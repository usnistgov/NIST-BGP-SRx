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
 * NOTE:
 * Functions starting with underscore are only to be called from within this
 * file. Therefore no additional checking is needed is some provided values
 * are NULL. entry functions specified in the header file do take cate of that.
 * 
 * 
 * The internal Cache structure is build along the AS number
 * 
 * The AS number is split into 2 word buckets.
 *             +--------+--------+--------+--------+
 * 4 Byte ASN  |      upper      |       AS2       |
 *             +--------+--------+--------+--------+
 * 
 * Most ASN's currently are in the AS2 bucket only 0x0000[0000] - 0x0000[FFFF]
 * The upper (left) bucket is relatively un-used. For each bit in the upper 
 * bucket, the cache reserves a 64K array for AS2. To keep the memory usage 
 * minimal but still have a speed access the upper uses a single linked list
 * and the AS2 portion a pointer array of 64K elements -> 256K/512K bytes 
 * depending on the pointer size (4 or 8 bytes)
 * 
 * The Cache list looks as follows:
 * 
 * [Cache]
 *   |
 * [upper]--->[upper]-->
 *   |      
 * +---+   
 * |AS2|---[AlgoID]--->[AlgoID]--->
 * +---+      |
 * |AS2|  [SKI;ASN;AlgoID]---[UID]--->[UID]--->
 * +---+      |>
 * .   .  [SKI;ASN;AlgoID]---[UID]--->[UID]--->
 * .   .      |>
 * +---+
 * |AS2|
 * +---+
 * 
 * Legend:
 * ===============================
 * 
 * Name           | Type   | Struct
 * -------------------------------------------------------------------------
 * Cache          | single | _SKI_CACHE
 * -------------------------------------------------------------------------
 * upper          | list   | _SKI_CACHE_NODE, _ski_cache_node (next)
 * -------------------------------------------------------------------------
 * AS2            | array  | _SKI_CACHE_ALGO_ID* [65535] with AS2 as index
 * -------------------------------------------------------------------------
 * AlgoID         | list   | _SKI_CACHE_ALGO_ID, _ski_cache_algo_id (next)
 * -------------------------------------------------------------------------
 * SKI;ASN;ALgoID | list   | _SKI_CACHE_DATA, _ski_cache_data (next)
 * -------------------------------------------------------------------------
 * UID            | list   | _SKI_CACHE_UPDATEID, _ski_cache_updateid (next)
 * -------------------------------------------------------------------------
 * 
 * 
 * +---+
 * |   |       Array (element)
 * +---+
 * 
 * ---  or |   Regular Pointer 
 * 
 * ---> or |>  Next Pointer
 * 
 * [    ]      Struct Element
 * 
 * @version 0.5.0.1
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.5.0.1 - 2017/08/25 - oborchert
 *           * Modified ski parameter from char* to u_int8_t* in function
 *             ___ski_createCacheData to resolve compiler warnings.
 * 0.5.0.0 - 2017/06/30 - oborchert
 *           * BZ1166: Added counter to update registration.
 *         - 2017/06/29 - oborchert
 *           * Added capability to count total number of registered keys during 
 *             ski_examineCache
 *         - 2017/06/26 - oborchert 
 *           * added ski_examineCache which also provides an XML print function
 *         - 2017/06/19 - oborchert
 *           * modified function header for registering key ski's 
 *         - 2017/06/14 - oborchert
 *           * File created
 */
#include <stdlib.h>
#include <string.h>
#include <srx/srxcryptoapi.h>
#include <semaphore.h>
#include "util/log.h"
#include "shared/srx_identifier.h"
#include "server/ski_cache.h"

/** The SKI center value. */
#define _SKI_AS2_ARRAY_SIZE 65536
/** Max number of algorithm id's per BGPsec update (RFC8205) */
#define _SKI_MAX_ALGOIDS 2
/** The size of the SRxUpdateID*/
#define _SRX_UPDATE_ID_SIZE 4

#define _SKI_ERR_CACHE_NULL "RPKI Cache is not initialized (NULL)"
#define _SKI_ERR_NO_LOCK    "Could not aquire cache lock!"
#define _SKI_ERR_BGPSEC     "Error during parsing the BGPsec_PATH attribute!"

/** This structure is a single linked list of update id's */
typedef struct _ski_cache_updateid
{
  /** Pointer to the next update id. */
  struct _ski_cache_updateid* next;
  /** The update id. */
  SRxUpdateID updateID;  
  /** A counter allowing multiple registrations. */
  u_int16_t   counter;
} _SKI_CACHE_UPDATEID;

/** This struct represents a single ski cache data element. One for each triplet
 * <SKI/asn/algoid> */
typedef struct _ski_cache_data
{
  /** in case other SKI's are stored as well */
  struct _ski_cache_data* next;
  /** number of keys received that use this particular ski and algo and asn 
   * combination (should be very rare). */
  u_int8_t    counter;
  /** The ASN of this cache data element */
  u_int32_t   asn;
  /** The SKI of this element */
  u_int8_t    ski[SKI_LENGTH];
  /** The algorithm ID */
  u_int8_t    algoID;
  /** List of updates assigned to this data element */
  _SKI_CACHE_UPDATEID* cacheUID;  
} _SKI_CACHE_DATA ;

/** This struct is a simple linked list for algorithm ID*/
typedef struct _ski_cache_algo_id {
  /** Next algorithm ID */
  struct _ski_cache_algo_id* next;
  /** The algorithm ID*/
  u_int8_t         algoID;  
  /** The ski cache data */
  _SKI_CACHE_DATA* cacheData;
} _SKI_CACHE_ALGO_ID;

/** The cache node if an ordered list of the first 2 bytes. It is expected to 
 * not have many elements. */
typedef struct _ski_cache_node {
  /** The next node. The value of next is larger than the value if this. */
  struct _ski_cache_node* next;  
  /** The left most 2 bytes of the AN number must match this node. */
  u_int16_t upper;
  /** */
  _SKI_CACHE_ALGO_ID* as2[_SKI_AS2_ARRAY_SIZE];
} _SKI_CACHE_NODE;

/** This struct is a helper struct that allows to store all elements down 
 * to the leaf. They are the elements used to walk the structure back and
 * can be understood as the "parent" of each element. This structure is 
 * only intended to be used for temporary usage. It will be filled during 
 * the _ski_getCacheData walk and initialized back to all pointers = NULL
 * before _ski_getCacheData returns. 
 * In other words this structure must not be used outside of an
 * ski_lock / ski_unlock block. */
typedef struct {
  /** The Cache Node  - contains the upper value */
  _SKI_CACHE_NODE*    cNode;
  /** as an additional helper, the position in the as2 array that points to the
   * first cAlgo instance. */
  u_int32_t           as2;
  /** The AlgoID node - contains the algorithm ID */
  _SKI_CACHE_ALGO_ID* cAlgoID;
  /** The Data Node   - This is the leaf and contains all information */
  _SKI_CACHE_DATA*    cData;
} _SKI_TMP_HELPER;

/** This structure has the same function as the tmp helper, it is used to 
 * store the data gathered while parsing the update. This data is used during 
 * registering and unregistering an update
 */
typedef struct {
  /** The parsing result */
  e_Upd_RegRes status;
  /** The number of segments. */
  u_int16_t   nrSegments;
  /** Number of signature blocks. */
  u_int16_t   nrSigBlocks;
  /** An array of as numbers (size if number of segments */
  u_int32_t*  asn;
  /** This array contains the algorithm ids (max 2).*/
  u_int8_t algoID[_SKI_MAX_ALGOIDS];
  /** An array of SKIs (array size is nrSigBlocks * nrSegments * SKI_LENGTH) */
  u_int8_t*   ski;
} _SKI_TMP_UPD_INFO;

/** The internal SKI cache. */
typedef struct {  
  /** The RPKI queue that is used to queue change notifications. */
  RPKI_QUEUE*        rpki_queue;
  /** The SKI cache root node. */
  _SKI_CACHE_NODE*   cacheNode;
  /** The tmpHelper is ONLY be used during walking the data structure. 
   * It is mainly needed to allow a cleanup of data and MUST be NULL during 
   * all times outside of the semaphore lock. */
  _SKI_TMP_HELPER    tmpHelper;
  /** The tmpBGPsecInfo structure is used to store all information gathered 
   * during the parsing of the BGPsec+PATH attribute. Here as well the data
   * must be cleaned prior releasing the semaphore lock. */
  _SKI_TMP_UPD_INFO  tmpBGPsecInfo;
  /** The semaphore for access control. */
  sem_t semaphore;
} _SKI_CACHE;

////////////////////////////////////////////////////////////////////////////////
// Data Structure creation and Release
////////////////////////////////////////////////////////////////////////////////
static _SKI_CACHE_DATA* ___ski_freeCacheData(_SKI_CACHE_DATA* cData);

/**
 * Frees all memory allocated during creation of this element. It also will 
 * free the memory of uid if not shared!
 * 
 * @param cUID The cache Update data.
 * 
 * @return Value of the internal next pointer
 */
static _SKI_CACHE_UPDATEID* ___ski_freeCacheUID(_SKI_CACHE_UPDATEID* cUID)
{
  _SKI_CACHE_UPDATEID* next = NULL;
  if (cUID != NULL)
  {
    next = cUID->next;
    memset(cUID, 0, sizeof(_SKI_CACHE_UPDATEID));
    free (cUID);
  }  
  
  return next;          
}

/**
 * Create a new Update Data list element only if upateID is not NULL and the 
 * value is not zero
 * 
 * @param updateID The SRx update id to be stored.
 * 
 * @return The ski cache update id or NULL if updateID is NULL or zero
 */
static _SKI_CACHE_UPDATEID* ___ski_createCacheUID(SRxUpdateID* updateID)
{
  _SKI_CACHE_UPDATEID* cUID = NULL;
  if ((updateID != NULL) && (*updateID != 0))
  {
    cUID = malloc(sizeof(_SKI_CACHE_UPDATEID));
    cUID->next = NULL;
    // Set to the initial value. (BZ 1166)
    cUID->counter = 1;
    memcpy(&(cUID->updateID), updateID, LEN_SRxUpdateID);
  }
  
  return cUID;          
}

/**
 * Free all memory allocated with the algorithmID. This includes the complete
 * data tree. This function returns the next algorithmID is it exists.
 * 
 * @param cAlgoID The algorithm ID tree to be removed.
 * 
 * @return The value of the next pointer
 */
static _SKI_CACHE_ALGO_ID* ___ski_freeCacheAlgoID(_SKI_CACHE_ALGO_ID* cAlgoID)
{
  _SKI_CACHE_ALGO_ID* next = NULL;
  if (cAlgoID != NULL)
  {
    next = cAlgoID->next;
    while (cAlgoID->cacheData != NULL)
    {
      cAlgoID->cacheData = ___ski_freeCacheData(cAlgoID->cacheData);
    }
    
    memset (cAlgoID, 0, sizeof(_SKI_CACHE_ALGO_ID));
    free (cAlgoID);
  }
  return next;
}

/**
 * Create a cache algorithm id list
 * 
 * @param algoID the algorithm identifier of the data node
 *
 * @return the algorithm ID
 */
static _SKI_CACHE_ALGO_ID* ___ski_createCacheAlgoID(u_int8_t algoID)
{
  _SKI_CACHE_ALGO_ID* cAlgoID = malloc(sizeof(_SKI_CACHE_ALGO_ID));
  
  memset (cAlgoID, 0, sizeof(_SKI_CACHE_ALGO_ID));  
  cAlgoID->algoID = algoID;
  
  return cAlgoID;
}

/**
 * Free this given cache data object including all assigned update id's
 * 
 * @param data The cache data to be removed
 * 
 * @return The value of the next pointer.
 */
static _SKI_CACHE_DATA* ___ski_freeCacheData(_SKI_CACHE_DATA* cData)
{
  _SKI_CACHE_DATA* next = NULL;
  
  if (cData != NULL)
  {
    // Store the next pointer
    next = cData->next;
    // Remove all update ids.
    while (cData->cacheUID != NULL)
    {
      cData->cacheUID = ___ski_freeCacheUID(cData->cacheUID);
    }
    memset (cData, 0, sizeof(_SKI_CACHE_DATA));
    free (cData);
  }
  
  return next;
}

/**
 * Create a cache dataNode
 * 
 * @param asn the ASN of the data node
 * @param ski the ski of the data node
 * @param algoID the algorithm identifier of the data node
 * @param updateID The update identifier (can be NULL)
 *
 * @return the SKI cache data
 */
static _SKI_CACHE_DATA* ___ski_createCacheData(u_int32_t asn, 
                                               u_int8_t* ski, u_int8_t algoID, 
                                               SRxUpdateID* updateID)
{
  _SKI_CACHE_DATA* cData = malloc(sizeof(_SKI_CACHE_DATA));
  memset (cData, 0, sizeof(_SKI_CACHE_DATA));
  
  cData->asn    = asn;
  cData->algoID = algoID;
  memcpy(cData->ski, ski, SKI_LENGTH);
  if (updateID != NULL)
  {
    cData->cacheUID = ___ski_createCacheUID(updateID);
  }
   
  return cData;
}

/**
 * Free the memory allocated with this cache node and its underlying data 
 * structure. This function returns the value of the next pointer.
 * This function is very expensive.
 * 
 * @param cNode The cache node to be removed/
 * 
 * @return the next pointer
 */
static _SKI_CACHE_NODE* ___ski_freeCacheNode(_SKI_CACHE_NODE* cNode)
{
  _SKI_CACHE_NODE* next = NULL;
  
  if (cNode != NULL)
  {
    next = cNode->next;
    int idx = 0;
    for (idx = 0; idx < _SKI_AS2_ARRAY_SIZE; idx ++)
    {
      while (cNode->as2[idx] != NULL)
      {
        cNode->as2[idx] = ___ski_freeCacheAlgoID(cNode->as2[idx]);
      }
    }
  }
  // wipe memory
  memset(cNode, 0, sizeof(_SKI_CACHE_NODE));
  free(cNode);
  
  return next;
}

/**
 * Generate a new cache node.
 * 
 * @param upper the upper value of the ASN if the cache node
 * 
 * @return The cache node.
 */
static _SKI_CACHE_NODE* ___ski_createCacheNode(u_int16_t upper)
{
  _SKI_CACHE_NODE* cNode = malloc(sizeof(_SKI_CACHE_NODE));
  
  memset (cNode, 0, sizeof(_SKI_CACHE_NODE));
  cNode->upper = upper;
  
  return cNode;
}

////////////////////////////////////////////////////////////////////////////////
// Cleanup functions
////////////////////////////////////////////////////////////////////////////////
/**
 * Clean the given node and return true of it can be removed without loosing 
 * any other data.
 * 
 * @param cData The data object to be cleaned.
 * @param type The cleanup type
 */
bool ___ski_clean_cData(_SKI_CACHE_DATA* cData, e_SKI_clean type)
{
  bool canFree = false;
  
  if (cData != NULL)
  {
    switch (type)
    {
      case SKI_CLEAN_ALL:
        cData->counter = 0;
        while (cData->cacheUID != NULL)
        {
          cData->cacheUID = ___ski_freeCacheUID(cData->cacheUID);
        }
        break;
      case SKI_CLEAN_KEYS:
        cData->counter = 0;
        break;
      case SKI_CLEAN_UPDATES:
        while (cData->cacheUID != NULL)
        {
          cData->cacheUID = ___ski_freeCacheUID(cData->cacheUID);
        }
      default:
        LOG(LEVEL_ERROR, "Unknown Cleaning Type [%i]", type);
        break;
    }
    // If no further data exist, report as can be freed.
    canFree = (cData->counter == 0) && (cData->cacheUID == NULL);
  }
          
  return canFree;
}

/**
 * Clean all elements connected to this algorithm ID if possible.
 * 
 * @param cAlgoID the algorithm ID object to be cleaned.
 * @param type The type of cleaning.
 * 
 * @return true if this element can be freed and false if still some data is 
 *         attached.
 */
bool ___ski_clean_cAlgoID(_SKI_CACHE_ALGO_ID* cAlgoID, e_SKI_clean type)
{
  bool canFree = false;

  // if we want to clean something, give it the first element to clean
  _SKI_CACHE_DATA* cData = type == SKI_CLEAN_NONE ? NULL : cAlgoID->cacheData;
  _SKI_CACHE_DATA* prev = NULL;
  
  while (cData != NULL)
  {
    if (!___ski_clean_cData(cData, type))
    {
      prev  = cData;
      cData = cData->next;
    }
    else
    {
      // can be freed.
      cData = ___ski_freeCacheData(cData);
      if (prev != NULL)
      {
        prev->next = cData;
      }
      else
      {
        cAlgoID->cacheData = cData;
      }
    }  
  }
  
  if (cAlgoID->cacheData == NULL)
  {
    canFree = true;
  }
  
  return canFree;
}

/**
 * Clean all elements connected to this Data Node if possible.
 * 
 * @param cNode The Cache node to be examined.
 * @param type The cleaning type
 * 
 * @return true if no other data is stored and this element can be freed
 */
bool ___ski_clean_cNode(_SKI_CACHE_NODE* cNode, e_SKI_clean type)
{
  bool canFree = true;
  
  _SKI_CACHE_ALGO_ID* prev    = NULL;
  _SKI_CACHE_ALGO_ID* cAlgoID = NULL;
  
  int idx = 0;
  for (; idx < _SKI_AS2_ARRAY_SIZE; idx++)
  {    
    prev    = NULL;
    cAlgoID = cNode->as2[idx];
    while (cAlgoID != NULL)
    {
      if (___ski_clean_cAlgoID(cAlgoID, type))
      {
        cAlgoID = ___ski_freeCacheAlgoID(cAlgoID);
        if (prev == NULL)
        {
          // This is the head
          cNode->as2[idx] = cAlgoID;
        }
        else
        {
          // repoint the previous next pointer.
          prev->next = cAlgoID;
        }
        continue;
      }
      
      prev = cAlgoID;
      cAlgoID = cAlgoID->next;
    }
    if (cNode->as2[idx] != NULL)
    {
      canFree = false;
    }
  }
  
  
  
  return canFree;
}
////////////////////////////////////////////////////////////////////////////////
// Data Retrieval and Data Storing
////////////////////////////////////////////////////////////////////////////////

/**
 * Return the correct Cache Node or NULL if none is found. If create is set to 
 * true then a new one is created if none exists.
 * 
 * @param sCache The cache where the cache node is located in 
 * @param upper The upper two bytes of the as number.
 * @param create If true create a new one if it does not exist.
 * 
 * @return The cache node or NULL if none is found.
 */
static _SKI_CACHE_NODE* __ski_getCacheNode(_SKI_CACHE* sCache, u_int16_t upper, 
                                           bool create)
{
  /** The cache node. */
  _SKI_CACHE_NODE* cNode = NULL;
  _SKI_CACHE_NODE* prev = NULL;
  bool found = false;
  
  if (sCache->cacheNode != NULL)
  {
    cNode = sCache->cacheNode;
  }
  else if (create)
  {
    sCache->cacheNode = ___ski_createCacheNode(upper);
    cNode             = sCache->cacheNode;
    found             = true;
  }

  while (!found && (cNode != NULL))
  {      
    if (upper < cNode->upper)
    {
      // OK we need to insert a new node
      if (create)
      {
        cNode = ___ski_createCacheNode(upper);
        if (prev != NULL)
        {
          cNode->next = prev->next;            
          prev->next  = cNode;
        }
        else
        {
          cNode->next       = sCache->cacheNode;
          sCache->cacheNode = cNode;
        }
        found = true;
      }
      else
      {
        cNode = NULL;
      }
      continue;
    }
    if (upper == cNode->upper)
    {
      found = true;
      continue;
    }
    prev = cNode;
    if (cNode->next == NULL)
    {
      if (create)
      {
        cNode->next = ___ski_createCacheNode(upper);
        found = true;
      }
    }
    cNode = cNode->next;
  }    
  
  if (!found)
  {
    // cNode should be NULL if not found, so this line is not really necessary
    // but left it just in case.
    cNode = NULL;
  }
  
  return cNode;
}

/**
 * Add the given update udentifier to the cache data object
 * 
 * @param cacheData The cache data object
 * @param updateID the update identifier
 * @param shared specifies if this identifier is shared.
 */
static void __ski_addUpdateCacheUID(_SKI_CACHE_DATA* cacheData, 
                                    SRxUpdateID* updateID)
{
  _SKI_CACHE_UPDATEID* cUID = NULL;
  _SKI_CACHE_UPDATEID* prev = NULL;
  bool added = false;
  int cmp = 0;

  if (cacheData != NULL)
  {
    if (cacheData->cacheUID == NULL)
    {
      cacheData->cacheUID = ___ski_createCacheUID(updateID);
      added = true;
    }    
    cUID = cacheData->cacheUID;
    // Compare only the path validation section.
    while (!added)
    {
      cmp = compareSrxUpdateID(updateID, &cUID->updateID, SRX_UID_PV);
      if (cmp != 0)
      {
        if (cmp < 0)
        {
          // we need to insert the update ID
          cUID = ___ski_createCacheUID(updateID);
          if (prev != NULL)
          {
            // Insert before this one
            cUID->next = prev->next;
            prev->next = cUID;
          }
          else
          {
            cUID->next = cacheData->cacheUID;
            cacheData->cacheUID = cUID;
          }
          added = true;
        }
        else
        {
          if (cUID->next == NULL)
          {
            cUID->next = ___ski_createCacheUID(updateID);
            added = true;                    
          }
          prev = cUID;
          cUID = cUID->next;                    
        }
      }
      else
      {
        // already added
        cUID->counter++; // BZ1166
        added = true;  
      }
    }
  }
}

/**
 * Find the algorithm id for te given cache node. If create is set to true and
 * no algorithm identifier exists this function will create a new one.
 * 
 * @param cacheNode the cache node the algorithm identifier belongs too.
 * @param as2 the lower 2 bytes of the asn (old AS2 value).
 * @param algoID the algorithm identifier
 * @param create if true a new one will be generated if none exists.
 * 
 * @return The algorithm identifier or NULL is none is found.
 */
static _SKI_CACHE_ALGO_ID* __ski_getCacheAlgoID(_SKI_CACHE_NODE* cacheNode, 
                                                 u_int16_t as2, u_int8_t algoID, 
                                                 bool create)
{
  /** The Cache algorithm identifier */
  _SKI_CACHE_ALGO_ID* cAlgoID = NULL;
  _SKI_CACHE_ALGO_ID* prev;
  bool found = false;
  
  if (cacheNode != NULL)
  {
    if (cacheNode->as2[as2] != NULL)
    {
      cAlgoID = cacheNode->as2[as2];
    }
    else if (create)
    {
      cacheNode->as2[as2] = ___ski_createCacheAlgoID(algoID);
      found = true;
      cAlgoID = cacheNode->as2[as2];
    }            
    
    // Now we found an algorithm ID bin, go to the correct one.
    while (!found && (cAlgoID != NULL))
    {
      // Most likely the first one is the correct one - especially now where we 
      // only have one official algorithm identifier.
      if (cAlgoID->algoID == algoID)
      {
        found = true;
        continue;
      }
      if (algoID < cAlgoID->algoID)
      {
        // Ok we need to insert one.
        if (create)
        {
          cAlgoID = ___ski_createCacheAlgoID(algoID);
          if (prev != NULL)
          {
            cAlgoID->next = prev->next;
            prev->next    = cAlgoID;
          }
          else
          {
            cAlgoID->next       = cacheNode->as2[as2];
            cacheNode->as2[as2] = cAlgoID;
          }
          found = true;
        }
        else
        {
          cAlgoID = NULL;
        }
        continue;
      }
      if (cAlgoID->next != NULL)
      {
        prev    = cAlgoID;
      }
      else
      {
        if (create)
        {
          cAlgoID->next = ___ski_createCacheAlgoID(algoID);
          found = true;
        }
      }
      cAlgoID = cAlgoID->next;
    }    
  }
  
  if (!found)
  {
    cAlgoID = NULL;
  }
          
  return cAlgoID;
}

/**
 * Set the Semaphore lock
 * 
 * @param queue the queue whose access is locked.
 * 
 * @return false if an error occurred
 */
static bool _ski_lock(_SKI_CACHE* sCache)
{
  if (sCache != NULL)
  {
    // Maybe use the sem_wait_wrapper which expires after some time
    sem_wait(&sCache->semaphore);
    // or sem_timedwait(...)
  }
  
  return sCache != NULL;
}

/**
 * Set the Semaphore lock
 * 
 * @param rQueue the queue whose access will be unlocked.
 * 
 * @return false if an error occurred
 */
static bool _ski_unlock(_SKI_CACHE* sCache)
{
  bool retVal = false;
  
  // The caller assures that rQueue is not NULL  
  int lockVal;
  sem_getvalue(&sCache->semaphore, &lockVal);
  // This checks the binary semaphore (0|1)
  if (lockVal == 0)
  {
    // Maybe use the sem_wait_wrapper which expires after some time
    sem_post(&sCache->semaphore);
    retVal = true;
  }
  else 
  {
    LOG(LEVEL_ERROR, "%s called without a previously aquired lock.", 
                     __func__);
  }
  
  return retVal;
}

/**
 * Return the cache data that matches this given <asn,ski,algoid> triplet.
 * This function also generates all required cache structure data and cache data 
 * element if not existing and the parameter 'create' is set to true.
 * 
 * In addition this function sets the temporary helper attribute within the 
 * for later usage.
 * 
 * @param cache The cache where to look in.
 * @param asn The ASN of the cache object in host format.
 * @param ski The SKI of the cache object
 * @param algoID The algorithm identifier of the cache object
 * @param uid The SRx UpdateID (can be NULL)
 * @param create if true the object will be created if it does not exist 
 *        already.
 * 
 * @return the cache data object or NULL.
 */
static _SKI_CACHE_DATA* _ski_getCacheData(_SKI_CACHE* sCache, u_int32_t asn,
                                          u_int8_t* ski, u_int8_t algoID, 
                                          bool create)
{
  /** The left most 2 bytes as unsigned word value. */
  u_int16_t upper = asn >> 16;
  /** The right most 2 bytes as unsigned word value (former AS2 number). */
  u_int16_t as2  = asn & 0xFFFF;
  
  /** Initialize the helper memory */
  _SKI_TMP_HELPER* tHlp = &sCache->tmpHelper;
  memset(tHlp, 0, sizeof(_SKI_TMP_HELPER));  
  tHlp->cNode   = NULL;
  tHlp->cAlgoID  = NULL;
  tHlp->cData    = NULL;
  _SKI_CACHE_DATA*    prev  = NULL;
  bool found = false;
  int  cmp   = 0;
  
  // Retrieve the correct CacheNode from the cache. If the node does not exist
  // yet and create is false, the cacheNODE will be NULL
  tHlp->cNode = __ski_getCacheNode(sCache, upper, create);

  if (tHlp->cNode != NULL)
  {
    // Retrieve the correct algoID list head from the cache. If the node does 
    // not exist yet and create is false, the cacheAlgoID will be NULL      
    tHlp->cAlgoID = __ski_getCacheAlgoID(tHlp->cNode, as2, algoID, create);
  }    
  
  if (tHlp->cAlgoID != NULL)
  {
    // Now where we have the entrance point, find the data
    if (tHlp->cAlgoID->cacheData != NULL)
    {
      tHlp->cData = tHlp->cAlgoID->cacheData;
    }
    else
    {
      if (create)
      {
        tHlp->cData = ___ski_createCacheData(asn, ski, algoID, NULL);
        tHlp->cAlgoID->cacheData = tHlp->cData;
        found = true;
      }
    }
    
    while (!found && (tHlp->cData != NULL))
    {
      cmp = memcmp(ski, tHlp->cData->ski, SKI_LENGTH);
      if (cmp < 0)
      {
        // We need to insert
        if (create)
        {
          tHlp->cData = ___ski_createCacheData(asn, ski, algoID, NULL);
          if (prev != NULL)
          {
            tHlp->cData->next = prev->next;
            prev->next  = tHlp->cData;            
          }
          else
          {
            tHlp->cData->next        = tHlp->cAlgoID->cacheData;
            tHlp->cAlgoID->cacheData = tHlp->cData;
          }
          found = true;
        }
        else
        {
          tHlp->cData = NULL;
        }
        continue;
      }
      if (cmp == 0)
      {
        found = true;
        continue;
      }
      prev  = tHlp->cData;      
      tHlp->cData = tHlp->cData->next;
      if (tHlp->cData == NULL)
      {
        if (create)
        {
          tHlp->cData = ___ski_createCacheData(asn, ski, algoID, NULL);
          prev->next  = tHlp->cData;
          found = true;
        }
      }
    }
  }

  if (!found)
  {
    memset(tHlp, 0, sizeof(_SKI_TMP_HELPER));
  }
  
  return tHlp->cData;
}

////////////////////////////////////////////////////////////////////////////////
// Process BGPsec Update
////////////////////////////////////////////////////////////////////////////////

/** 
 * This function cleans allocated memory of internal arrays and sets all 
 * values to zero or NULL
 * 
 * @param tmpBGPsecInfo The bgpsec Update info object
 */
static void _ski_initializeUpdInfo(_SKI_TMP_UPD_INFO* tmpBGPsecInfo)
{ 
  // First wipe and free all internal allocated memory, then wipe structure.
  
  // Wipe and Free the list of ASNs
  if (tmpBGPsecInfo->asn != NULL)
  {
    // wipe the memory
    memset(tmpBGPsecInfo->asn, 0, tmpBGPsecInfo->nrSegments * sizeof(u_int32_t));
    // free the list memory
    free(tmpBGPsecInfo->asn);
  }
    
  // Wipe and Free the list of SKIs
  if (tmpBGPsecInfo->ski != NULL)
  {
    // first wipe memory
    int memSize = tmpBGPsecInfo->nrSegments * tmpBGPsecInfo->nrSigBlocks 
                  * SKI_LENGTH;
    memset(tmpBGPsecInfo->ski, 0, memSize);
    // now free memory
    free(tmpBGPsecInfo->ski);
  }
  
  // Set all values to zero / NULL
  memset(tmpBGPsecInfo, 0, sizeof(_SKI_TMP_UPD_INFO));
}

/**
 * Parse the BGPsec_PATH and store the information in the updInfo structure that 
 * is handed over.
 * The memory must be freed using the function __ski_freeInternUpdInfo()
 * 
 * @param updInfo Will be initialized and filled with the update information.
 * @param pathAttr The bgpsec path attribute
 * @param updateID The ID of the update (can be null).
 * 
 */
static void _ski_parseBGPsec_PATH (_SKI_TMP_UPD_INFO* updInfo,
                                    SCA_BGP_PathAttribute* pathAttr, 
                                    SRxUpdateID* uID)
{
  #define _BGPSEC_MAX_SIG_BLOCKS 2  
  SCA_BGPSEC_SecurePath*        securePath  = NULL;
  SCA_BGPSEC_SecurePathSegment* pathSegment = NULL;
  SCA_BGPSEC_SignatureBlock*    sigBlocks[_BGPSEC_MAX_SIG_BLOCKS] = {NULL, NULL};
  SCA_BGPSEC_SignatureSegment*  sigSement   = NULL;
 
  u_int8_t*   stream = NULL;  
  SRxUpdateID updateID;
  
  _ski_initializeUpdInfo(updInfo);
  updInfo->status = REGVAL_ERROR;
  if (uID != NULL)
  {
    updateID = *uID;
  }
  
  if (pathAttr != NULL)
  {
    stream = (u_int8_t*)pathAttr;
    // Now figure out the type of path information  
    stream += sizeof(SCA_BGP_PathAttribute);
    // Contains the length of SecurePath and all Signature blocks.
    u_int16_t remainder = 0;  
    if ((pathAttr->flags & SCA_BGP_UPD_A_FLAGS_EXT_LENGTH) == 0)
    {
      remainder = *stream;
      stream++;
    }
    else
    {
      // Extended message length (2 bytes)
      remainder = ntohs(*((u_int16_t*)stream));
      stream    += 2;
    }    
    if (remainder <= 0) { return; }
    
    // Now stream is located at the Secure_Path element.
    securePath  = (SCA_BGPSEC_SecurePath*)stream;
    updInfo->nrSegments = ((ntohs(securePath->length)-2) / 6);
    // Now move stream to first secure path segment
    remainder  -= 2;
    if (remainder <= 0)
    { LOG(LEVEL_ERROR, "Malformed BGPsec update, UpdateID[0x%X]\n", updateID);
      return; 
    }
    stream     += 2;
    
    // Now we parsed the "header" - get the Path segments
    pathSegment = (SCA_BGPSEC_SecurePathSegment*)stream;
    
    // Now move stream to the first signature block    
    remainder  -= (updInfo->nrSegments * 6);
    // here only check for < 0 in case we do NOT have a signature block
    if (remainder < 0) 
    { LOG(LEVEL_ERROR, "Malformed BGPsec update, UpdateID[0x%X]\n", updateID);
      return; 
    }            
    if (remainder > 0)
    {
      // set to position of first signature block
      updInfo->nrSigBlocks = 1;
      // Move stream to first signature block (remainder is already set)
      stream += (updInfo->nrSegments * 6);
      sigBlocks[0] = (SCA_BGPSEC_SignatureBlock*)stream;
      int length = ntohs(sigBlocks[0]->length);
      // move to the end of the first signature block
      stream    += length;
      remainder -= length;
      
      // Now check if a second signature block exists
      if (remainder > 0)
      {
        // set the second signature block
        updInfo->nrSigBlocks = 2;
        sigBlocks[1] = (SCA_BGPSEC_SignatureBlock*)stream;
        // Now get the length of this signature block
        length = ntohs(sigBlocks[1]->length);
        // and adjust remainder
        remainder -= length;
      }
      
      // Now remainder MUST be 0 or the attribute is MALFORMED.
      if (remainder != 0) 
      { LOG(LEVEL_ERROR, "Malformed BGPsec update, UpdateID[0x%X]\n", updateID);
        return; 
      }
      // Now we MUST have a remainder of zero, otherwise the attribute is 
      // malformed.
    }
    
    // Now where we are here the update seems to be syntactically OK. 
    updInfo->status = REGVAL_INVALID;
    
    int idx = 0;
    int size = sizeof(u_int32_t) * updInfo->nrSegments;
    //allocate the asn list
    updInfo->asn = malloc(size);
    memset(updInfo->asn, 0, size);
    
    for (idx = 0; idx < updInfo->nrSegments; idx ++)
    {
      updInfo->asn[idx] = ntohl(pathSegment->asn);
      if (idx < updInfo->nrSegments)
      {
        // Jump to the next segment
        pathSegment++;
      }
    }
    
    // Now create the ski array
    updInfo->ski = malloc(updInfo->nrSigBlocks * updInfo->nrSegments 
                          * SKI_LENGTH);
    u_int8_t* skiStream = updInfo->ski;
    
    // Do this for each signature block
    int blockIdx = 0;
    while (sigBlocks[blockIdx] != NULL)
    {
      updInfo->algoID[blockIdx] = sigBlocks[blockIdx]->algoID;
      // Move the stream to the signature block
      stream = (u_int8_t*)sigBlocks[blockIdx];
      // Move the stream to the next signature segment
      stream += sizeof(SCA_BGPSEC_SignatureBlock);
      for (idx = 0; idx < updInfo->nrSegments; idx ++)
      {
        // Set the signature segment
        sigSement = (SCA_BGPSEC_SignatureSegment*)stream;
        memcpy(skiStream, sigSement->ski, SKI_LENGTH);        
        // Now move the skiStream Pointer to then next available space
        skiStream += SKI_LENGTH;
        
        // Now move to the next signature segment if available
        if (idx < updInfo->nrSegments)
        {
          // jumping to the next signature           
          stream +=   sizeof(SCA_BGPSEC_SignatureSegment) 
                    + ntohs(sigSement->siglen); //the later one is the signature
        }
      }
      // Move to the next block (should be null is not set)
      blockIdx++;
    }    
  }
}

////////////////////////////////////////////////////////////////////////////////
// HEADER FILE FUNCTIONS
////////////////////////////////////////////////////////////////////////////////

/**
 * Create and initialize as SKI cache. The SKI Cache uses the RPKI queue to 
 * signal changes in the ski cache. Wither the queue or a queue manager will 
 * notify the consumer of these changes.
 * 
 * @param rpki_queue The RPKI queue where changes for updates are queued in
 * 
 * @return Pointer to the SKI cache or NULL if an error occurred.
 */
SKI_CACHE* ski_createCache(RPKI_QUEUE* rpki_queue)
{
  _SKI_CACHE* sCache = NULL;  
  char* errMSG = NULL;
  
  if ( rpki_queue != NULL )
  {
    sCache = malloc(sizeof(_SKI_CACHE));
    memset (sCache, 0, sizeof(_SKI_CACHE));
    sCache->rpki_queue = rpki_queue;
    // Initialize the semaphore, not shared value 1 (binary)
    if (sem_init(&sCache->semaphore, 0, 1) != 0)
    {
      free(sCache);
      errMSG = "Could not initialize SKI Cache Lock!";
    }
  }
  else
  {
    errMSG = _SKI_ERR_CACHE_NULL;
  }
  if (errMSG != NULL)
  {
    LOG (LEVEL_ERROR, "%s: %s", __func__, errMSG);
  }
  
  return (SKI_CACHE*)sCache;
}

/**
 * Frees all allocated resources. The cleanup uses the semaphore locking, after
 * that it doesn't
 *
 * @param cache The SKI cache that needs to be removed.
 * 
 * @return false if an error occurred, otherwise true
 */
bool ski_releaseCache(SKI_CACHE* cache)
{
  char* errMSG = NULL;
  // first call clean.
  if (cache != NULL)
  {    
    if (ski_clean(cache, SKI_CLEAN_ALL))
    {
      _SKI_CACHE* sCache = (_SKI_CACHE*)cache;    
      sem_destroy(&sCache->semaphore);
      memset(sCache, 0, sizeof(_SKI_CACHE));
      free (sCache);
    }
    errMSG = "Could not clean SKI CACHE during release.";
  }
  else
  {
    errMSG = _SKI_ERR_CACHE_NULL;
  }
  
  if (errMSG != NULL)
  {
    LOG(LEVEL_ERROR, "%s: %s", __func__, errMSG);
  }
  
  return errMSG != NULL;
}

/**
 * Register the update with the ski cache. This method scans through the 
 * the BGPSEC secure path and extracts all SKI's and their associated algorithm
 * id and registers the SKI's in the SKI cache and assigns the update ID's to 
 * the SKI's. 
 * 
 * If this process notices that none of the signature blocks can be 
 * validated due to missing keys, it will return SKIVAL_INVALID. 
 * 
 * If at least one signature block had keys registered to all found SKI's the 
 * return value will be SKIVAL_UNKNOWN. 
 * 
 * If the handed update is not a BGPSEC update, the return value will be 
 * SKIVAL_ERROR.
 * 
 * The return value of SKIVAL_UNKNOWN does require a complete BGPSEC path 
 * validation to retrieve the correct BGPSEC path validation result.
 * 
 * @param cache The SKI cache.
 * @param updateID The ID of the BGPSec update
 * @param bgpsec The BGPsec_PATH attribute.
 * 
 * @return REGVAL_ERROR if not BGPsec_PATH attribute, REGVAL_INVALID if at least 
 *                      one key is missing in all signature blocks, 
 *                      REGVAL_UNKNOWN if all keys are available.
 */
e_Upd_RegRes ski_registerUpdate(SKI_CACHE* cache, SRxUpdateID* updateID, 
                                SCA_BGP_PathAttribute* bgpsec)
{
  #define _BGPSEC_MAX_SIG_BLOCKS 2
  e_Upd_RegRes retVal = REGVAL_ERROR;
  
  LOG(LEVEL_DEBUG, "ski_register %i", *updateID);
  
  char* errMSG = NULL;

  if (cache != NULL)
  {
    _SKI_CACHE* sCache = (_SKI_CACHE*)cache;
    if (_ski_lock(sCache))
    {
      _SKI_CACHE_DATA* cData  = NULL;

      u_int32_t asn;
      u_int8_t* ski;
      u_int8_t  algoID;

      if (bgpsec != NULL)
      {
        // Parse the BGPsec+PATH attribute
        _ski_parseBGPsec_PATH(&sCache->tmpBGPsecInfo, bgpsec, updateID);
        retVal = sCache->tmpBGPsecInfo.status;

        if (retVal != REGVAL_ERROR)
        {
          // Now where we have the BGPsec_PATH attribute successfully parsed,
          // register the update with each SKI
          int sbIdx, segIdx, skiOffset;
          // Now do this for each signature block:
          for (sbIdx = 0; sbIdx < sCache->tmpBGPsecInfo.nrSigBlocks; sbIdx++)
          {            
            algoID = sCache->tmpBGPsecInfo.algoID[sbIdx];
            // Now run through the signature segments and in parallel through 
            // the path segments.
            for (segIdx = 0; segIdx < sCache->tmpBGPsecInfo.nrSegments; segIdx++)
            {
              // Now the ski's are stored in sequence, we need to calculate the 
              // current position.
              //        current sig block pos  add previous sig block
              skiOffset = (segIdx * SKI_LENGTH) + (segIdx * SKI_LENGTH * sbIdx);
              asn = sCache->tmpBGPsecInfo.asn[segIdx];
              ski = sCache->tmpBGPsecInfo.ski + skiOffset;
              cData = _ski_getCacheData(sCache, asn, ski, algoID, true);
              // Now register the UpdateID with this cData
              __ski_addUpdateCacheUID(cData, updateID);        
            }            
          }
        }
        else
        {
          errMSG = _SKI_ERR_BGPSEC;
        }
        // cleanup
        _ski_initializeUpdInfo(&sCache->tmpBGPsecInfo);
      }
      else
      {
        errMSG = "Provided BGPsec_PATH is not initialized (NULL)";
      }
      _ski_unlock(sCache);
    }
    else
    {
      errMSG = _SKI_ERR_NO_LOCK;    
    }
  }
  else
  {
    errMSG = _SKI_ERR_CACHE_NULL;
  }
  
  if (errMSG != NULL)
  {
    LOG(LEVEL_ERROR, "%s: %s", __func__, errMSG);
  }

  return retVal;  
}

/**
 * Remove the update id from the SKI cache.
 * 
 * @param cache The SKI cache
 * @param updateID The update ID to be unregistered
 * @param bgpsec The BGPSEC path attribute.
 * 
 * @return false if an error occurred, otherwise true
 */
bool ski_unregisterUpdate(SKI_CACHE* cache, SRxUpdateID* updateID,
                          SCA_BGP_PathAttribute* bgpsec)
{
  char* errMSG = NULL;
 
  LOG(LEVEL_DEBUG, "ski_unregisterUpdate %i", *updateID);  
  
  if (cache != NULL)
  {
    _SKI_CACHE* sCache     = (_SKI_CACHE*)cache;
    if (_ski_lock(sCache))
    {
      if (bgpsec != NULL)
      {
        _ski_parseBGPsec_PATH(&sCache->tmpBGPsecInfo, bgpsec, updateID);
        if (sCache->tmpBGPsecInfo.status != REGVAL_ERROR)
        {      
          // Signature Block Index
          int       sbIdx  = 0;
          // Path Segment Index
          int       psIdx  = 0;
          // The ski position offset
          int       skiOffset = 0;
          // SKI
          u_int8_t* ski    = NULL;
          u_int32_t asn    = 0;
          u_int8_t  algoID = 0;
          _SKI_CACHE_DATA* cData = NULL;
          for (sbIdx = 0; sbIdx < sCache->tmpBGPsecInfo.nrSigBlocks; sbIdx++)
          {
            algoID = sCache->tmpBGPsecInfo.algoID[sbIdx];
            for (psIdx = 0; psIdx < sCache->tmpBGPsecInfo.nrSegments; psIdx++)
            {
              asn = sCache->tmpBGPsecInfo.asn[psIdx];
              ski = sCache->tmpBGPsecInfo.ski + skiOffset;            
              skiOffset += SKI_LENGTH;
              // Only look for it, do NOT create
              cData = _ski_getCacheData(sCache, asn, ski, algoID, false);
              // It should not be NULL but could if an unregister is called more
              // than once with the same input data.
              if (cData != NULL)
              {
                _SKI_CACHE_UPDATEID* cUID = cData->cacheUID;
                _SKI_CACHE_UPDATEID* prev = NULL;
                while (cUID != NULL)
                {
                  int cmp = compareSrxUpdateID(updateID, &cUID->updateID, 
                                               SRX_UID_PV);
                  if (cmp != 0)
                  {                  
                    if (cmp > 0)
                    {
                      prev = cUID;
                      cUID = cUID->next;                 
                    }
                    else
                    {
                      // Update not registered!
                      cUID = NULL;
                      LOG(LEVEL_WARNING, "Could not find any update registration "
                          "%u for the particular cache data element", *updateID);
                    }
                  }
                  else
                  {
                    // Update found - unregister the instance. BZ1166 (counter)
                    cUID->counter--;
                    if (cUID->counter == 0)
                    {
                      if (prev != NULL)
                      {
                        prev->next = ___ski_freeCacheUID(cUID);;                    
                      }
                      else
                      {
                        cData->cacheUID = ___ski_freeCacheUID(cUID);;
                      }
                    }
                    // Set it to NULL to stop the loop.
                    cUID = NULL;
                  }
                }

                // Now check if cData can be removed as well
                if ((cData->cacheUID == NULL) && (cData->counter == 0))
                {
                  // Remove this cData instance
                  // 1st Check if it is the head
                  if (sCache->tmpHelper.cAlgoID->cacheData == cData)
                  {
                    // remove the head
                    sCache->tmpHelper.cAlgoID->cacheData = 
                                                      ___ski_freeCacheData(cData);
                  }
                  else
                  {                  
                    // find the previous element - go to th ehead
                    _SKI_CACHE_DATA* prev_cData = 
                                             sCache->tmpHelper.cAlgoID->cacheData;
                    // Now walk until it is found
                    while (prev_cData->next != cData)
                    {
                      prev_cData = prev_cData->next;
                    }
                    // Now take it out
                    prev_cData->next = ___ski_freeCacheData(cData);
                    cData = NULL;
                  }
                  sCache->tmpHelper.cData = NULL;
                }
              }
              else
              {
                LOG(LEVEL_WARNING, "No registration found for the given update %u",
                                   *updateID);
              }
            }
          }        
        }
        else
        {
          errMSG = _SKI_ERR_BGPSEC;
        }
        // cleanup
        _ski_initializeUpdInfo(&sCache->tmpBGPsecInfo);
      }
      _ski_unlock(sCache);
    }
    else
    {
      errMSG = _SKI_ERR_NO_LOCK;
    }
  }
  
  if (errMSG != NULL)
  {
    LOG (LEVEL_ERROR, "%s: %s", __func__, errMSG);
  }
  
  return (errMSG != NULL) ? false : true;
}

/**
 * Register the <SKI, algo-id> tuple in the SKI cache. This might trigger 
 * notifications for possible kick-starting of update validation.
 * 
 * @param cache The SKI cache.
 * @param asn The ASN the key is assigned to in host format.
 * @param ski The 20 byte SKI of the key.
 * @param algoID The algorithm ID of the key.
 * 
 * @return false if an error occurred, otherwise true
 */
bool ski_registerKey(SKI_CACHE* cache, u_int32_t asn, 
                     u_int8_t* ski, u_int8_t algoID)
{
  char* errMSG = NULL;

  LOG(LEVEL_DEBUG, "ski_registerKey asn=%i", asn);
  
  if (cache != NULL)
  {
    _SKI_CACHE* sCache = (_SKI_CACHE*)cache;
    if (_ski_lock(sCache))
    {        
      _SKI_CACHE_DATA* cData = _ski_getCacheData(sCache, asn, ski, algoID, true);
      // Clean the helper structure.
      memset(&sCache->tmpHelper, 0, sizeof(_SKI_TMP_HELPER));
      
      cData->counter++;
      // After some discussion we decided to always add a notification, not only
      // in the case from 0 to 1 or 1 to 0 but also from 1 to 2.
      // The reason is that in SCA we check all colliding keys (which is the 
      // case for > 1) and new new one could switch the validation state from 
      // invalid to valid.
      if (cData->cacheUID != NULL)
      {
        // Yeah a new key was registered and we had already updates asking for it.
        // Now notify these updates
        _SKI_CACHE_UPDATEID* cUID = cData->cacheUID;
        while (cUID != NULL)
        {      
          rq_queue(sCache->rpki_queue, RQ_KEY, &cUID->updateID);
          cUID = cUID->next;
        }
      }
      _ski_unlock(sCache);
    }
    else
    {
      errMSG = _SKI_ERR_NO_LOCK;
    }
  }
  else
  {
    errMSG = "SKI Cache is not initialized (NULL)!";
  }
  if (errMSG != NULL)
  {
    LOG(LEVEL_ERROR, "%s: %s", __func__, errMSG);
  }
  
  return (errMSG != NULL) ? false : true;
}

/** 
 * Remove the key counter from the <SKI, algo-id> tuple. This might trigger 
 * notifications for possible kick-starting of update validation. This method
 * DOES not perform a "deep-clean". It removes the data element if necessary but
 * not the internal data structure that leads to the data. for "deep-clean"
 * call ski_gc.
 * 
 * @param cache The SKI cache.
 * @param asn The ASN the key is assigned to in host format.
 * @param ski The 20 byte SKI of the key
 * @param algoID The algorithm ID of the key
 * 
 * @return false if an error occurred, otherwise true
 */
bool ski_unregisterKey(SKI_CACHE* cache, u_int32_t asn, 
                       u_int8_t* ski, u_int8_t algoID)
{
  char* errMSG = NULL;

  LOG(LEVEL_DEBUG, "ski_unregisterKey asn=%i", asn);
  
  if (cache != NULL)
  {
    _SKI_CACHE* sCache = (_SKI_CACHE*)cache;
    _ski_lock(sCache);

    // first find the SKI data object
    _SKI_CACHE_DATA* cData = _ski_getCacheData(sCache, asn, ski, algoID, false);
    bool canUnregister = cData != NULL;
    
    if (canUnregister)
    {
      // Now check if this data object has keys installed (counter > 1)
      canUnregister = cData->counter > 0;
      if (canUnregister)
      {
        // Now we can actually decrease the key counter (unregister).
        cData->counter--;
        
        // Now determine if we can either delete this element altogether or
        // if we need to notify updates of the change
        if (cData->cacheUID != NULL)
        {
          // Notify the attached updates
          _SKI_CACHE_UPDATEID* cUID = cData->cacheUID;
          while (cUID != NULL)
          {
            rq_queue(sCache->rpki_queue, RQ_KEY, &cUID->updateID);
            cUID = cUID->next;
          }
        }
        else
        {
          // We can remove it.
          // we need to check if this data element is in between two elements.
          _SKI_TMP_HELPER* tmpHelper = &sCache->tmpHelper;
          _SKI_CACHE_DATA* head = tmpHelper->cAlgoID->cacheData;
          if (head == cData)
          {
            // This is the first element, take it out and put the next one in 
            // its place.
            tmpHelper->cAlgoID->cacheData = cData->next;
          }
          else
          {
            // its in the middle, find its previous one.
            _SKI_CACHE_DATA* prev = head;
            while (prev->next != cData)
            {
              prev = prev->next;              
            }
            // Now we are there
            prev->next = cData->next;
          }
          // Now remove the element.
          ___ski_freeCacheData(cData);
          cData = NULL;            
        }
      }
    }
    
    if (!canUnregister)
    {
      LOG(LEVEL_WARNING, "Attempt to unregister a key for ASN %u that is not"
                         "previously registered!", asn);
    }
    
    _ski_unlock(sCache);
  }
  
  return (errMSG != NULL) ? false : true;
}

/**
 * This function does clean up the SKI CACHE. It can empty it, or selectively
 * clean all key registration or update registration. This clean walks through 
 * the complete data structure and cleans all empty structures.
 * If the clean type is SKI_CLEAN_NONE it does perform garbage collection.
 * 
 * IMPORTANT:
 * Use this function with caution. This function does not add any notifications
 * to the RPKI QUEUE!
 * 
 * @param cache The cache to be cleaned
 * @param mode The type of cleaning to be performed, SKI_CLEAN_KEYS, 
 *             SKI_CLEAN_UPDATES, SKI_CLEAN_ALL, SKI_CLEAN_NONE
 * 
 * @return false if an error occurred, otherwise true
 */
bool ski_clean(SKI_CACHE* cache, e_SKI_clean type)
{
  char* errMSG = NULL;
  
  if (cache != NULL)
  {
    _SKI_CACHE* sCache = (_SKI_CACHE*)cache;
    
    if (_ski_lock(sCache))
    {
      if (type == SKI_CLEAN_ALL)
      {
        while (sCache->cacheNode != NULL)
        {
          // Simple and easy delete all.
          sCache->cacheNode = ___ski_freeCacheNode(sCache->cacheNode);
        }        
      }
      else
      {
        _SKI_CACHE_NODE* prev  = NULL;
        _SKI_CACHE_NODE* cNode = sCache->cacheNode;
        // Don't clean all but selectively.
        while (cNode != NULL)
        {
          if (___ski_clean_cNode(cNode, type))
          {
            // We can clean this node
            cNode = ___ski_freeCacheNode(cNode);            
            if (prev == NULL) // head
            {
              sCache->cacheNode = cNode;
            }
            else
            {
              prev->next = cNode;
            }
            continue; //             
          }
          prev  = cNode;
          cNode = cNode->next;
        }
      }
      _ski_unlock(sCache);
    }
    else
    {
      errMSG = _SKI_ERR_NO_LOCK;
    }
  }
  
  return (errMSG != NULL) ? false : true;
}

////////////////////////////////////////////////////////////////////////////////
// Methods to print the cache.
////////////////////////////////////////////////////////////////////////////////

/** This function allows to suppress the print function. */
int __ski_printf(const char *__restrict __format, ...)
{ return 0; }

/**
 * Examine given SKI Cache. This function also allows to print the cache in 
 * XML format if verbose is enabled..
 * 
 * @param cache The cache to be examined
 * @param info The cache info object.
 * @param verbose Do an XML print of the cache while examining it.
 * @param gc Allows to perform garbage collection during examination.
 */
void ski_examineCache(SKI_CACHE * cache, SKI_CACHE_INFO* info, bool verbose)
{
  #define _SKI_PRINT_OPEN  false
  #define _SKI_PRINT_CLOSE true
  #define _SKI_USE_XML     true

  int (*_ski_printf)(const char *__restrict __format, ...);
  _ski_printf = verbose ? &printf : &__ski_printf;
  
  // In case info is NULL
  SKI_CACHE_INFO tmpInfo;
  if (info == NULL)
  {
    info = &tmpInfo;
  }
  memset (info, 0, sizeof(SKI_CACHE_INFO));
  
  _SKI_CACHE*          sCache  = (_SKI_CACHE*)cache;
  _SKI_CACHE_NODE*     cNode   = NULL;
  _SKI_CACHE_ALGO_ID*  cAlgoID = NULL;
  _SKI_CACHE_DATA*     cData   = NULL;
  _SKI_CACHE_UPDATEID* cUID    = NULL;
  int as2    = 0;
  int skiIdx = 0;
  
  if (sCache != NULL)
  {
    if (_ski_lock(sCache))
    {
      _ski_printf ("<SKI_CACHE>\n");
      cNode = sCache->cacheNode;
      while (cNode != NULL)
      {
        info->count_cNode++;
        _ski_printf ("  <CACHE_NODE upper=[0x%04X....]>\n", cNode->upper);
        
        for (as2 = 0; as2 < _SKI_AS2_ARRAY_SIZE; as2++)
        {
          if (cNode->as2[as2] != NULL)
          {
            info->count_AS2++;
            cAlgoID = cNode->as2[as2];
            _ski_printf ("    <AS2 as2=[0x....%04X]>\n", as2);
            while (cAlgoID != NULL)
            {
              info->count_cAlgoID++;
              _ski_printf ("      <CACHE_ALGO_ID algoid=%u>\n", cAlgoID->algoID);
              cData = cAlgoID->cacheData;
              while (cData != NULL)
              {
                info->count_cData++;
                info->count_keys += cData->counter;
                _ski_printf ("        <CACHE_DATA algoID=%u, counter %u>\n",
                        cData->algoID, cData->counter);
                _ski_printf ("          <ASN asn=[0x%08X], asn_int=%u, "
                             "asn_dot=%u.%u />\n", 
                             cData->asn, cData->asn, cNode->upper, 
                             (cData->asn & 0xFFFF));
                _ski_printf ("          <SKI>");
                for (skiIdx = 0 ; skiIdx < SKI_LENGTH; skiIdx++)
                {
                  _ski_printf ("%02X", cData->ski[skiIdx]);
                }
                _ski_printf ("</SKI>\n");
                cUID = cData->cacheUID;
                while (cUID != NULL)
                {
                  info->count_cUID++;
                  info->count_updates += cUID->counter;
                  _ski_printf ("          <UID id=0x%X counter=%u/>\n", 
                               cUID->updateID, cUID->counter);
                  cUID = cUID->next;
                }
                
                _ski_printf ("        </CACHE_DATA>\n");
                cData = cData->next;
              }
              _ski_printf ("      </CACHE_ALGO_ID>\n");
              cAlgoID = cAlgoID->next;
            }
            _ski_printf ("    </AS2>\n");
          }
        }
        
        _ski_printf ("  </CACHE_NODE>\n");
        cNode = cNode->next;
      }
      
      _ski_printf ("</SKI_CACHE>\n");
      
      if (verbose)
      { // Just some simple speedup in case verbose is turned off
        _ski_printf ("Summary:\n");
        _ski_printf ("================================\n");
        _ski_printf ("  count cNode   = %i\n", info->count_cNode);
        _ski_printf ("  count_AS2     = %i\n", info->count_AS2);
        _ski_printf ("  count_cAlgoID = %i\n", info->count_cAlgoID);
        _ski_printf ("  count_cData   = %i\n", info->count_cData);
        _ski_printf ("  count_cUID    = %i\n", info->count_cUID);
        _ski_printf ("  count_keys    = %i\n", info->count_keys);
        _ski_printf ("  count_updates = %i\n", info->count_updates);
      }
      
      _ski_unlock(sCache);
    }
  }    
}