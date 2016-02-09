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
 * This file contains the prefix cache responsible for update validation using
 * ROA information provided by the RPKI Cache.
 *
 * This file have 2 main entry points for debugging:
 * 
 *  - maintainOriginStatus: triggered by information received by the RPKI Cache
 *
 *  - getOriginStatus: Triggered by the SRx - Router - proxy for each
 *                     validation request.
 * 
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/10 - oborchert
 *            * Moved outputPrefixCacheAsXML from c file to header.
 * 0.3.0    - 2013/03/20 - oborchert
 *            * Added filter to not accept white-list entries for AS numbers
 *              specified in rfc5398.
 *          - 2013/01/28 - oborchert
 *            * Update to be compliant to draft-ietf-sidr-rpki-rtr.26. This 
 *              update does not include the secure protocol section. The 
 *              protocol will still use un-encrypted plain TCP
 *          - 2013/01/01 - oborchert
 *            * Removed dead code
 * 0.2.0    - 2011/01/07 - oborchert
 *            * Completely rewritten
 * 0.1.0    - 2010/05/24 - pgleichm
 *            * Code complete rewritten
 * 0.0.0    - 2010/04/08 - pgleichm
 *            * Code Created
 * -----------------------------------------------------------------------------
 */

#include <stdlib.h>
#include <string.h>

#include <uthash.h>
#include "server/prefix_cache.h"
#include "shared/srx_defs.h"
#include "util/log.h"
#include "util/math.h"
#include "util/xml_out.h"

#define  HDR "[PrefixCache [0x%08X]]: "

/*-----------------------------
 * R/W lock and mutex debugging
 */

// Trace mutexes and locking
#if 0
  #define PRINT_LINE_VAR(METHOD, VAR) \
    fprintf(stderr, "[r=%d, w=%d] " METHOD " (%s %s:%d) var=" #VAR "\n", \
            num_read_lock, num_write_lock, __func__, __FILE__, __LINE__)

  static int num_read_lock;
  static int num_write_lock;

  bool dbg_createRWLock(RWLock* self) {
    num_read_lock  = 0;
    num_write_lock = 0;
    return createRWLock(self);
  }
  
  #define CREATE_RW_LOCK(VAR) \
    dbg_createRWLock(VAR)

  #define CHANGE_READ_LOCK_COUNT(OP) \
    num_read_lock = num_read_lock OP 1;  

  #define CHANGE_WRITE_LOCK_COUNT(OP) \
    num_write_lock = num_write_lock OP 1;
#else
  #define PRINT_LINE_VAR(METHOD, VAR)
  #define CREATE_RW_LOCK(VAR) createRWLock(VAR)
  #define CHANGE_READ_LOCK_COUNT(OP)
  #define CHANGE_WRITE_LOCK_COUNT(OP)
#endif

// Enable mutexes and locking
#if 0
  #define READ_LOCK(VAR) \
    CHANGE_READ_LOCK_COUNT(+);        \
    PRINT_LINE_VAR("Read lock", VAR); \
    acquireReadLock(VAR)

  #define WRITE_LOCK(VAR) \
    CHANGE_WRITE_LOCK_COUNT(+);        \
    PRINT_LINE_VAR("Write lock", VAR); \
    acquireWriteLock(VAR)

  #define READ_TO_WRITE_LOCK(VAR) \
    CHANGE_READ_LOCK_COUNT(-);                 \
    CHANGE_WRITE_LOCK_COUNT(+);                \
    PRINT_LINE_VAR("Read -> Write lock", VAR); \
    changeReadToWriteLock(VAR)

  #define WRITE_TO_READ_LOCK(VAR) \
    CHANGE_READ_LOCK_COUNT(+);                 \
    CHANGE_WRITE_LOCK_COUNT(-);                \
    PRINT_LINE_VAR("Write -> Read lock", VAR); \
    changeWriteToReadLock(VAR)

  #define UNLOCK_READ_LOCK(VAR) \
    CHANGE_READ_LOCK_COUNT(-);               \
    PRINT_LINE_VAR("Unlock read lock", VAR); \
    unlockReadLock(VAR) 

  #define UNLOCK_WRITE_LOCK(VAR) \
    CHANGE_WRITE_LOCK_COUNT(-);               \
    PRINT_LINE_VAR("Unlock write lock", VAR); \
    unlockWriteLock(VAR)

  #define LOCK_MUTEX(VAR) \
    PRINT_LINE_VAR("Lock mutex", VAR); \
    lockMutex(VAR)

  #define UNLOCK_MUTEX(VAR) \
    PRINT_LINE_VAR("Unlock mutex", VAR); \
    unlockMutex(VAR)
#else
  #define READ_LOCK(VAR)
  #define WRITE_LOCK(VAR)
  #define READ_TO_WRITE_LOCK(VAR)
  #define WRITE_TO_READ_LOCK(VAR)
  #define UNLOCK_READ_LOCK(VAR)
  #define UNLOCK_WRITE_LOCK(VAR)
  #define LOCK_MUTEX(VAR)
  #define UNLOCK_MUTEX(VAR)
#endif

/**
 * Initializes an empty cache and creates a link to an existing Update Cache.
 *
 * @param self the Instance of prefix cache that should be initialized.
 * @param updateCache Instance of the Update Cache that should be notified
 * 
 * @return true if the initialization was successful, otherwise false.
 */
bool initializePrefixCache(PrefixCache* self, UpdateCache* updateCache)
{
  // Create the patricia prefix tree
  self->prefixTree = New_Patricia(PATRICIA_MAXBITS); // 128 = IPv6
  if (self->prefixTree == NULL)
  {
    RAISE_ERROR("Failed to initialize the prefix tree");
    return false;
  }
 
  // Create the mutex and locks
  if (!initMutex(&self->updatesMutex))
  {
    RAISE_ERROR("Failed to initialize the updates mutex");
    Destroy_Patricia(self->prefixTree, NULL);
    return false;
  }
  int step = 0;
  if (CREATE_RW_LOCK(&self->treeLock))
  {
    step = 1;
    if (CREATE_RW_LOCK(&self->asLock))
    {
      step = 2;
      if (CREATE_RW_LOCK(&self->validLock))
      {
        step = 3;
        if (CREATE_RW_LOCK(&self->otherLock))
        {
          step = 4;
        }      
      }      
    }
  }
  if (step < 4)
  {
    RAISE_ERROR("Failed to initialize a cache R/W lock");
    switch (step)
    {
      case 3:  releaseRWLock(&self->validLock);
      case 2:  releaseRWLock(&self->asLock);
      case 1:  releaseRWLock(&self->treeLock);
      default: Destroy_Patricia(self->prefixTree, NULL);
               return false;
    }
  }

  // Misc.
  self->updateCache = updateCache;
  initSList(&self->updates);
  return true;
}

/**
 * This method only frees up the memory attached. No update counter or other
 * maintenance values are maintained here. This method should not be
 * called for other than a clean emptying of the cache.
 * 
 * @param prefix the particular pc prefix to be released.
 */
static void releasePrefix(PC_Prefix* prefix)
{
  SListNode* asListNode;
  SListNode* roaListNode;
  PC_AS*  asNumber;
  PC_ROA* roa;
  
  releaseSList(&prefix->valid);
  releaseSList(&prefix->other);
  
  // All ases
  FOREACH_SLIST(&prefix->asn, asListNode)
  {
    asNumber = (PC_AS*)asListNode->data;
    if (asNumber != NULL)
    {      
      FOREACH_SLIST(&asNumber->roas, roaListNode)
      {
        roa = (PC_ROA*)roaListNode->data;
        if (roa != NULL)
        {
          free(roa);
          roa = NULL;
        }
      }
      releaseSList(&asNumber->roas);
      free(asNumber);
      asNumber = NULL;
    }
  }
  releaseSList(&prefix->asn);  
  free(prefix);
}

/**
 * Frees all allocated resources. the prefix cache itself must be freed outside.
 */
void releasePrefixCache(PrefixCache* self)
{
  if (self != NULL) 
  {
    patricia_node_t*  treeNode;
    SListNode*        listNode;
    PC_Prefix*        prefix;
    PC_Update*        pc_update;
    
    // Free all prefixes and node-data
    WRITE_LOCK(&self->asLock);
    WRITE_LOCK(&self->validLock);
    WRITE_LOCK(&self->otherLock);

    PATRICIA_WALK(self->prefixTree->head, treeNode)
    {
      prefix = PATRICIA_DATA_GET(treeNode, PC_Prefix);            
      releasePrefix(prefix);
    } PATRICIA_WALK_END;
    RAISE_ERROR("Check if the treeNode has to be released independent or if it gets released with the Destroy_Patricia!");
    Destroy_Patricia(self->prefixTree, NULL);
    // test if the DestroyPatricia deleted everything!
    free(treeNode);        //           <<<<<<<------ Hopefully this causes a sigdev
    // end of test. If it was freed before this should cause a SIGDEV!!!! (I HOPE SO)
    
    
    releaseRWLock(&self->otherLock);
    releaseRWLock(&self->validLock);
    releaseRWLock(&self->asLock);
    releaseRWLock(&self->treeLock);

    // Free all updates
    LOCK_MUTEX(&self->updatesMutex);
    FOREACH_SLIST(&self->updates, listNode)
    {
      pc_update = (PC_Update*)getDataOfSListNode(listNode);
      free(pc_update);
    }
    releaseSList(&self->updates);
    releaseMutex(&self->updatesMutex);
  }
}

/**
 * Empty the complete update cache. This method empties the prefix tree and the 
 * all Updates.
 * 
 * @param self The update cache to be emptied!
 */
void emptyCache(PrefixCache* self)
{
  //TODO: Implement for version 0.3.x
#ifndef SRX_ALL
  RAISE_ERROR("NOT IMPLEMENTED YET, PLANNED FOR PROTOTYPE 0.3.x");
#else
  if (self != NULL) 
  {
    patricia_node_t*  treeNode;
    SListNode*        listNode;
    PC_Prefix*        prefix;
    PC_AS*            pc_as;
    PC_ROA*           pc_roa;
    PC_Update*        pc_update;
    
    // Free all prefixes and node-data
    WRITE_LOCK(&self->asLock);
    WRITE_LOCK(&self->validLock);
    WRITE_LOCK(&self->otherLock);

    PATRICIA_WALK(self->prefixTree->head, treeNode)
    {
      prefix = (PC_Prefix*)treeNode->data;
      if (prefix != NULL)
      {
        releasePrefix(prefix);
      }
      treeNode->data = NULL;
    } PATRICIA_WALK_END;    
    Clear_Patricia(self->prefixTree, NULL);
    
    // Free all updates
    LOCK_MUTEX(&self->updatesMutex);
    FOREACH_SLIST(&self->updates, listNode)
    {      
      pc_update = (PC_Update*)listNode->data;
      if (pc_update != NULL)
      {
        free(pc_update);
      }
    }
    emptySList(&self->updates);
    UNLOCK_MUTEX(&self->updatesMutex);
    
    UNLOCK_WRITE_LOCK(&self->asLock);
    UNLOCK_WRITE_LOCK(&self->validLock);
    UNLOCK_WRITE_LOCK(&self->otherLock);
  }  
#endif
}

/**
 * This method returns the parent prefix or NULL if no more parent is available.
 * The parent prefix is NOT the patricia tree parent, it is the next available
 * stored prefix within the tree.
 * 
 * @param prefix The patricia tree node whose parent has to be examined for an 
 *               SRx prefix.
 * 
 * @return The parent prefix if it exists or NULL.
 */
PC_Prefix* getParent(patricia_node_t* node)
{  
  PC_Prefix* retVal = NULL;
  if (node != NULL)
  {
    if (node->parent != NULL)
    {
      node = node->parent;
      // Patricia parent found, does it contain a PC_Prefix?
      retVal = node->data != NULL ? (PC_Prefix*)node->data : getParent(node);
    }      
  }
  // No further parent Found
  return retVal;
}

////////////////////////////////////////////////////////////////////////////////
// FOREWARD DECLARATIONS
////////////////////////////////////////////////////////////////////////////////
static prefix_t* ipPrefixToPrefix_t(IPPrefix* from);
static void notifyUpdateCacheForROAChange(UpdateCache* updCache, 
                    SRxUpdateID* updateID, SRxValidationResultVal newROAResult);
static void _ROAwl_changeStateOfOther(UpdateCache* updateCache, 
                                      PC_Prefix* pcPrefix, 
                                      SRxValidationResultVal newState);
static void printXML(PrefixCache* self, char* methodName);

/**
 * Returns the requested AS attached to the given prefix. In case the AS does 
 * not exist, a new one is created and added.
 * 
 * @param pcPrefix The prefix cache prefix instance.
 * @param as The as number of the prefix.
 * 
 * @return The prefix cache AS or NULL in case a fatal internal error occurred.
 */
static PC_AS* getASFromPrefix(PC_Prefix* pcPrefix, uint32_t as)
{
  PC_AS* pcAS = NULL;
  int idx;
  
  // Go through the list until the as number is found.
  for (idx = 0; idx < pcPrefix->asn.size; idx++)
  {
    pcAS = (PC_AS*)getFromSList(&pcPrefix->asn, idx);
    if (pcAS->asn == as)
    {
      break;
    }
    else
    {
      pcAS = NULL;
    }
  }
  
  // If the AS is not found, create one.
  if (pcAS == NULL)
  {
    pcAS = malloc(sizeof(PC_AS));
    if (appendDataToSList(&pcPrefix->asn, pcAS))
    {
      pcAS->asn          = as;
      pcAS->update_count = 0;
      initSList(&pcAS->roas);      
    }
    else
    {
      RAISE_SYS_ERROR( HDR "Could not add AS%u to the prefix tree!",
                       pthread_self(), as);
      free(pcAS);
      pcAS = NULL;
    }
  }
  return pcAS;
}

/**
 * Return all direct children in the trie one level down that contain a 
 * PC_Prefix. The children are NOT the prefix tree nodes. The children are the 
 * PC_Prefix nodes attached to the data elements. Once a child is found NO 
 * grandchild is searched for.
 * 
 * @param children The list where all children will be stored in. The stored 
 *                 children are of type PC_Prefix*
 * @param node the patricia node whose PC_Prefix children will be searched for.
 * 
 * @return true if any children could be found.
 */
static bool getChildren(SList* children, patricia_node_t* node)
{
  if (node->l != NULL)
  {
    if (node->l->data != NULL)
    {
      if (!appendDataToSList(children, node->l->data))
      {
        RAISE_SYS_ERROR("Could not gather prefix children. Memory Problems, "
                        "Not all children could be added!");
        emptySList(children);
      }
    }
    else
    {
      getChildren(children, node->l); 
    }
  }
  if (node->r != NULL)
  {
    if (node->r->data != NULL)
    {
      if (!appendDataToSList(children, node->r->data))
      {
        RAISE_SYS_ERROR("Could not gather prefix children. Memory Problems, "
                        "Not all children could be added!");
        emptySList(children);
      }
    }
    else
    {
      getChildren(children, node->r); 
    }    
  }
  return children->size > 0;
}

////////////////////////////////////////////////////////////////////////////////
// Request Validation
////////////////////////////////////////////////////////////////////////////////

static bool _performUpdateValidationNewPrefix(PrefixCache* self, 
                                              PC_Update* update, uint32_t as);
static bool _performUpdateValidationKnownPrefix(PrefixCache* self, 
                                                PC_Update* update, uint32_t as, 
                                                bool isNew);

/**
 * Request the validation for an update received. During the process of 
 * validating of adding the update it will be added to the cache, the validation 
 * is done by using the data within the prefix cache. Each update MUST be added
 *  only once! Once added, changes of the validation state are signaled to the 
 * update cache and with this to the registered clients.
 * 
 * @param self The prefix cache
 * @param updateID the id of the update itself
 * @param prefix The prefix of the update
 * @param as The AS number of the update
 * 
 * @return false indicates an error, most likely memory related! (fatal)
 */
bool requestUpdateValidation(PrefixCache* self, SRxUpdateID* updateID, 
                             IPPrefix* prefix, uint32_t as)
{
  // the node within the prefix tree. the data of it is the PC_prefix 
  // information.
  patricia_node_t* treeNode = NULL;
  // the prefix in patricia tree notation. It is needed to find the pc_prefix 
  prefix_t*        lookupPrefix = ipPrefixToPrefix_t(prefix);
  // This is the prefix the algorithm runs on.
  PC_Prefix*       pcPrefix = NULL;
  // The update itself
  PC_Update*       pcUpdate = malloc(sizeof(PC_Update));
  // The AS instance
  PC_AS*           pcAS = NULL;
  // The update id. I know it is so=illy but the structure might change.
  SRxUpdateID      updID = *updateID;
  
  WRITE_LOCK(&self->treeLock);
 
  pcUpdate->roa_match = 0;
  pcUpdate->updateID  = updID;
  pcUpdate->as = as;
  if (!appendDataToSList(&self->updates, pcUpdate))
  {
    RAISE_SYS_ERROR( HDR "Could not add update [0x%08X] to prefix cache!",
                     pthread_self(), updID);
    free(pcUpdate);
    free(lookupPrefix);
    UNLOCK_WRITE_LOCK(&self->treeLock);
    return false;
  }
  
  // Create or get the existing prefix node
  // Return the prefix tree element for the prefix in question. This lookup will
  // insert the requested prefix in the tree if it doesn't exist already.
  // Therefore the result value equals NULL can be interpreted as an internal
  // ERROR.
  treeNode = patricia_lookup(self->prefixTree, lookupPrefix);
  if (treeNode == NULL)
  {
    RAISE_ERROR("Failed to append a prefix to the prefix tree");
    deleteFromSList(&self->updates, pcUpdate);
    free(pcUpdate);
    free(lookupPrefix);    
    UNLOCK_WRITE_LOCK(&self->treeLock);
    return false;
  }
  else
  {
    pcUpdate->treeNode = treeNode;
  }
  
// Maybe keep the write lock!
  WRITE_TO_READ_LOCK(&self->treeLock);
  bool retVal = true;
  
  // Already existed - need to free given prefix
  if (lookupPrefix->ref_count > 0) // If the prefix would have been existed 
  {                     // already this instance would not have been referenced.
    // (Does P exist ? NO)
    retVal = _performUpdateValidationNewPrefix(self, pcUpdate, as);
    UNLOCK_READ_LOCK(&self->treeLock);
    
    // printXML(self, "requestUpdateValidation");

    return retVal;
  }
  else
  {
    // (Does P exist ? Yes)
    // The prefix already existed in the tree, free the newly created one.
    free(lookupPrefix); 
    
    pcPrefix = (PC_Prefix*)treeNode->data;
    
    if (pcPrefix->roa_coverage > 0)
    {
      // (P::ROA_Count == 0 ? No)                           //false = ! NEW P
      retVal = _performUpdateValidationKnownPrefix(self, pcUpdate, as, false);
      
      UNLOCK_READ_LOCK(&self->treeLock);
      return retVal;
    }
    else
    {
      // (P::ROA_Count == 0 ? Yes)
      if (!appendDataToSList(&pcPrefix->other, pcUpdate))
      {
        RAISE_SYS_ERROR( HDR "Could not add update [0x%08X] to P::other!", 
                         pthread_self(), updateID);
        // remove update only, other updates for this prefix do exist!
        deleteFromSList(&self->updates, pcUpdate);
        free(pcUpdate);
        UNLOCK_READ_LOCK(&self->treeLock);
        return false;
      }
      
      pcAS = getASFromPrefix(pcPrefix, as);
      if (pcAS == NULL)
      {
        // Error already generated!
        RAISE_SYS_ERROR( HDR "Remove update [0x%08X] from cache, could not add"
                             " required AS to prefix!", 
                         pthread_self(), updateID);
        deleteFromSList(&pcPrefix->other, pcUpdate);
        deleteFromSList(&self->updates, pcUpdate);
        free(pcUpdate);
        UNLOCK_READ_LOCK(&self->treeLock);
        return false;
      }
      
      pcAS->update_count++;
      
      //BUG #18 - missing notification of update cache
      notifyUpdateCacheForROAChange(self->updateCache, &pcUpdate->updateID,
                              (SRxValidationResultVal)pcPrefix->state_of_other);
      // End BUG#18
    }
    
    UNLOCK_READ_LOCK(&self->treeLock);
    
    //printXML(self, "requestUpdateValidation");
    
    return true;
  }
}

/**
 * This method prepares the prefix for the final update validation request.
 * 
 * @param self The prefix cache
 * @param pcUpdate The prefix cache update
 * @param as The origin as number of the update.
 * 
 * @return false in case of an internal error, otherwise true;
 */
static bool _performUpdateValidationNewPrefix(PrefixCache* self, 
                                              PC_Update* pcUpdate, uint32_t as)
{
  if (pcUpdate->treeNode->data != NULL)
  {
    RAISE_SYS_ERROR(HDR "First time prefix origin validation for update "
                        "[0x%08X]requested but pc prefix already exists!", 
                    pthread_self(), pcUpdate->updateID);
    return false;
  }
  PC_Prefix* pcPrefix = malloc(sizeof(PC_Prefix));
  pcPrefix->treeNode = pcUpdate->treeNode;
  pcUpdate->treeNode->data = pcPrefix;
  
  initSList(&pcPrefix->asn);
  initSList(&pcPrefix->other);
  initSList(&pcPrefix->valid);
  pcPrefix->roa_coverage = 0;
  
  PC_Prefix* parent_pcPrefix = getParent(pcUpdate->treeNode);
  if (parent_pcPrefix != NULL)
  {
    pcPrefix->state_of_other = parent_pcPrefix->state_of_other;
  }
  else
  {
    pcPrefix->state_of_other = SRx_RESULT_NOTFOUND;
  }  

  return _performUpdateValidationKnownPrefix(self, pcUpdate, as, true);
}

/*
 * This is a subroutine of performUpdateValidation used to notify the update 
 * cache of the validation result.
 * 
 * @param self Instance of the prefix cache
 * @param pcPrefix the prefix itself
 * 
 * @return false only in case of an internal error
 */
static bool _performUpdateValidation_PrefixNotCovered(PrefixCache* self,
                                                      PC_Prefix* pcPrefix,
                                                      PC_Update* pcUpdate)
{
  bool retVal = true;
  // (P::State_of_Other == UNKNOWN) => Yes
  if (pcUpdate->roa_match == 0)
  {
    // (U::ROA_Count == 0) => Yes
    if (appendDataToSList(&pcPrefix->other, pcUpdate))
    {
      notifyUpdateCacheForROAChange(self->updateCache, &pcUpdate->updateID, 
                              (SRxValidationResultVal)pcPrefix->state_of_other);
    }
    else
    {
      RAISE_SYS_ERROR( HDR "Could not add the update [0x%08X] to the list "
                           "P::other!", pthread_self(), pcUpdate->updateID);
      retVal = false;
    }
  }
  else
  {
    // (U::ROA_Count == 0) => No
    if (appendDataToSList(&pcPrefix->valid, pcUpdate))
    {
      notifyUpdateCacheForROAChange(self->updateCache, &pcUpdate->updateID, 
                                    SRx_RESULT_VALID);      
    }
    else
    {
      RAISE_SYS_ERROR( HDR "Could not add the update [0x%08X] to the list "
                           "P::valid!", pthread_self(), pcUpdate->updateID);
      retVal = false;
    }
  }      
  
  return retVal;
}

/**
 * This is a subroutine of performUpdateValidation used determine which ROAs
 * might cover the update.
 * 
 * @param pcPrefix_Po The original prefix cache prefix (Po)
 * @param pcPrefix The current prefix to be checked
 * @param pcUpdate The update to be validated
 * @param as The AS number of the update.
 * @param isNew Indicates if the prefix of this update was newly installed in 
 *              the prefix cache tree.
 * 
 * @return false in case an internal error occurred.
 */
static void _performUpdateValidation_PrefixIsCovereByAROA (
                                   PC_Prefix* pcPrefix_Po, PC_Prefix* pcPrefix,
                                   PC_Update* pcUpdate, uint32_t as, bool isNew)
{
  SListNode* asListNode;
  SListNode* roaListNode;

  PC_AS*  pcAS;
  PC_ROA* pcROA;

  FOREACH_SLIST(&pcPrefix->asn, asListNode)
  {
    pcAS = (PC_AS*)asListNode->data;
    
    // Could be added for optimization, leave it out at this point.
    // if (!isNew && pcAS->asn != as)
    // {
    //   continue;
    // }
    
    // AS number matches, does prefix also cover this one?
    FOREACH_SLIST(&pcAS->roas, roaListNode)
    {
      pcROA = (PC_ROA*)roaListNode->data;

      // Does ROA cover PO
      if (pcPrefix_Po->treeNode->prefix->bitlen <= pcROA->max_len)
      {        
        // prefix covers update
        if (isNew)
        {
          // NEW prefix, increase the Po coverage. Otherwise it is increased 
          // by ROA management itself.
          pcPrefix_Po->roa_coverage++;
        }
        if (pcAS->asn == as)
        {
          pcROA->update_count++;
          pcUpdate->roa_match += pcROA->roa_count;
        }
      }
    }
  }
}

/**
 * This is the subroutine of requestUpdateValidation that adds and validates
 * the update. 
 * 
 * @param self The instance of the prefix cache
 * @param pcUpdate The prefix cache update
 * @param as The as number of the update
 * @param isNew Indicates if the prefix was added to the prefix tree during this
 *        validation request.
 * @return false in case of an internal error.
 */
static bool _performUpdateValidationKnownPrefix(PrefixCache* self, 
                                                PC_Update* pcUpdate, 
                                                uint32_t as, bool isNew)
{
  PC_Prefix* pcPrefix = (PC_Prefix*)pcUpdate->treeNode->data;
  PC_Prefix* pcPrefix_Po = pcPrefix;
  PC_AS*     pcAS = getASFromPrefix(pcPrefix, as);
  pcAS->update_count++;
  
  // P might be covered by a ROA (we don't know if NEW prefix). 
  while (   ( isNew && (pcPrefix->state_of_other == SRx_RESULT_INVALID))
         || (!isNew && (pcPrefix->roa_coverage > 0)))
  {
    _performUpdateValidation_PrefixIsCovereByAROA(pcPrefix_Po, pcPrefix, 
                                                  pcUpdate, as, isNew);

    // (Exist less specific P' ?) => yes
    // P := P'
    pcPrefix = getParent(pcPrefix->treeNode);

    if (pcPrefix == NULL)
    {
      // (Exist less specific P' ?) => No        
      break;
    }    
  }
  return _performUpdateValidation_PrefixNotCovered(self, pcPrefix_Po, 
                                                  pcUpdate);
    
  return true;
}

////////////////////////////////////////////////////////////////////////////////
// REMOVE AN UPDATE
////////////////////////////////////////////////////////////////////////////////

/**
 * This method will remove the given update from the prefix cache.
 * 
 * NOT IMPLEMENTED PRIOR VERSION 0.3
 * 
 * @param self The prefix cache.
 * @param updateID The id of the update that has to be removed.
 * @param prefix The prefix of the update.
 * @param as The AS number of the update.
 * 
 * @return true if the update could be removed.
 */
bool removeUpdate(PrefixCache* self, SRxUpdateID* updateID, IPPrefix* prefix,
                  uint32_t as)
{
  //TODO: Implement for 0.3.x
  RAISE_ERROR("IMPLEMENTATION EXPECTED FOR VERSION 0.4.0");
  return true;
}

/**
 * Check if the given AS number belongs to the reserved numbers for 
 * documentation use.
 * 
 * @param asn the as number to be checked.
 *
 * @return true if the given as number belongs to rfc5398
 * 
 * @since 0.3.0
 */
bool belongsToRfc5398(uint32_t asn)
{
  return    ((asn >= 64496) && (asn <= 64511))  // "16-bit" number set 
         || ((asn >= 65536) && (asn <= 65551)); // "32-bit" number set
}

////////////////////////////////////////////////////////////////////////////////
// ADD A ROA WHITELIST ENTRY
////////////////////////////////////////////////////////////////////////////////

static void _addROAwl_CheckCoverage(PrefixCache* self, uint8_t prefixLen,
                                  PC_Prefix* pcPrefix, PC_Prefix* parentPrefix);
static void _addROAwl_verifyUpdates(PrefixCache* self, PC_Prefix* pcPrefix, 
                                    PC_ROA* pcROA);
static void _addROAwl_moveMatchedUpdatesToValid(UpdateCache* updateCache, 
                                               SList* validList, 
                                               SList* otherList, PC_ROA* pcROA);

/**
 * Add the given ROA white-list entry provided by the specified validation cache
 * with the given session id.
 * ROA white-list entries for ASNs specified in rfc5398 are ignored!
 * 
 * @param self The prefix cache
 * @param originAS The origin AS of the ROA whitelist entry.
 * @param prefix The prefix of the ROA whitelist entry to be added
 * @param maxLen The max length of the ROA whitelist entry
 * @param session_id The session id of the validation cache session 
 * @param valCacheID The validation cache ID
 * 
 * @return true if the ROA whitelist entry could be added - false most likely 
 *         indicates a memory problem or rfc5398
 */
bool addROAwl(PrefixCache* self, uint32_t originAS, IPPrefix* prefix, 
              uint8_t maxLen, uint32_t session_id, uint32_t valCacheID)
{
  if (belongsToRfc5398(originAS))
  {
    LOG(LEVEL_WARNING, "Ignore white-list entry for reserved ASV %u from "
            "validation cache %u!", originAS, valCacheID);
    return false;
  }
  
  // the node within the prefix tree. the data of it is the PC_prefix 
  // information.
  patricia_node_t* treeNode = NULL;
  // the prefix in patricia tree notation. It is needed to find the pc_prefix 
  prefix_t*        lookupPrefix = ipPrefixToPrefix_t(prefix);
  // This is the prefix the algorithm runs on.
  PC_Prefix*       pcPrefix = NULL;
  // The AS instance
  PC_AS*           pcAS = NULL;
  // The ROA instance
  PC_ROA*          pcROA = NULL;
  // The as list node
  SListNode*      asListNode;
  // The roa list node
  SListNode*      roaListNode;
  
  
  WRITE_LOCK(&self->treeLock);
   
  // Create or get the existing prefix node
  // Return the prefix tree element for the prefix in question. This lookup will
  // insert the requested prefix in the tree if it doesn't exist already.
  // Therefore the result value equals NULL can be interpreted as an internal
  // ERROR.
  treeNode = patricia_lookup(self->prefixTree, lookupPrefix);
  if (treeNode == NULL)
  {
    RAISE_ERROR("Failed to append a prefix to the prefix tree");
    free(lookupPrefix);    
    UNLOCK_WRITE_LOCK(&self->treeLock);
    return false;
  }
  
  // Already existed - need to free given prefix
  if (lookupPrefix->ref_count == 0) 
  { // patricia prefix already exists in tree, free unused helper
    free(lookupPrefix); // prefix already existed. This instance is not used.
  }

  if (treeNode->data == NULL)
  {
    // (Does P exist ? NO) - Created here
    pcPrefix = malloc(sizeof(PC_Prefix));
    pcPrefix->treeNode = treeNode;
    treeNode->data = pcPrefix;
    initSList(&pcPrefix->asn);
    initSList(&pcPrefix->other);
    initSList(&pcPrefix->valid);
    pcPrefix->roa_coverage = 0;

    // Exist less Specific P'
    PC_Prefix* pcParent = getParent(pcPrefix->treeNode);
    if (pcParent == NULL)
    {
      // (Exist less specific P') => No
      pcPrefix->state_of_other = SRx_RESULT_NOTFOUND;
    }
    else
    {
      // (Exist less specific P') => Yes - if other is unknown no further roas
      // do exist up the tree.
      pcPrefix->state_of_other = pcParent->state_of_other;
      if (pcPrefix->state_of_other != SRx_RESULT_NOTFOUND)
      {
        // Check Coverage
        _addROAwl_CheckCoverage(self, prefix->length, pcPrefix, pcParent);
      }
    }      
  }
  else
  {
    // free(lookupPrefix); // prefix already existed. This instance is not used.
    pcPrefix = (PC_Prefix*)treeNode->data;
  }

  if(pcPrefix!=NULL) 
  {
      // IF P CONTAINS AS
      FOREACH_SLIST(&pcPrefix->asn, asListNode)
      {
	  pcAS = (PC_AS*)asListNode->data;
	  if (pcAS->asn == originAS)
	  {      
	      break;
	  }
	  else
	  {
	      pcAS = NULL;
	  }
      }
  } else{
      RAISE_ERROR(" exist! --> patricia tree fetch error");
      RAISE_ERROR(" STOP this point -- press any key");
      getchar();
      return false;    
  }
  
  
  if (pcAS == NULL)
  {
    // (P contains AS ? => No
    pcAS = malloc(sizeof(PC_AS));
    pcAS->asn = originAS;
    pcAS->update_count = 0;
    initSList(&pcAS->roas);
    appendDataToSList(&pcPrefix->asn, pcAS);
  }
  
  FOREACH_SLIST(&pcAS->roas, roaListNode)  
  {
    pcROA = (PC_ROA*)roaListNode->data;
    if (pcROA->valCacheID == valCacheID)
    {
      if (pcROA->max_len == maxLen)
      {
        break;
      }
      else
      {
        pcROA = NULL;
      }
    }
    else
    {
      pcROA = NULL;
    }
  }
  if (pcROA == NULL)
  {
    pcROA = malloc(sizeof(PC_ROA));
    pcROA->valCacheID = valCacheID;
    pcROA->as = originAS;
    pcROA->max_len = maxLen;      
    pcROA->deferred_count = 0;
    pcROA->roa_count = 1;
    pcROA->update_count = 0;
    appendDataToSList(&pcAS->roas, pcROA);
  }
  else
  {
    pcROA->roa_count++;
  }  
  _addROAwl_verifyUpdates(self, pcPrefix, pcROA);
  UNLOCK_WRITE_LOCK(&self->treeLock);
  
  //printXML(self, "addROAwl");
  
  return true;
}

/**
 * this method moved up the prefix tree to check if a parent prefix holds a roa
 * that might cover this prefix. the walk up the tree can stop once a parent
 * is found that does not have any coverage.
 * this method does not need to check the updates. updates are checked 
 * separately. this method will only be called if a new roa adds a new prefix.
 * 
 * @param self the prefix tree itself
 * @param prefixlen    the length of the new prefix.
 * @param pcprefix     the prefix who might be covered by parent roas.
 * @param parentprefix the parent that will be examined for roas.
 */
static void _addROAwl_CheckCoverage(PrefixCache* self, uint8_t prefixLen,
                                   PC_Prefix* pcPrefix, PC_Prefix* parentPrefix)
{
  // The AS instance
  PC_AS*     pcAS = NULL;
  // The ROA instance
  PC_ROA*    pcROA = NULL;
  // The as list node
  SListNode* asListNode;
  // The roa list node
  SListNode* roaListNode;
  
  LOG(LEVEL_NOTICE,"In Check Parent Coverage!");
  
  // The while loop implements the walk up the tree.
  while (parentPrefix != NULL)
  {
    LOG(LEVEL_NOTICE,"ROA_Coverage==%u", parentPrefix->roa_coverage);
    if (parentPrefix->roa_coverage > 0)
    {
      // FOR EACH P'AS
      FOREACH_SLIST(&parentPrefix->asn, asListNode)
      {
        pcAS = (PC_AS*)asListNode->data;
        if (pcAS->roas.size > 0)
        {
          FOREACH_SLIST(&pcAS->roas, roaListNode)
          {
            pcROA = (PC_ROA*)roaListNode->data;
            if (pcROA->max_len >= prefixLen)
            {
              pcPrefix->roa_coverage += pcROA->roa_count;
            }
          }
        }
      }
      // Get the parent or NULL
      parentPrefix = getParent(parentPrefix->treeNode);
    }
    else
    {
      // Don't look for a parent anymore, the current prefix is not covered.
      parentPrefix = NULL;
    }
  }
}


/**
 * This is the subroutine for add ROA whitelist. It returns false in case 
 * something went wrong.
 * 
 * @param self Instance of the prefix cache.
 * @param pcPrefix The prefix to examine
 * @param pcROA The roa to be added.
 */
static void _addROAwl_verifyUpdates(PrefixCache* self, PC_Prefix* pcPrefix, 
                                    PC_ROA* pcROA)
{
  // nodes in valid list
  SListNode* validListNode = NULL;
  // The pc Update
  PC_Update* pcUpdate = NULL;
  // Indicates if children have to be checked as well.
  bool checkChildren = false;
  
  // Does R cover P?
  if (pcPrefix->treeNode->prefix->bitlen <= pcROA->max_len)
  {
    // (Does R cover P ? ) => Yes
    pcPrefix->roa_coverage++;
    
    // For each matched Update
    FOREACH_SLIST (&pcPrefix->valid, validListNode)
    {
      pcUpdate = (PC_Update*)validListNode->data;
      if (pcUpdate->as == pcROA->as)
      {
        pcUpdate->roa_match++;
        pcROA->update_count++;
      }
    }
    
    // Move all matches from Other to Valid.
    _addROAwl_moveMatchedUpdatesToValid(self->updateCache, &pcPrefix->valid,
                                        &pcPrefix->other, pcROA);
    
    // For Each Update in Other
    if (pcPrefix->state_of_other == SRx_RESULT_NOTFOUND)
    {
      _ROAwl_changeStateOfOther(self->updateCache, pcPrefix, 
                                SRx_RESULT_INVALID);
    }
    
    checkChildren = true;
  }
  else
  {
    // (Does R cover P ? ) => No
    if (pcPrefix->state_of_other == SRx_RESULT_NOTFOUND)
    {
      _ROAwl_changeStateOfOther(self->updateCache, pcPrefix, 
                                SRx_RESULT_INVALID);
      
      checkChildren = true;
    }
  }
  
  if (checkChildren)
  {
    SList childrenList;
    SListNode* childrenListNode = NULL;
    initSList(&childrenList);
    
    if (getChildren(&childrenList, pcPrefix->treeNode))
    {
      FOREACH_SLIST(&childrenList, childrenListNode)
      {
        pcPrefix = (PC_Prefix*)childrenListNode->data;
        _addROAwl_verifyUpdates(self, pcPrefix, pcROA);
      }
      releaseSList(&childrenList);    
    }
  }
}

/**
 * Change the P::State_of_Other to the given new state and notify all updates 
 * stored in the "other" list.
 * 
 * @param updateCache The update cache
 * @param pcPrefix The prefix whose updates have to be changed.
 * @param newState The new validation state.
 */
static void _ROAwl_changeStateOfOther(UpdateCache* updateCache, 
                                      PC_Prefix* pcPrefix, 
                                      SRxValidationResultVal newState)
{
  PC_Update* pcUpdate;
  SListNode* otherListNode;
  
  // P::State_of_Other == UNKNOWN ? Yes
  pcPrefix->state_of_other = newState;
  FOREACH_SLIST(&pcPrefix->other, otherListNode)
  {
    pcUpdate = (PC_Update*)otherListNode->data;
    notifyUpdateCacheForROAChange(updateCache, &pcUpdate->updateID, newState);
  }  
}

/**
 * Moves the list nodes from otherList to validList.
 * 
 * @param updateCache The cache containing the updates that are affected. 
 * @param validList the list of valid updates.
 * @param otherList the list of not valid updates.
 * @param pcROA the ROA that is used to match updates.
 */
static void _addROAwl_moveMatchedUpdatesToValid(UpdateCache* updateCache, 
                                                SList* validList, 
                                                SList* otherList, PC_ROA* pcROA)
{
  SListNode* nodeToMove = NULL;
  SListNode* currNode = otherList->root;
  SListNode* prevNode = NULL;
  PC_Update* pcUpdate;
  
  // For each matched Update Do:
  while (currNode != NULL)
  {
    pcUpdate = (PC_Update*)currNode->data;
    if (pcUpdate->as == pcROA->as)
    {
      nodeToMove = currNode;
      pcUpdate->roa_match++;
      pcROA->update_count++;
      notifyUpdateCacheForROAChange(updateCache, &pcUpdate->updateID, 
                                    SRx_RESULT_VALID);
    }
    else
    {
      prevNode = currNode;
    }
    
    // Advance in list to not loose the next pointer
    currNode = currNode->next;
    
    if (nodeToMove != NULL)
    {
      // Remove Node from Other
      otherList->size--;
      if (prevNode == NULL)
      {
        // Node was the List Head
        otherList->root = nodeToMove->next;
      }
      else
      {        
        prevNode->next = nodeToMove->next;
      }
      
      if (nodeToMove->next == NULL)
      {
        // Node was last node
        otherList->last = prevNode;
      }
      
      // Now add it into valid list
      validList->size++;
      nodeToMove->next = NULL;
      if (validList->root == NULL)
      {
        validList->root  = nodeToMove;
      }
      else
      {
        validList->last->next = nodeToMove;
      }
      validList->last = nodeToMove;
      nodeToMove = NULL;
    }
  }  
}

////////////////////////////////////////////////////////////////////////////////
// REMOVE A ROA WHITELIST ENTRY
////////////////////////////////////////////////////////////////////////////////

static void _delROAwl_validateUpdates(PrefixCache* self, PC_Prefix* pcPrefix, 
                      PC_ROA* pcROA, SRxValidationResultVal parentStateOfOther);

static void _delROAwl_moveToOther(UpdateCache* updateCache, PC_Prefix* pcPrefix, 
                                  PC_ROA* pcROA);

/**
 * Delete the given ROA white-list entry provided by the specified validation 
 * cache with the given session id.
 * 
 * @param self The prefix cache
 * @param originAS The origin AS of the ROA whitelist entry.
 * @param prefix The prefix of the ROA whitelist entry to be added
 * @param maxLen The max length of the ROA whitelist entry
 * @param session_id The session id of the validation cache session 
 * @param valCacheID The validation cache ID
 * 
 * @return true if the ROA whitelist entry could be removed. False indicates the
 *         entry was not found at all.
 */
bool delROAwl(PrefixCache* self, uint32_t originAS, IPPrefix* prefix, 
              uint8_t maxLen, uint32_t session_id, uint32_t valCacheID)
{
  // the node within the prefix tree. the data of it is the PC_prefix 
  // information.
  patricia_node_t* treeNode = NULL;
  // the prefix in patricia tree notation. It is needed to find the pc_prefix 
  prefix_t*        lookupPrefix = ipPrefixToPrefix_t(prefix);
  // This is the prefix the algorithm runs on.
  PC_Prefix*       pcPrefix = NULL;
  // The AS instance
  PC_AS*           pcAS = NULL;
  // The ROA instance
  PC_ROA*          pcROA = NULL;
  // The AS list node  
  SListNode*       asListNode = NULL;
  // The ROA list node  
  SListNode*       roaListNode = NULL;
  
  
  WRITE_LOCK(&self->treeLock);
   
  // Create or get the existing prefix node
  // Return the prefix tree element for the prefix in question. This lookup will
  // insert the requested prefix in the tree if it doesn't exist already.
  // Therefore the result value equals NULL can be interpreted as an internal
  // ERROR.
  treeNode = patricia_lookup(self->prefixTree, lookupPrefix);
  if (treeNode == NULL)
  {
    RAISE_ERROR("Failed to access the prefix tree");
    free(lookupPrefix);    
    UNLOCK_WRITE_LOCK(&self->treeLock);
    return false;
  }
  
  // Already existed - need to free given prefix
  if (lookupPrefix->ref_count == 0)
  {
    free(lookupPrefix); // prefix already existed. This instance is not used.
  }
 
  if (treeNode->data == NULL)
  {
    if (belongsToRfc5398(originAS))
    {
      // These were not added to start with so 
      LOG(LEVEL_NOTICE, "Received white-list entry withdrawal for reserved AS"
              "number %u from validation cache %u - As expected entry not "
              "found!", originAS, valCacheID);
      return false;
    }
    else
    {
      // (Does P exist ? NO) - Created here
      RAISE_ERROR("Received a ROA white-list withdrawal for an entry that does "
                  "not exist!");
    }
    UNLOCK_WRITE_LOCK(&self->treeLock);
    return false;
  }
  else
  {
  //  free(lookupPrefix); // prefix already existed. This instance is not used.
    pcPrefix = (PC_Prefix*)treeNode->data;
  }

  if(pcPrefix!=NULL) 
  {
    // find the ROA to be deleted
    FOREACH_SLIST(&pcPrefix->asn, asListNode)
    {
      pcAS = (PC_AS*)asListNode->data;
      if (pcAS->asn == originAS)
      {
        break;
      }
      else
      {
        pcAS = NULL;
      }
    }
  }
  else
  {
    RAISE_ERROR("Received a ROA white-list withdrawal for an entry that does "
                "not exist! --> patricia tree fetch error");
    UNLOCK_WRITE_LOCK(&self->treeLock);
    RAISE_ERROR(" STOP this point -- press any key");
    getchar();
    return false;    
  }
  
  if (pcAS == NULL)
  {
    RAISE_ERROR("Received a ROA white-list withdrawal for an entry that does "
                "not exist!");
    UNLOCK_WRITE_LOCK(&self->treeLock);
    return false;    
  }
  
  FOREACH_SLIST(&pcAS->roas, roaListNode)
  {
    pcROA = (PC_ROA*)roaListNode->data;
      if (pcROA->valCacheID == valCacheID)
    {
      if (pcROA->max_len == maxLen)
      {
        // FOUND!!!!
        break;
      }
      else
      {
        pcROA = NULL;        
      }
    }
    else
    {
      pcROA = NULL;
    }
  }
  
  if (pcROA == NULL)
  {
    RAISE_ERROR("Received a ROA white-list withdrawal for an entry that does "
                "not exist!");
    UNLOCK_WRITE_LOCK(&self->treeLock);
    return false;    
  } 
  
  // Does less specific P' exist?
  PC_Prefix* pcParentPrefix = getParent(treeNode);
  if (pcParentPrefix != NULL)
  {
    // (Exist less specific P') ?  => Yes
    _delROAwl_validateUpdates(self, pcPrefix, pcROA, 
                              pcParentPrefix->state_of_other);    
  }
  else
  {
    // (Exist less specific P') ?  => No
    _delROAwl_validateUpdates(self, pcPrefix, pcROA, SRx_RESULT_NOTFOUND);
  }
  
  pcROA->roa_count--;
  if (pcROA->roa_count < 0)
  {
    RAISE_SYS_ERROR("BUG in code, ROA Count should not go below 0!");
  }
  
  if (pcROA->roa_count == 0)
  {
    LOG(LEVEL_DEBUG, HDR "Remove ROA entry!", pthread_self());
    deleteFromSList(&pcAS->roas, pcROA);
    free(pcROA);
    
    if (pcAS->roas.size == 0)
    {      
      if (pcAS->update_count == 0)
      {
        LOG(LEVEL_DEBUG, HDR "Remove AS from prefix!", pthread_self());
        deleteFromSList(&pcPrefix->asn, pcAS);
        free(pcAS);
        
        if (pcPrefix->asn.size == 0)
        {
          free(pcPrefix);
          treeNode->data = NULL;
        }
      }
    }
  }
  UNLOCK_WRITE_LOCK(&self->treeLock);
  
  //printXML(self, "delROAwl");
  
  return true;
}

/**
 * This method implements the subroutine Re-validate Updates.
 * 
 * @param self The prefix cache
 * @param pcPrefix The prefix itself
 * @param pcROA The ROA
 * @param parentStateOfOther the Other state of the parent.
 */
static void _delROAwl_validateUpdates(PrefixCache* self, PC_Prefix* pcPrefix, 
                     PC_ROA* pcROA, SRxValidationResultVal parentStateOfOther)
{
  bool checkForChildren = false;
  
  if (pcPrefix->treeNode->prefix->bitlen <= pcROA->max_len)
  {
    // (Does R cover P) ? => Yes
    pcPrefix->roa_coverage--;
    if (pcPrefix->roa_coverage < 0)
    {
      RAISE_SYS_ERROR("BUG: ROA Count MUST NOT go below 0!");      
    }
    
    if (parentStateOfOther == SRx_RESULT_NOTFOUND)
    {
      if (pcPrefix->roa_coverage == 0)
      {
        _ROAwl_changeStateOfOther(self->updateCache, pcPrefix, 
                                  SRx_RESULT_NOTFOUND);        
      }
    }
    _delROAwl_moveToOther(self->updateCache, pcPrefix, pcROA);
    checkForChildren = true;
  }
  else
  {
    // (Does R cover P) ? => No
    if (pcPrefix->roa_coverage == 0)
    {
      if (parentStateOfOther == SRx_RESULT_NOTFOUND)
      {
        _ROAwl_changeStateOfOther(self->updateCache, pcPrefix, 
                                  SRx_RESULT_NOTFOUND);
        checkForChildren = true;        
      }
    }
  }
  
  if (checkForChildren)
  {
    SList childrenList;
    SListNode* childrenListNode = NULL;
    PC_Prefix* childPrefix = NULL;
    initSList(&childrenList);
    
    if (getChildren(&childrenList, pcPrefix->treeNode))
    {
      FOREACH_SLIST(&childrenList, childrenListNode)
      {
        childPrefix = (PC_Prefix*)childrenListNode->data;
        _delROAwl_validateUpdates(self, childPrefix, pcROA, 
                                  pcPrefix->state_of_other);
      }
      releaseSList(&childrenList);
    }
  }
}

/**
 * Move all possible matches from valid into other
 * @param updateCache The update cache to be informed in case an update changes
 *                    validation state.
 * @param pcPrefix The prefix under investigation 
 * @param pcROA the ROA that is removed
 */
static void _delROAwl_moveToOther(UpdateCache* updateCache, PC_Prefix* pcPrefix, 
                                  PC_ROA* pcROA)
{
  SListNode* nodeToMove = NULL;
  SListNode* currNode = pcPrefix->valid.root;
  SListNode* prevNode = NULL;
  PC_Update* pcUpdate;
  
  // For each matched Update Do:
  while ((currNode != NULL) && (pcROA->update_count > 0))
  {
    pcUpdate = (PC_Update*)currNode->data;
    if (pcUpdate->as == pcROA->as)
    {
      pcUpdate->roa_match--;
      if (pcROA->roa_count == 1)
      { // because this is the last ROA to delete, remove update count.
        pcROA->update_count--;
      }
      if (pcUpdate->roa_match < 0)
      {
        RAISE_SYS_ERROR("BUG: ROA Count in update MUST NOT go below 0!");
      }
      if (pcROA->roa_count < 0)
      {
        RAISE_SYS_ERROR("BUG: ROA Count in ROA MUST NOT go below 0!");
      }
      
      if (pcUpdate->roa_match == 0)
      {
        nodeToMove = currNode;        
        notifyUpdateCacheForROAChange(updateCache, &pcUpdate->updateID,       
                                      pcPrefix->state_of_other);
      }
    }
    else
    {
      prevNode = currNode;
    }

    currNode = currNode->next;

    if (nodeToMove != NULL)
    {
      // Remove Node from Valid
      pcPrefix->valid.size--;
      if (prevNode == NULL)
      {
        // Node was the List Head
        pcPrefix->valid.root = nodeToMove->next;
      }
      else
      {        
        prevNode->next = nodeToMove->next;
      }
      
      if (nodeToMove->next == NULL)
      {
        // Node was last node
        pcPrefix->valid.last = prevNode;
      }
      
      // Now add it into other list
      pcPrefix->other.size++;
      nodeToMove->next = NULL;
      if (pcPrefix->other.root == NULL)
      {
        pcPrefix->other.root  = nodeToMove;
      }
      else
      {
        pcPrefix->other.last->next = nodeToMove;
      }
      pcPrefix->other.last  = nodeToMove;
      nodeToMove = NULL;
    }
  }
}

/**
 * Remove all ROA whitelist entries from the given validation cache with the 
 * given session id value. Used for giving up a cache, executing a cache reset
 * or session id change.
 * 
 * NOT IMPLEMENTED PRIOR VERSION 0.3
 * 
 * @param self The prefix cache instance
 * @param session_id the session_id of this session
 * @param valCacheID the validation cache ID
 * @param deferredOnly clean only the deferred ROA's
 * 
 * @return the number of ROA whitelist entries to be removed.
 */
int cleanAllROAwl(PrefixCache* self, uint32_t session_id, uint32_t valCacheID,
                  bool deferredOnly)
{
  RAISE_ERROR("NOT IMPLEMENTED PRIOR VERSION 0.3");
  // Go top down and remove all existing ROA.s
  return true;
}

/**
 * Flag all ROA whitelist entries of the given validation cache with the given 
 * session id value. This is used in case a session id value switch occurred and
 * the state of ROA white-list entries gets rebuild.
 *
 * NOT IMPLEMENTED PRIOR VERSION 0.4
 * 
 * @param self The validation cache
 * @param sessionID the session id whose values have to be flagged.
 * @param valCacheID The validation cache ID.
 * 
 * @return The number of ROA white-list entries to be flagged.
 */
int flagAllROAwl(PrefixCache* self, uint32_t sessionID, uint32_t valCacheID)
{
  RAISE_ERROR("NOT IMPLEMENTED PRIOR VERSION 0.4");
  // Flag it by setting the defferedCount to ROA-count.
  return true;
}

////////////////////////////////////////////////////////////////////////////////
// OTHER HELPER FUNCTIONS
////////////////////////////////////////////////////////////////////////////////


/** 
 * Creates a prefix_t out of an IPPrefix.
 * 
 * @note The returned pointer needs to be freed (\c ref_count = 0) unless it 
 *       is passed to \c  patricia_lookup
 */
static prefix_t* ipPrefixToPrefix_t(IPPrefix* from)
{
  prefix_t* to = (prefix_t*)malloc(sizeof(prefix_t));
  if (to == NULL)
  {
    return NULL;
  }

  to->bitlen    = from->length;
  to->ref_count = 0; // Will be 'Ref'ed by lookup

  if (from->ip.version == 4)
  {
    to->family         = AF_INET;
    to->add.sin.s_addr = from->ip.addr.v4.u32;
  } 
  else
  {
    to->family = AF_INET6;

    memcpy(&to->add.sin6, &from->ip.addr.v6.in_addr, sizeof(IPv6Address));
  }

  return to;
}

/**
 * Returns a textual representation of a given patricia tree prefix.
 * @param prefix The patricia tree prefix.
 * 
 * @return The text (human readable) version of the prefix.
 *
 * @note Local, static buffer - i.e. not thread-safe!
 */
const char* ipOfPrefix_tToStr(prefix_t* prefix)
{
  #define BUF_SIZE  MAX_IP_V6_STR_LEN
  static const char buf[BUF_SIZE];

  return (prefix->family == AF_INET) 
      ? ipV4AddressToStr((IPv4Address*)&prefix->add.sin, (char*)buf, BUF_SIZE)
      : ipV6AddressToStr((IPv6Address*)&prefix->add.sin6, (char*)buf, BUF_SIZE);
}

////////////////////////////////////////////////////////////////////////////////
// Just some function for debugging. Subject to be deleted!
////////////////////////////////////////////////////////////////////////////////
//TODO: Add documentation
static void printPrefix(char* msg, prefix_t* prefix, uint32_t oas)
{
  if (oas == 0x0)
  {
    printf("%s%s/%i\n", (msg == NULL ? "Prefix: " : msg),
                        ipOfPrefix_tToStr(prefix),
                        prefix->bitlen);
  }
  else
  {
    printf("%s%s/%i, %i\n", (msg == NULL ? "Prefix: " : msg),
                        ipOfPrefix_tToStr(prefix),
                        prefix->bitlen, oas);
  }
}

static void printXML(PrefixCache* self, char* methodName)
{
  printf ("%s---------------------------------\n", methodName);
  outputPrefixCacheAsXML(self, stdout);
  printf ("end--------------------------------\n");
}

//TODO: Documentation
/**
 * Outputs a prefix.
 *
 * @note Recursive!
 */
static void outputPrefix(XMLOut* out, patricia_node_t* treeNode)
{
  PC_Prefix*  pcPrefix = NULL;
  PC_Update*  pcUpdate = NULL;
  PC_AS*      pcAS     = NULL;
  PC_ROA*     pcROA    = NULL;
  SListNode*  asListNode    = NULL;
  SListNode*  roaListNode   = NULL;
  SListNode*  otherListNode = NULL;
  SListNode*  validListNode = NULL;

  openTag(out, "prefix");
  if (treeNode->data == NULL)
  {
    addBoolAttrib(out, "internal-trie-node", true);
  } 
  else
  {
    pcPrefix = (PC_Prefix*)treeNode->data;
    addStrAttrib(out, "ip", ipOfPrefix_tToStr(treeNode->prefix));
    addIntAttrib(out, "length", treeNode->prefix->bitlen);
    addIntAttrib(out, "roa-coverage", pcPrefix->roa_coverage);
    addIntAttrib(out, "no-valid-updates", pcPrefix->valid.size);
    addIntAttrib(out, "no-other-updates", pcPrefix->other.size);
    addStrAttrib(out, "state-of-other", 
                 pcPrefix->state_of_other == SRx_RESULT_NOTFOUND ? "NOTFOUND"
                                                                 : "INVALID");

    FOREACH_SLIST(&pcPrefix->asn, asListNode)
    {
      pcAS = (PC_AS*)asListNode->data;
      openTag(out, "as");
      addU32Attrib(out, "as-number", pcAS->asn);
      addU32Attrib(out, "update-count", pcAS->update_count);
      FOREACH_SLIST(&pcAS->roas, roaListNode)
      {
        pcROA = (PC_ROA*)roaListNode->data;
        openTag(out, "roa");        
        addU32Attrib(out, "valCacheID",   pcROA->valCacheID);
        addU32Attrib(out, "as",           pcROA->as);
        addU32Attrib(out, "max-length",   pcROA->max_len);
        addU32Attrib(out, "roa-count",    pcROA->roa_count);
        addU32Attrib(out, "deferred-count",    pcROA->deferred_count);
        addU32Attrib(out, "update-count", pcROA->update_count);          
        closeTag(out); // roa
      }        
      closeTag(out); // as
    }
    openTag(out, "valid");
    addU32Attrib(out, "no-updates", pcPrefix->valid.size);
    FOREACH_SLIST(&pcPrefix->valid, validListNode)
    {
      pcUpdate = (PC_Update*)validListNode->data;
      openTag(out, "update");
      addH32Attrib(out, "update-id", pcUpdate->updateID);
      addU32Attrib(out, "as",        pcUpdate->as);
      addU32Attrib(out, "roa-match", pcUpdate->roa_match);
      closeTag(out); // update
    }
    closeTag(out); // valid

    openTag(out, "other");
    addU32Attrib(out, "no-updates", pcPrefix->other.size);
    addStrAttrib(out, "state", 
                 pcPrefix->state_of_other == SRx_RESULT_NOTFOUND ? "NOTFOUND"
                                                                 : "INVALID");
    FOREACH_SLIST(&pcPrefix->other, otherListNode)
    {
      pcUpdate = (PC_Update*)otherListNode->data;
      openTag(out, "update");
      addH32Attrib(out, "update-id", pcUpdate->updateID);
      addU32Attrib(out, "origin-as", pcUpdate->as);
      addU32Attrib(out, "roa-match", pcUpdate->roa_match);
      closeTag(out); // update
    }
    closeTag(out); // other
  }
  
  // Children
  SList childrenList;
  SListNode* childrenListNode = NULL;
  
  initSList(&childrenList);
  getChildren(&childrenList, treeNode);
  
  FOREACH_SLIST(&childrenList, childrenListNode)
  {
    pcPrefix = (PC_Prefix*)childrenListNode->data;   
    outputPrefix(out, pcPrefix->treeNode);    
  }
  releaseSList(&childrenList);
  
  closeTag(out); // prefix
}

/**
 * Print the content of the prefix cache to the given file.
 * 
 * @param self the prefix cache
 * @param stream The file to be written into.
 */
void outputPrefixCacheAsXML(PrefixCache* self, FILE* stream)
{
  XMLOut      out;
  SListNode*  updateListNode;
  PC_Update*  pcUpdate;

  initXMLOut(&out, stream);
  openTag(&out, "prefix-cache");

  // Tree
  if (self->prefixTree->head != NULL)
  {
    outputPrefix(&out, self->prefixTree->head);
  }

  // Updates
  if (sizeOfSList(&self->updates))
  {
    openTag(&out, "updates");
    FOREACH_SLIST(&self->updates, updateListNode)
    {
      pcUpdate = (PC_Update*)getDataOfSListNode(updateListNode);
      openTag(&out, "update");
        addH32Attrib(&out, "update-id", pcUpdate->updateID);
        addU32Attrib(&out, "origin-as", pcUpdate->as);
        addAttrib(&out, "prefix", "%s/%hhu",
                  ipOfPrefix_tToStr(pcUpdate->treeNode->prefix), 
                  pcUpdate->treeNode->prefix->bitlen);
        addU32Attrib(&out, "roa-count", pcUpdate->roa_match);
        if (pcUpdate->roa_match > 0)
        {
          addStrAttrib(&out, "val-state", "VALID");          
        }
        else
        {
          if (((PC_Prefix*)pcUpdate->treeNode->data)->state_of_other 
              == SRx_RESULT_NOTFOUND)
          {
            addStrAttrib(&out, "val-state", "NOTFOUND");          
          }
          else
          {
            addStrAttrib(&out, "val-state", "INVALID");                      
          }            
        }
      closeTag(&out);
    }
    closeTag(&out);
  }

  closeTag(&out);
  releaseXMLOut(&out);
}

/*-----------------------
 * Miscellanous functions
 */

/**
 * Notifies the Update Cache about a change of ROA prefix/origin validation.
 * This is done by storing the new result in the update cache. It is
 * expected that the update exists within the update cache, otherwise an error
 * log will be generated.
 *
 * @param updCache Update Cache instance, not NULL
 * @param updateID IF of the update whose validation state changed.
 * @param newROAResult The new validation state.
 */
static void notifyUpdateCacheForROAChange(UpdateCache* updCache, 
                     SRxUpdateID* updateID, SRxValidationResultVal newROAResult)
{  
  if (updCache != NULL)
  {
    SRxResult srxRes;
    srxRes.roaResult    = newROAResult;
    srxRes.bgpsecResult = SRx_RESULT_DONOTUSE; // Indicates this 
                                      // parameter must not be used    
    
    LOG(LEVEL_DEBUG, HDR "Store new ROA result[0x%02X] for update [0x%08X]",
                     pthread_self(), newROAResult, *updateID);
    if (!modifyUpdateResult(updCache, updateID, &srxRes))
    {
      RAISE_SYS_ERROR("A validation result for a non existing update [0x%08X]!",
                      *updateID);      
    }
  }
  else
  {
    RAISE_SYS_ERROR("The provided UpdateCache is NULL!");
  }
}

