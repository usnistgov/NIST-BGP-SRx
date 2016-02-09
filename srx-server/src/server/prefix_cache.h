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
 * Prefix Cache.
 *
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 *            * Moved outputPrefixCacheAsXML from c file to header.
 * 0.3.0    - 2013/01/28 - oborchert
 *            * Update to be compliant to draft-ietf-sidr-rpki-rtr.26. This 
 *              update does not include the secure protocol section. The
 *              protocol will still use un-encrypted plain TCP
 * 0.2.0    - 2011/01/07 - oborchert 
 *            * Changelog added with version 0.2.0 and date 2011/01/07
 *            * Version tag added
 *            * Changed return value of function getOriginStatus from bool to
 *              uint8 to reflect the validation result. This method provides
 *              more than valid/invalid.
 *            * Added unknownLock to PrefixCache  
 * 0.1.0    - 2010/04/08 - pgleichm
 *            * Code Created
 * -----------------------------------------------------------------------------
 *
 */

#ifndef __PREFIX_CACHE_H__
#define __PREFIX_CACHE_H__

#include <stdio.h>

#define HAVE_IPV6
#include <patricia.h>
 
#include "server/update_cache.h"
#include "shared/srx_defs.h"
#include "util/mutex.h"
#include "util/prefix.h"
#include "util/rwlock.h"
#include "util/slist.h"



/**
 * A single Prefix Cache.
 */
typedef struct {
  UpdateCache*      updateCache;
  patricia_tree_t*  prefixTree;
  // This list is not really needed!
  SList             updates;
 
  // Access control variables
  Mutex             updatesMutex;
  RWLock            treeLock;
  RWLock            otherLock;
  RWLock            validLock;
  RWLock            asLock;
} PrefixCache;

/**
 * Update with reference counter.
 */
typedef struct {
  /** The id of the update in the update cache. */
  SRxUpdateID      updateID;
  /** The origin AS */
  uint32_t         as;
  /** The patricia tree node this update is assigned to. */
  patricia_node_t* treeNode;
  /** Number of ROAs that cover this update. If the value == 0 the update MUST
   * be located in the 'other' list, otherwise the update must be located in the
   * valid list. */
  uint16_t         roa_match;
} PC_Update;

typedef struct {
  /** Contains the tree node. */
  patricia_node_t* treeNode;
  /** Number of ROAs covering this prefix (attached and through max-length.  */
  uint32_t roa_coverage;
  /** The validation state of updates in the 'other' list. 
   * Acceptable values are SRx_RESULT_UNKNOWN and SRx_RESULT_INVALID */
  SRxValidationResultVal  state_of_other;
  
  /** Contains all updates considered valid. */
  SList    valid;
  /** Contains all updates considered valid. */
  SList    other;
  /** Contains all ASN's attached to this prefix either through ROA.s or 
   * updates or both. Each AS (PC_AS) is listed only once. */
  SList    asn;
} PC_Prefix;

/**
 * The Origin AS associated with the update.
 */
typedef struct {
  /** The AS number*/
  uint32_t asn;
  /** the list of ROAs attached to this AS*/
  SList    roas;  
  // OR 
  // PC_ROA[] roas; // the length of the array is (32-length) + 1
  
  /** The number of updates announced by to this as. (only for the prefix this 
   * instance is attached to/ */
  uint32_t update_count;
} PC_AS;

typedef struct {
  /** The AS number of this roa. */
  uint32_t as;
  /** the max length of the ROA. The prefix of the ROA can be determined though
   * the prefix the ROA is attached to.*/
  uint8_t  max_len;
  /** The number of identical ROAs that are represented by this instance.*/
  uint16_t roa_count;
  /** The number of identical ROAS that are represented by this instance
   * prior a change of cache session id or cache reset. This allows to keep the 
   * cache as is until the validation cache is newly synchronized. After 
   * synchronization is done the ROA-count needs to be removed by the number
   * of deferred_count. This counter indicates a re-synchronization if it is 
   * other than zero "0"*/
  uint16_t deferred_count;
  /** The id of the validation cache that maintains this ROA-white-list entry.*/
  uint32_t valCacheID;
  /** The number of updates covered by this ROA. */
  uint32_t update_count;
} PC_ROA;

/**
 * Initializes an empty cache and creates a link to an existing Update Cache.
 *
 * @param self the Instance of prefix cache that should be initialized.
 * @param updateCache Instance of the Update Cache that should be notified
 * 
 * @return true if the initialization was successful, otherwise false.
 */
bool initializePrefixCache(PrefixCache* self, UpdateCache* updCache);

/**
 * Frees all allocated resources. the prefix cache itself must be freed outside.
 */
void releasePrefixCache(PrefixCache* self);

/**
 * Request the validation for an update received. The result will be stored in 
 * the update cache's update by calling its notification method.
 * 
 * @param self The prefix cache
 * @param updateID the id of the update itself
 * @param prefix The prefix of the update
 * @param as The AS number of the update
 * 
 * @return true if the validation request could be performed.
 */
bool requestUpdateValidation(PrefixCache* self, SRxUpdateID* updateID, 
                             IPPrefix* prefix, uint32_t as);

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
                  uint32_t as);

/**
 * Add the given ROA white-list entry provided by the specified validation cache
 * with the given session id.
 * ROA white-list entries for ASNs specified in rfc5398 are ignored!
 * 
 * @param self The prefix cache
 * @param originAS The origin AS of the ROA white-list entry.
 * @param prefix The prefix of the ROA white-list entry to be added
 * @param maxLen The max length of the ROA white-list entry
 * @param session_id The session_id of the validation cache session 
 * @param valCacheID The validation cache ID
 * 
 * @return true if the ROA white-list entry could be added - false most likely 
 *         indicates a memory problem.
 */
bool addROAwl(PrefixCache* self, uint32_t originAS, IPPrefix* prefix, 
              uint8_t maxLen, uint32_t session_id, uint32_t valCacheID);

/**
 * Add the given ROA white-list entry provided by the specified validation cache
 * with the given session id.
 * ROA white-list entries for ASNs specified in rfc5398 are ignored!
 * 
 * @param self The prefix cache
 * @param originAS The origin AS of the ROA white-list entry.
 * @param prefix The prefix of the ROA white-list entry to be added
 * @param maxLen The max length of the ROA white-list entry
 * @param session_id The session id of the validation cache session 
 * @param valCacheID The validation cache ID
 * 
 * @return true if the ROA white-list entry could be removed. False indicates the
 *         entry was not found at all.
 */
bool delROAwl(PrefixCache* self, uint32_t originAS, IPPrefix* prefix, 
              uint8_t maxLen, uint32_t session_id, uint32_t valCacheID);

/**
 * Remove all ROA whitelist entries from the given validation cache with the 
 * given session id value. Used for giving up a cache, executing a cache reset
 * or session id change.
 * 
 * NOT IMPLEMENTED PRIOR VERSION 0.4
 * 
 * @param self The prefix cache instance
 * @param session_id the session id of this session
 * @param valCacheID the validation cache ID
 * @param deferredOnly clean only the deferred ROA's
 * 
 * @return the number of ROA white-list entries to be removed.
 */
int cleanAllROAwl(PrefixCache* self, uint32_t session_id, uint32_t valCacheID,
                  bool deferredOnly);

/**
 * Flag all ROA white-list entries of the given validation cache with the given 
 * session id value. This is used in case a session id value switch occurred and
 * the state of ROA white-list entries gets rebuild.
 *
 * NOT IMPLEMENTED PRIOR VERSION 0.4.0
 * 
 * @param self The validation cache
 * @param sessionID the session id whose values have to be flagged.
 * @param valCacheID The validation cache ID.
 * 
 * @return The number of ROA white-list entries to be flagged.
 */
int flagAllROAwl(PrefixCache* self, uint32_t sessionID, uint32_t valCacheID);


/**
 * Empty the complete update cache. This method empties the prefix tree and the 
 * all Updates.
 * 
 * @param self The update cache to be emptied!
 */
void emptyCache(PrefixCache* self);

////////////////////////////////////////////////////////////////////////////////
// Made the internal only methods available to allow access of console.
////////////////////////////////////////////////////////////////////////////////

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
PC_Prefix* getParent(patricia_node_t* node);

/**
 * Returns a textual representation of a given patricia tree prefix.
 * @param prefix The patricia tree prefix.
 * 
 * @return The text (human readable) version of the prefix.
 *
 * @note Local, static buffer - i.e. not thread-safe!
 */
const char* ipOfPrefix_tToStr(prefix_t* prefix);

/**
 * Convert the cache into an XML stream
 * 
 * @param self The prefix cache itself
 * @param stream The stream to write it into.
 */
void outputPrefixCacheAsXML(PrefixCache* self, FILE* stream);




















// @TODO: Remove code below or activate it. 



/**
 * Maintains the status of a (prefix, origin) pair, along with
 * “max prefix length”. This could be storing new p/o pairs, updating or
 * removing the status of existing ones.
 * The Update Cache (update_cache.h) is informed if a status change happened.
 *
 * @param self Instance
 * @param valCacheID The unique identifier of the validation cache this entry
 *                   was received from.
 * @param session_id The cache session id of this entry.
 * @param add \c true = add, \c false = remove
 * @param prefix IP prefix
 * @param maxLen Max. prefix length
 * @param oas Origin AS
 * @param flags Arbitrary flags
 * @return \c true = stored, \c false = an internal error occurred
 */
//bool maintainOriginStatus(PrefixCache* self, uint32_t valCacheID,
//                          uint16_t session_id, bool add,
//                          IPPrefix* prefix, uint8_t maxLen, uint32_t oas,
//                          uint8_t flags);

/**
 * Retrieves the status of a (prefix, origin) pair and logs the passed update 
 * identifier.
 * has been announced.
 * In case, the prefix does not exist, then the method looks up the status of
 * the parent – i.e. less specific – prefix.
 *
 * @param self Instance of the prefix cache
 * @param prefix IP prefix the IP prefix requested
 * @param oas Origin AS of the update
 * @param updateID Update identifier that will be recorded
 * @param details More detailed information regarding the status
 * @return SRx_RESULT_VALID, SRx_RESULT_UNKNOWN, SRx_RESULT_INVALID
 */
//SRxValidationResultVal getOriginStatus(PrefixCache* self, IPPrefix* prefix, 
//                                       uint32_t oas, SRxUpdateID* updateID, 
//                                       OriginStatusDetails* details);

/**
 * Removes all statuses.
 *
 * @param self Instance
 */
//void resetAllOriginStatuses(PrefixCache* self);

/**
 * Outputs the cache as an XML tree.
 *
 * @param self Instance
 * @param stream Output stream
 */
//void outputPrefixCacheAsXML(PrefixCache* self, FILE* stream);

/**
 * Returns the number an update is referenced internally.
 *
 * @note Only for testing/development purposes!
 * @note Not thread-safe!
 *
 * @param self Instance
 * @param updateID Update identifier
 * 
 * @return Number of references, or \c -1 if an unknown update
 */
//int getUpdateRefCount(PrefixCache* self, SRxUpdateID* updateID);

#endif // !__PREFIX_CACHE_H__
