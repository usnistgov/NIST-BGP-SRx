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
 * The update cache holds the updates in two separate structures, one is the 
 * update cache, a hash table with the update id as key and the update as 
 * value. The other is a list, that allows to scan through all updates. Both 
 * MUST be maintained the same.
 * 
 * @version 0.4.0.0
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.4.0.0  - 2016/06/19 - oborchert
 *            * added function storeCacheEntryBlob
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 * 0.3.0    - 2013/02/15 - oborchert
 *            * Added outputUpdateCacheAsXML to the header.
 *          - 2013/01/01 - oborchert
 *            * Added declaration of modifyUpdateResult into header file.
 *          - 2012/12/17 - oborchert
 *            * Changed the logic of function getUpdateResult's signature. Both, 
 *              result and default value are out parameters now. 
 *            * Changed signature of function storeUpdate.   
 * 0.2.0    - 2011/11/01 - oborchert
 *            * mostly rewritten
 * 0.1.0    - 2010/04/15 - pgleichm
 *          * Code created.
 */

#ifndef __UPDATE_CACHE_H__
#define __UPDATE_CACHE_H__

#include <stdio.h>
#include "server/configuration.h"
#include "shared/srx_defs.h"
#include "shared/srx_packets.h"
#include "util/mutex.h"
#include "util/rwlock.h"
#include "util/slist.h"

/**
 * Function that is called in case a result changed.
 *
 * @param updateId Affected update
 * @param newRes New result
 */
typedef void (*UpdateResultChanged)(SRxValidationResult* result);

/**
 * A single Update Cache.
 */
typedef struct {  
  Configuration*      sysConfig;  // The system configuration
  UpdateResultChanged resChangedCallback;
  Mutex               itemMutex;
  // TODO Check if allItems can be removed!
  SList               allItems;   // All updates in an SList.
  void*               availItems; // pointer to the next available cEntry
  int                 itemsUsed;  // number of cEntries used
  RWLock              tableLock;
  void*               table;      // The hash table for quick lookup
  // The is also the maximum number of clients currently installed. It is
  // called minNumberOfclients because it is the minimum expected and therefore
  // the initial number of array elements needed per update. This number might
  // grow over time and will be always maintained and reflects at least the 
  // maximum number of clients used, sometimes a bit more.
  uint8_t             minNumberOfClients;
  // determines if a particular client is locked. A client is locked if the 
  // cache works on cleaning updates from this client. During this phase no 
  // updates can be assigned to this client.
  uint32_t*           lockedClients;
} UpdateCache;

/** Return value for method getUpdateSignature the memory of this instance
 * is managed by the update cache.
 */
typedef struct {
  bool     containsError;
  uint16_t errorCode;
  uint32_t signatureLength;
  void*    signatureBlock;
} UpdSigResult;

/**
 * The sole purpose of this typedef is to allow gathering some statistical 
 * information for the server console. It is NOT used within the update cache.
 * The memory MUST be managed by the caller.
 */
typedef struct {
  SRxUpdateID*     updateID;
  uint32_t         asn;
  uint32_t         roa_count;
  SRxDefaultResult defResult;
  SRxResult        result;
  IPPrefix         prefix;
  UpdSigResult     bgpsecResult;
} UC_UpdateStatistics;

#define DEFAULT_NUMBER_CLIENTS 2; 

/**
 * Initialized the update cache. The memory for the cache MUST be allocated
 * by the caller of this method.
 * 
 * @param self The update cache
 * @param chCallback The callback method called for changes within the cache
 * @param minNumberOfUpdates the minimum number of expected clients. Must be
 *                           greater then 0;
 * 
 * @return true = successfully initialized, false = an error occurred
 */
bool createUpdateCache(UpdateCache* self, UpdateResultChanged chCallback, 
                       uint8_t minNumberOfUpdates, Configuration* sysConfig);

/**
 * Frees all allocated resources.
 *
 * @param self Instance that should be released
 */
void releaseUpdateCache(UpdateCache* self);

/**
 * Queries the update cache for the result associated with the update. This
 * method DOES NOT create a cache entry if no update was found. This method DOES
 * NOT change the update cache in any means.
 *
 * @param self The instance of the update cache
 * @param updId The update ID whose result is queried
 * @param clientID The id of the client that requests the update result.
 *                 in case the ID is greater than zero "> 0" the client will be
 *                 registered with the update, Otherwise it will not be 
 *                 registered.
 * @param client   The proxy client. MUST be NULL if clientID == 0.
 * @param srxRes The current result associated with the update This is an OUT
 *               parameter.
 * @param defResult The default result provided by proxy during verification
 *                  call. This is an OUT parameter.
 *
 * @return true if the update was found, false if not.
 */
bool getUpdateResult(UpdateCache* self, SRxUpdateID* updateID, 
                     uint8_t clientID, void* clientMapping,
                     SRxResult* srxRes, SRxDefaultResult* defaultRes);

/**
 * This function returns the update signature if already existent. It will NOT
 * start the signing. If no signature exists the return value is NULL
 *
 * @param self The instance of the update cache
 * @param result The result of the function call.
 * @param updateID The id of the update
 * @param prependCount the prepend count of the host AS
 * @param peerAS The peer AS
 * @param algorithm The algorithm used
 * @param complete Indicates if the complete signature block or just the
 *                 new addition will be returned.
 * @return The signature block.
 */
UpdSigResult* getUpdateSignature(UpdateCache* self, UpdSigResult* result,
                                 SRxUpdateID* updateID, uint32_t prependCount, 
                                 uint32_t peerAS, uint16_t algorithm,
                                 bool complete);

/**
 * This method is not for usage within the update cache management. It is 
 * mainly to allow the server console to query for update information.
 * 
 * @param self The update cache 
 * @param statistics The statistics information to be filles. The value 
 *                   updateID MUST be set and will be used to locate the update.
 * 
 * @return true if the update was found, otherwise false
 */
bool getUpdateData(UpdateCache* self, UC_UpdateStatistics* statistics);

/**
 * Stores an update in the update cache. This method returns 0 in case the 
 * update already exists in the update cache. In this case depending on the 
 * operational flow the stored update should be re-queried. This might happen
 * if two clients request the same update information at the exact same time 
 * and both will receive information that the update is not stored yet. In this
 * case both might attempt to store the update. Here it is important to notice 
 * that the default value might differ. The caller where the result is 0 should
 * re-query the result to assure the returned validation result is same.
 * In case the result value is 1 the provided update was stored successfully.
 * for internal errors the result value is -1. For the update result the value
 * SRX_RESULT_UNDEFINED is used to indicate that the validation was not 
 * performed yet. As long as the value is UNDEFINED the command handler accepts
 * a validation request for this particular update. Once the value is other than
 * "UNDEFINED" a validation attempt will be stopped. From this moment the RPKI-
 * Handler and BGPSEC-handler are the only two instances that can start a new
 * validation.
 * 
 *
 * @param self The instance of the update cache.
 * @param clientID The ID of the srx-server client. This is NOT the proxyID,
 *                 it is a one byte client ID that is mapped to the proxyID.
 * @param clientMapping The mapping entry for the client.
 * @param updateID The ID of the Update.
 * @param prefix The prefix of the update.
 * @param asn    The AS number of the update.
 * @param defRes The default result info. This will only be taken when stored
 *               the very first time. In case the value is NULL for a first time
 *               storage, the internal UNDEFINED and UNKNOWN will be used.
 * @param bgpSec Contains BGPSEC data. This parameter as well as defRes is only
 *               used during initial storing of an update. The value can be 
 *               NULL.
 * 
 *
 * @return 1 the result stored, 0 the update is already stored, 
 *         -1 indicates an internal error
 */
int storeUpdate(UpdateCache* self, uint8_t clientID, void* clientMapping,
                SRxUpdateID* updateID, IPPrefix* prefix, 
                uint32_t asn, SRxDefaultResult* defRes,
                BGPSecData* bgpSec);

/**
 * Removes the update data from the list and releases all memory associated to 
 * it.
 *
 * @param self The instance of the update cache 
 * @param clientID The ID of the srx-server client. This is NOT the proxyID,
 *                 it is a one byte client ID that is mapped to the proxyID.
 *                 If this id is zero all mappings and the update itself will be 
 *                 removed!
 * @param updateID The ID of the update that has to be removed.
 * @param keepTime A proposed time in seconds the update should still be kept 
 *                 before final deletion. The cache might remove the update at 
 *                 any time though.
 * 
 * @return true If the update / association could be removed, false if the 
 *              update was not either found in the cache or no association to 
 *              the client was found.
 */
bool deleteUpdateFromCache(UpdateCache* self, uint8_t clientID, 
                           SRxUpdateID* updateID, uint16_t keepTime);

/**
 * Empties a cache and releases all memory attached to each of the elements.
 *
 * @note Primarily for development purposes or program shutdown.
 *
 * @param self Instance of the update cache.
 */
void emptyUpdateCache(UpdateCache* self);

/**
 * This method is used to configure the update cache in such that the minimum 
 * number of clients expected per update can be configured. the value MUST not 
 * be zero, zero values are reset to be one.
 * 
 * @param self the UpdateCache instance.
 * @param noClients The minimum number of clients expected per update.
 * 
 * @since 0.3.0
 */
void setMinClients(UpdateCache* self, uint8_t noClients);

/**
 * Fill the given array "clientIDs" with the number clientID's associated to the
 * update with the "updateID". This method will NOT initialize the given array 
 * with zero's but will fill the array without "holes". The return value is the
 * number of clientIDs filles in the array or -1 if the array is to small!
 * 
 * @param self The updateCache.
 * @param updateID pointer to the update ID.
 * @param clientIDs an initialized array of uint8_t elements.
 * @param size Size of the provided array in bytes.
 * 
 * @return the number of arrays filled in the array, -1 if the array is to 
 *         small.
 * 
 * @since 0.3.0
 */
int getClientIDsOfUpdate(UpdateCache* self, SRxUpdateID* updateID, 
                         uint8_t* clientIDs, uint8_t size);

/**
 * Stores a result for in the update cache for later retrieval.
 * If this overwrites an existing update result, then the registered 
 * UpdateResultChanged callback is called. The update MUST exist! Only result
 * values other than SRx_RESULT_DONOTUSE are used. This allows to change only 
 * one value, not necessary both.
 *
 * @param self The instance of the update cache.
 * @param updateID The ID of the Update.
 * @param result the result the current update has to be updated with. In case
 *               the result differs from the stored update result, a 
 *               notification will be send to the client. to indicate which 
 *               result MUST NOT be modified use SRx_RESULT_DONOTUSE.
 *
 * @return true the result stored, false indicates an internal error such as the
 *              update does not exist.
 */
bool modifyUpdateResult(UpdateCache* self, SRxUpdateID* updateID, 
                        SRxResult* result);

/**
 * Removed the association of the client to all updates within the cache.
 * 
 * @param self The update cache
 * @param clientID The client ID
 * @param clientMapping must be NULL for clientID == 0, otherwise not.
 * @param keepTime the keep time.
 * 
 * @return the number of update associations removed, -1 if an error occured.
 * 
 * @since 0.3.0
 */
int unregisterClientID(UpdateCache* self, uint8_t clientID, void* clientMapping,
                       uint32_t keepTime);

/**
 * This method determines if an update with the given ID already exist. If so,
 * a collision is detected. A collision is detected if an update with the same
 * updateID already exist but the data is different.
 * 
 * @param self The Update cache
 * @param updateID Update ID to be checked!
 * @param prefix the prefix of the update
 * @param asn the Origin AS of the update
 * @param bgpsecData The bgpsec data blob.
 * 
 * @return true if a collision could be detected!
 */
bool detectCollision(UpdateCache* self, SRxUpdateID* updateID, IPPrefix* prefix, 
                     uint32_t asn, BGPSecData* bgpsecData);

/**
 * This function selects the data from bgpsecData that is used for ID generation
 * - see srx_identifier::generateIdentifier and stores it in the cache entry.
 * It is important that both data blobs are same otherwise problems with the
 * ID finding are given.
 * This method copies the data from bgpsecData into the cache entry. Therefore
 * the memory allocated in bgpsecData can safely be deallocated.
 * 
 * @param cEntry The cache entry where the blob data will be stored in.
 * @param bgpsecData The bgpsec (and bgp4) data that has to be stored.
 * 
 * @return false if the cache entry already contains data,otherwise true.
 * 
 * @since 0.4.0.0 
 * 
 * @see srx_identifier.h::generateIdentifier
 */
//bool storeCacheEntryBlob(CacheEntry* cEntry, BGPSecData* bgpsecData);

/**
 * Print the content of the update cache to the given file.
 * 
 * @param self the update cache
 * @param stream The file to be written into.
 * @param maxBlob The maximum number of blob bytes printed. (-1 all, 0 none, 
 *                >0 the specified number or the blob length if less.)
 * 
 * @since 0.3.0
 * 
 */
void outputUpdateCacheAsXML(UpdateCache* self, FILE* stream, int maxBlob);
#endif // !__UPDATE_CACHE_H__
