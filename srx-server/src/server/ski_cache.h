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
 * @version 0.1.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.5.0.0 - 2017/06/30 - oborchert
 *           * added count_updates to SKI_CACHE_INFO
 *           * modified the function ski_clean and removed ski_gc - clean does
 *             garbage collection if used with SKI_CLEAN_NONE
 *         - 2017/06/29 - oborchert
 *           * added count_keys to SKI_CACHE_INFO
 *         - 2017/06/26 - oborchert 
 *           * added ski_printCache
 *         - 2017/06/23 - oborchert
 *           * modified the return values of the functions.
 *           * reorganized the struct types
 *           * added garbage collector ski_gc()
 *           * fixed wrong type in ski_unregisterUpdate
 *         - 2017/06/19 - oborchert
 *           * modified function header for registering key ski's 
 *         - 2017/06/14 - oborchert
 *           * File created
 */
#ifndef SKI_CACHE_H
#define SKI_CACHE_H

#include <srx/srxcryptoapi.h>
#include "shared/srx_defs.h"
#include "rpki_queue.h"

/** This enumeration is used to hint of a BGPSEC path validation is needed or 
 * not needed. If the registration determines that a validation will result in
 * invalid due to missing keys, the return valid is REGVAL_INVALID.*/
typedef enum {
  /** An ERROR during registration */
  REGVAL_ERROR=0,
  /** Due to missing keys a BGPSEC path validation will return INVALID*/
  REGVAL_INVALID=1,
  /** All keys are available, BGPSEC path validation can not be determined here.
   * A complete BGPsec path validation needs to be performed. */
  REGVAL_UNKNOWN=2,
} e_Upd_RegRes;

/** This enumeration allows to specify what kind of SKI change was performed. */
typedef enum {
  /** The SKI was newly added to the system */
  SKI_NEW=0,
  /** The SKI counter was increased. */
  SKI_ADD=1,
  /** The SKI counter was decreased but is above 0. */
  SKI_DEL=2,
  /** The SKI was removed (counter == 0) */
  SKI_REMOVED=3
} e_SKI_status;

/** This enumeration is used to specify the kind of cache cleaning that has to 
 * be performed. */
typedef enum {
  /** Special case, used for garbage collection. */
  SKI_CLEAN_NONE=0,
  /** Indicates to remove all key registrations. */
  SKI_CLEAN_KEYS=1,
  /** Indicates to remove all key registrations. */
  SKI_CLEAN_UPDATES=2,          
  /** Indicate to clean the complete cache */
  SKI_CLEAN_ALL=3  
} e_SKI_clean;

/** This struct allows to get some statistics information about the internal 
 * SKI Cache. */
typedef struct {
  /** Number of CACHE Nodes, each CACHE Node represents the upper two bytes of
   * an ASN */
  u_int32_t count_cNode;
  /** Number of 2 byte AS numbers. */
  u_int32_t count_AS2;
  /** Number of Algorithm ID nodes, Min 1 per ASN*/
  u_int32_t count_cAlgoID;
  /** Number of SKI data leafs (same as counter of SKIs) */
  u_int32_t count_cData;
  /** Number of update IDs stored. (Not Unique)*/
  u_int32_t count_cUID;
  /** Number of keys registered (sum of cNode->counter). */
  u_int32_t count_keys;
  /** Numbers of updates registered (count of cUID->counter.)*/
  u_int32_t count_updates;
} SKI_CACHE_INFO;

/** The SKI_CACHE type */
typedef void SKI_CACHE;

/**
 * Create and initialize as SKI cache. The SKI Cache uses the RPKI queue to 
 * signal changes in the ski cache. Wither the queue or a queue manager will 
 * notify the consumer of these changes.
 * 
 * @param rpki_queue The RPKI queue where changes for updates are queued in
 * 
 * @return Pointer to the SKI cache or NULL if an error occurred.
 */
SKI_CACHE* ski_createCache(RPKI_QUEUE* rpki_queue);

/**
 * Frees all allocated resources.
 *
 * @param cache The SKI cache that needs to be removed.
 * 
 * @return false if an error occurred, otherwise true
 */
bool ski_releaseCache(SKI_CACHE* cache);

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

bool ski_clean(SKI_CACHE* cache, e_SKI_clean type);

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
                                SCA_BGP_PathAttribute* bgpsec);

/**
 * Remove the update id from the SKI cache.
 * 
 * @param cache The SKI cache
 * @param updateID The update ID to be unregistered
 * @param bgpsec The BGPsec_PATH attribute.
 * 
 * @return false if an error occurred, otherwise true
 */
bool ski_unregisterUpdate(SKI_CACHE* cache, SRxUpdateID* updateID,
                          SCA_BGP_PathAttribute* bgpsec);

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
                     u_int8_t* ski, u_int8_t algoID);

/** 
 * Remove the key counter from the <SKI, algo-id> tuple. This might trigger 
 * notifications for possible kick-starting of update validation.
 * 
 * @param cache The SKI cache.
 * @param asn The ASN the key is assigned to in host format.
 * @param ski The 20 byte SKI of the key
 * @param algoID The algorithm ID of the key
 * 
 * @return false if an error occurred, otherwise true
 */
bool ski_unregisterKey(SKI_CACHE* cache, u_int32_t asn, 
                       u_int8_t* ski, u_int8_t algoID);

/**
 * Examine given SKI Cache. This function also allows to print the cache in 
 * XML format if verbose is enabled..
 * 
 * @param cache The cache to be examined
 * @param info The cache info object.
 * @param verbose Do an XML print of the cache while examining it.
 */
void ski_examineCache(SKI_CACHE * cache, SKI_CACHE_INFO* info, bool verbose);

#endif /* SKI_CACHE_H */
