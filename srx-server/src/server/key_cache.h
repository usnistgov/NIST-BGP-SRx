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
 *
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Added Changelog
 *            * Fixed speller in documentation header
 * 0.1.0    - 2010/04/08
 *            * File created
 */

#ifndef __KEY_CACHE_H__
#define __KEY_CACHE_H__

#include "server/update_cache.h"
#include "shared/srx_defs.h"

/**
 * Function that is called when a key was removed or replaced.
 *
 * @param keyId Affected key
 */
typedef void (*KeyInvalidated)(SRxKeyID keyId);

/**
 * Function that is called when a key could not be found.
 * 
 * @param keyId Key
 */
typedef void (*KeyNotFound)(SRxKeyID keyId);

/** 
 * A single Key Cache instance.
 */
typedef struct {
  UpdateCache*    updateCache;
  KeyInvalidated  invCallback;
  KeyNotFound     notFoundCallback;
} KeyCache;

/**
 * Initializes an empty cache and creates a link to an existing Update Cache. 
 *
 * @param self Variable that should be initialized
 * @param updateCache Update Cache that this Key Cache should be linked to
 * @param invCallback A key became invalid
 * @param nfCallback A key couldn't be found
 * @return \c true = initalization was successful, \c false = an error occurred
 */
bool createKeyCache(KeyCache* self, UpdateCache* updateCache,
                    KeyInvalidated invCallback, KeyNotFound nfCallback);

/**
 * Frees all allocated resources.
 *
 * @param self Instance that should be released
 */
void releaseKeyCache(KeyCache* self);

/**
 * Returns a stored public key, or an error if they key could not be found. 
 * In case of an error, the KeyNotFound callback is invoke.
 *
 * @todo Adjust according to specification
 *
 * @param self Instance
 * @param keyId Key to look-up
 * @return \c true = key was found, \c false = key not found
 */
bool getPublicKey(KeyCache* self, SRxKeyID keyId);

/**
 * Stores a key. 
 * If the key already existed, the KeyInvalidated callback is called, and the
 * Update Cache (update_cache.h) will be informed.
 
 * @param self Instance
 * @param keyId Identifier of the passed key
 * @return \c true = key stored, \c false = failed to store
 *
 * @todo Adjust according to specification
 */
bool storePublicKey(KeyCache* self, SRxKeyID keyId);

/**
 * Removes a key. 
 * KeyInvalidated is invoked, and the Update Cache (update_cache.h) is 
 * informed.
 *
 * @param self Instance
 * @param keyId Key that should be removed
 * @return \c true = key was removed, \c false = unknown key
 */
bool deletePublicKey(KeyCache* self, SRxKeyID keyId);

/**
 * Records that a key has been used to sign a certain update.
 *
 * @param self Instance
 * @param keyId Key with which to register the update
 * @param updId Update that should be registered with the key
 * @return \c true = registered with the given key, \c false = unknown key
 */
bool addUpdateToKey(KeyCache* self, SRxKeyID keyId, SRxUpdateID updId);

#endif // !__KEY_CACHE_H__

