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
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 * 0.1.0    - 2010/04/08
 *            * File created
 */
#include "server/key_cache.h"
#include "util/log.h"

bool createKeyCache(KeyCache* self, UpdateCache* updateCache,
                    KeyInvalidated invCallback, KeyNotFound nfCallback) {
  if (updateCache == NULL) {
    RAISE_ERROR("The given Update Cache instance is NULL");
    return false;
  }

  self->invCallback = invCallback;
  self->notFoundCallback = nfCallback;

  return true;
}

void releaseKeyCache(KeyCache* self) {
}

bool getPublicKey(KeyCache* self, SRxKeyID keyId) {
  if (self->notFoundCallback != NULL) {
    self->notFoundCallback(keyId);
  }
  return false;
}

bool storePublicKey(KeyCache* self, SRxKeyID keyId) {
  return true;
}

bool deletePublicKey(KeyCache* self, SRxKeyID keyId) {
  return true;
}

bool addUpdateToKey(KeyCache* self, SRxKeyID keyId, SRxUpdateID updId) {
  return true;
}

