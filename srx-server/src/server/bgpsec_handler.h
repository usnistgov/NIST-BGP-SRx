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
 * @version 0.5.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.5.0.0  - 2017/07/07 - oborchert
 *            * Moved validation into this handler (renamed validateSignature 
 *              into validateUpdate)
 *          - 2017/07/05 - oborchert
 *            * Updated cache creation function - removed unused parameters
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Added Changelog
 *            * Fixed speller in documentation header
 * 0.1.0.0  - 2010/08/04 - pgleichm
 *            * File created.
 */

#ifndef __BGPSEC_HANDLER_H__
#define __BGPSEC_HANDLER_H__

#include <srx/srxcryptoapi.h>
#include "server/key_cache.h"
#include "server/update_cache.h"
#include "shared/srx_defs.h"

/**
 * A single BGPSec Handler.
 */
typedef struct {
  KeyCache* keyCache;
  SRxCryptoAPI* srxCAPI;
} BGPSecHandler;

/**
 * Initializes the handler and registers an existing Key Cache.
 *
 * @param self Variable that should be initialized
 * @param keyCache Existing Key Cache
 * @return \c true = successful, \c false = an error occurred
 */
bool createBGPSecHandler(BGPSecHandler* self, KeyCache* keyCache);

/**
 * Frees all allocated resources.
 *
 * @param self Instance
 */
void releaseBGPSecHandler(BGPSecHandler* self);

/**
 * Loads a private key.
 * At least one call is necessary before createSignature can be used.
 *
 * @todo Adjust parameter if necessary
 *
 * @param self Instance
 * @param filename Filename of the private key
 * @return \c true = key loaded, \c false = invalid key, or file does not exist
 */
bool loadPrivateKey(BGPSecHandler* self, const char* filename);

/**
 * Validates the given bgpsec update data.
 *
 * The return value is SRx_RES_VALID or SRx_RES_INVALID
 *
 * @param self The BGPsec Handler itself
 * @param update the given update to be validated
 * 
 * @return SRx_RES_VALID or SRx_RES_INVALID
 */
uint8_t validateSignature(BGPSecHandler* self, UC_UpdateData* update);

/**
 * Creates a signature for a given Byte-stream.
 *
 * @todo Adjust parameters (e.g. AS to identify the private key, etc.)
 *
 * @param self Instance
 * @return \c true = signatures created, \c false = unknown key/internal error
 */
bool createSignature(BGPSecHandler* self);

#endif // !__BGPSEC_HANDLER_H__

