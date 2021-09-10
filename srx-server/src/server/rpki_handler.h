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
 * @version 0.5.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.5.0.0  - 2017/07/09 - oborchert
 *            * Removed define PUB_KEY_OCTET and replaced it with define 
 *              ECDSA_PUB_KEY_DER_LENGTH from srxcryptoapi.h
 *          - 2017/06/29 - oborchert
 *            * Removed define SKI_OCTED and replace with define SKI_LENGTH from 
 *              srxcryptoapi.h to prevent future issues
 *          - 2017/06/16 - kyehwanl
 *            * Added SCA
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 *            * Removed warning for comments within a comment
 * 0.1.0    - 2010/04/12 - pgleichm
 *            * Code Created
 */

#ifndef __RPKI_HANDLER_H__
#define __RPKI_HANDLER_H__

#include <pthread.h>
#include <srx/srxcryptoapi.h>
#include "server/prefix_cache.h"
#include "server/rpki_router_client.h"
#include "server/aspath_cache.h"
#include "util/prefix.h"
#include "server/aspa_trie.h"

/**
 * A single RPKI/Router Handler.
 */
typedef struct {
  PrefixCache*            prefixCache;
  RPKIRouterClientParams  rrclParams;
  RPKIRouterClient        rrclInstance;
  ASPA_DBManager*         aspaDBManager;
  AspathCache*            aspathCache;
} RPKIHandler;

/**
 * Initializes the instance, registers an existing Prefix Cache and creates
 * a RPKI/Router Client instance.
 *
 * @param self Variable that should be initialized
 * @param prefixCache Existing cache that should be registered
 * @param serverHost RPKI/Router protocol server host name
 * @param serverPort RPKI/Router protocol server port number
 * @return \c true = all went through, \c false = an error occurred
 */
bool createRPKIHandler(RPKIHandler* self, PrefixCache* prefixCache,
                       AspathCache* aspathCache, ASPA_DBManager* aspaDBManager,
                       const char* serverHost, int serverPort, int version);

/**
 * Frees all resources.
 * Also releases the RPKI/Router instance.
 *
 * @param self Handler instance
 */
void releaseRPKIHandler(RPKIHandler* self);

#endif // !__RPKI_HANDLER_H__

