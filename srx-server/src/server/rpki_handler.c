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
 * This handler processes ROA validation
 *
 * @version 0.3.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 *   0.3.0 - 2013/01/28 - oborchert
 *           * Update to be compliant to draft-ietf-sidr-rpki-rtr.26. This 
 *             update does not include the secure protocol section. The protocol
 *             will still use un-encrypted plain TCP
 *   0.2.0 - 2011/01/07 - oborchert
 *           * Changelog added with version 0.2.0 and date 2011/01/07
 *           * Version tag added
 *           * Applied changed return value of getOriginStatus (prefix_cache.h)
 *             to method validatePrefixOrigin
 *   0.1.0 - 2010/04/15 - pgleichm
 *           * Code Created
 * -----------------------------------------------------------------------------
 */

#include "server/rpki_handler.h"
#include "util/log.h"

///////////////////
// Constants
///////////////////

/** Time in seconds between reconnect attempts */
#define RECONNECT_DELAY 30
/** Flags stored in the Prefix Cache */
#define DEFAULT_FLAGS   0x0
/** Keep the connection upon an error */
#define KEEP_CONNECTION true

#define HDR "([0x%08X] RPKI Handler): "

////////////////////////////////////////////////////////////////////////////////
// forward declaration
////////////////////////////////////////////////////////////////////////////////

static void handlePrefix (uint32_t valCacheID, uint16_t session_id,
                          bool isAnn, IPPrefix* prefix, uint16_t maxLen,
                          uint32_t oas, void* rpkiHandler);
static void handleReset (uint32_t valCacheID, void* rpkiHandler);
static bool handleError (uint16_t errNo, const char* msg, void* rpkiHandler);
static int handleConnection (void* user);




/**
 * Configure the RPKI Handler and create an RPKIRouter client.
 *
 * @param handler The RPKIHandler instance.
 * @param prefixCache The instance of the prefix cache
 * @param serverHost The RPKI/Router server (RPKI Validation Cache)
 * @param serverPort The port of the server to be connected to.
 * @return
 */
bool createRPKIHandler (RPKIHandler* handler, PrefixCache* prefixCache,
                        const char* serverHost, int serverPort)
{
  // Attach the prefix cache
  handler->prefixCache = prefixCache;

  // Create the RPKI/Router protocol client instance
  handler->rrclParams.prefixCallback     = handlePrefix;
  handler->rrclParams.resetCallback      = handleReset;
  handler->rrclParams.errorCallback      = handleError;
  handler->rrclParams.connectionCallback = handleConnection;

  handler->rrclParams.serverHost         = serverHost;
  handler->rrclParams.serverPort         = serverPort;

  if (!createRPKIRouterClient(&handler->rrclInstance, &handler->rrclParams,
                               handler))
  {
    return false;
  }

  return true;
}

/**
 * Release the given Handler.
 *
 * @param handler The hamndler to be released.
 */
void releaseRPKIHandler(RPKIHandler* handler)
{
  if (handler != NULL)
  {
    releaseRPKIRouterClient(&handler->rrclInstance);
  }
}

////////////////////////////////////////////////////////////////////////////////
// RPKI/Router client callback
////////////////////////////////////////////////////////////////////////////////

/** This method handles prefix announcements and withdrawals received by the
 * RPKI cache via the RPKI/Router Protocol. They are also called whitelist
 * entries. This prefixes will be stored or removed from the prefix cache
 * depending on the value of isAnn.
 *
 * @param valCacheID The id of the validation cache.
 * @param session_id the id of the session id value. (NETWORK ORDER)
 * @param isAnn indicates if this is an announcement or withdrawal.
 * @param prefix The prefix itself
 * @param maxLen The maximum length for this prefix
 * @param oas The origin AS
 * @param user the RPKI handler of the prefix that points to the prefix cache.
 *
 */
static void handlePrefix (uint32_t valCacheID, uint16_t session_id,
                          bool isAnn, IPPrefix* prefix, uint16_t maxLen,
                          uint32_t oas, void* rpkiHandler)
{
  char prefixBuf[MAX_PREFIX_STR_LEN_V6];
  
  LOG(LEVEL_DEBUG, HDR "ROA-wl: %s [originAS: %u, prefix: %s, max-len: %u, "
                   "valCacheID: 0x%08X, session_id: 0x%04X)", pthread_self(),
      (isAnn ? "Ann" : "Wd"), oas, 
      ipPrefixToStr(prefix, prefixBuf, MAX_PREFIX_STR_LEN_V6), maxLen, 
      valCacheID, session_id);

  // This method takes care of the received white list prefix/origin entry.
  RPKIHandler* hanlder = (RPKIHandler*)rpkiHandler;
  if (isAnn)
  {    
    addROAwl(hanlder->prefixCache, oas, prefix, maxLen, session_id, valCacheID);
  }
  else
  {
    delROAwl(hanlder->prefixCache, oas, prefix, maxLen, session_id, valCacheID);
  }
}

/**
 * Handle the reset for the prefix cache.
 *
 * @param valCacheID The ID of the validation cache.
 * @param rpkiHandler The RPKIHandler that contains the cache to be reseted.
 */
static void handleReset (uint32_t valCacheID, void* rpkiHandler)
{
  LOG(LEVEL_DEBUG, HDR "Prefix: Reset", pthread_self());
  RPKIHandler* handler = (RPKIHandler*)rpkiHandler;
  RAISE_ERROR("Handle Reset not implemented yet! - doDo: remove or flag all "
              "ROAS from the given validation Cache");
  handler = NULL; // just to supress the compiler warning. Must be removed later
  // @TODO: Remove or flag all ROAS from the given validation Cache
}

/**
 * Handle the error.
 *
 * @param errNo The error number specified in the error package
 * @param msg The text message contained in the error package
 * @param user The Handler that received the error message (RPKI).
 * @return
 */
static bool handleError (uint16_t errNo, const char* msg, void* user)
{
  RAISE_ERROR("RPKI/Router error (%hu): \'%s\'", errNo, msg);
  return KEEP_CONNECTION;
}

/**
 * Called when the connection is lost. It returns the delay for the next
 * connection attempt.
 *
 * @param user The handler of the connection.
 * @return
 */
static int handleConnection (void* user)
{
  LOG(LEVEL_INFO, "Connection to RPKI/Router protocol server lost "
                  "- reconnecting after %dsec", RECONNECT_DELAY);
  return RECONNECT_DELAY;
}

