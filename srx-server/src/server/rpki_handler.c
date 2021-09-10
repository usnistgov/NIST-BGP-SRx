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
 * @version 0.6.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.6.0.0  - 2021/03/30 - oborchert
 *            * Added missing version control. Also moved modifications labeled 
 *              as version 0.5.2.0 to 0.6.0.0 (0.5.2.0 was skipped)
 *          - 2021/02/26 - kyehwanl
 *            * Removed handleASPAObject and replaced the function with 
 *              function handleAspaPdu.
 *            * Added aspaCache and aspaDBManager to handler creation.
 *            * Modified handleEndOfData by adding ADPA data and adding an 
 *              additional ASPA process for END of DATA.
 *          - 2021/02/16 - oborchert
 *            * Added skeleton function handleASPAObject() for APSA processing. 
 * 0.5.1.0  - 2018/03/09 - oborchert 
 *            * BZ1263: Merged branch 0.5.0.x (version 0.5.0.4) into trunk 
 *              of 0.5.1.0.
 *          - 2017/10/13 - oborchert
 *            * BZ1238: Used valCacheID Id as key source during key 
 *              registration.
 *  0.5.0.3 - 2018/02/26 - oborchert
 *            * fixed incorrect import.
 *  0.5.0.0 - 2017/07/08 - oborchert
 *            * Added final steps to fully integrate BGPsec path validation. 
 *          - 2017/07/06 - oborchert
 *            * Fixed speller in variable name. 
 *          - 2017/06/29 - oborchert
 *            * Removed define SKI_OCTED and replace with SKI_LENGTH from
 *              srxcryptoapi.h to prevent future issues
 *            * Modified handleRouterKey to determine the algorithm ID depending
 *              on the provided key.
 *            * Added getAlgorithID()
 *            * Added SKI cache registration.
 *          - 2017/06/21 - oborchert
 *            * Added include for main.h to resolve compiler warnings.
 *          - 2017/06/16 - kyehwanl
 *            * Added handling of router keys
 *  0.3.0.0 - 2013/01/28 - oborchert
 *            * Update to be compliant to draft-ietf-sidr-rpki-rtr.26. This
 *              update does not include the secure protocol section. The protocol
 *              will still use un-encrypted plain TCP
 *  0.2.0.0 - 2011/01/07 - oborchert
 *            * Changelog added with version 0.2.0 and date 2011/01/07
 *            * Version tag added
 *            * Applied changed return value of getOriginStatus (prefix_cache.h)
 *              to method validatePrefixOrigin
 *  0.1.0.0 - 2010/04/15 - pgleichm
 *            * Code Created
 * -----------------------------------------------------------------------------
 */

#include <srx/srxcryptoapi.h>
#include "server/main.h"
#include "server/rpki_handler.h"
#include "server/ski_cache.h"
#include "server/update_cache.h"
#include "server/bgpsec_handler.h"
#include "util/log.h"
#include "server/aspa_trie.h"

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
static void handleRouterKey (uint32_t valCacheID, uint16_t session_id,
                             bool isAnn, uint32_t asn, const char* ski,
                             const char* keyInfo, void* rpkiHandler);
static void handleEndOfData (uint32_t valCacheID, uint16_t session_id,
                             void* rpkiHandler);
int handleAspaPdu(void* rpkiHandler, uint32_t customerAsn, 
                    uint16_t providerAsCount, uint32_t* providerAsns, 
                    uint8_t addrFamilyType, uint8_t announce);

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
                        AspathCache* aspathCache, ASPA_DBManager* aspaDBManager,
                       const char* serverHost, int serverPort, int rpki_version)
{
  // Attach the prefix cache
  handler->prefixCache = prefixCache;
  handler->aspaDBManager = aspaDBManager;
  handler->aspathCache   = aspathCache;

  // Create the RPKI/Router protocol client instance
  handler->rrclParams.prefixCallback     = handlePrefix;
  handler->rrclParams.resetCallback      = handleReset;
  handler->rrclParams.errorCallback      = handleError;
  handler->rrclParams.routerKeyCallback  = handleRouterKey;
  handler->rrclParams.connectionCallback = handleConnection;
  handler->rrclParams.endOfDataCallback  = handleEndOfData;
  handler->rrclParams.cbHandleAspaPdu    = handleAspaPdu;

  handler->rrclParams.serverHost         = serverHost;
  handler->rrclParams.serverPort         = serverPort;
  handler->rrclParams.version            = rpki_version;

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
 * @param rpkiHandler the RPKI handler of the prefix that points to the prefix
 *                    cache.
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
  RPKIHandler* handler = (RPKIHandler*)rpkiHandler;
  if (isAnn)
  {
    addROAwl(handler->prefixCache, oas, prefix, maxLen, session_id, valCacheID,
             PC_DO_SUPPRESS);
  }
  else
  {
    delROAwl(handler->prefixCache, oas, prefix, maxLen, session_id, valCacheID,
             PC_DO_SUPPRESS);
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
  handler = NULL; // just to suppress the compiler warning. Must be removed later
  // @TODO: Remove or flag all ROAS from the given validation Cache
  // It makes sense to flag all ROAS from the given validation cache. Then 
  // request a refresh and for each ROA that is received, remove the flag. Once
  // done, parse through the prefix cache and remove all ROAS of the given 
  // validation cache that were not reloaded.
}

/**
 * Handle the reset for the prefix cache.
 *
 * @param valCacheID The id of the validation cache.
 * @param session_id the id of the session id value. (NETWORK ORDER)
 * @param rpkiHandler the RPKI handler of the prefix that points to the prefix
 *                    cache.
 *
 * @since 0.5.0.0
 */
static void handleEndOfData (uint32_t valCacheID, uint16_t session_id,
                             void* rpkiHandler)
{
  RPKIHandler*     handler = (RPKIHandler*)rpkiHandler;
  RPKI_QUEUE*      rQueue = getRPKIQueue();
  RPKI_QUEUE_ELEM  queueElem;
  SRxResult        srxRes;
  SRxDefaultResult defaultRes;
  
  SRxValidationResult valRes;

  UpdateCache*     uCache = handler->prefixCache->updateCache;
  SRxUpdateID*     uID = NULL;
    
  LOG(LEVEL_INFO, "Received an end of data, process RPKI Queue:\n");

  process_ASPA_EndOfData(uCache, handler->aspaDBManager->cbProcessEndOfData, handler);

  while (rq_dequeue(rQueue, &queueElem))
  {
    uID = &queueElem.updateID;
    valRes.updateID = queueElem.updateID;
    valRes.valType  = VRT_NONE;
    valRes.valResult.roaResult    = SRx_RESULT_DONOTUSE;
    valRes.valResult.bgpsecResult = SRx_RESULT_DONOTUSE;
    valRes.valResult.aspaResult   = SRx_RESULT_DONOTUSE;
    
    if ((queueElem.reason & RQ_ROA) == RQ_ROA)
    {
      if (getUpdateResult(uCache, uID, 0, NULL, &srxRes, &defaultRes, NULL))
      {
        valRes.valType |= VRT_ROA;
        valRes.valResult.roaResult = srxRes.roaResult;
      }
      else
      {
        LOG(LEVEL_WARNING, "Update 0x%08X not found during de-queuing of RPKI "
                           "QUEUE!", queueElem.updateID);
      }
    }
    // Now check for BGPSEC path Validation
    if ((queueElem.reason & RQ_KEY) == RQ_KEY)
    {
      UC_UpdateData* updateData = getUpdateData(uCache, uID);
      SCA_BGP_PathAttribute* bgpsec_path = updateData->bgpsec_path;
      if (bgpsec_path != NULL)
      {
        BGPSecHandler* bgpsecHandler = getBGPsecHandler();
        if (bgpsecHandler != NULL)
        {
          valRes.valType |= VRT_BGPSEC;
          valRes.valResult.bgpsecResult = validateSignature(bgpsecHandler, 
                                                            updateData);
        }
        else
        {
          RAISE_ERROR("BGPSecHAndler could not be retrieved!!");
        }
      }
      else
      {
        LOG(LEVEL_ERROR, "Update 0x%08X is registered for BGPsec but the "
                         "BGPsec_PATH attribute is not stored!", *uID);
      }
    }
    
    // Here check for ASPA Validation which was registered 
    if ((queueElem.reason & RQ_ASPA) == RQ_ASPA)
    {
      LOG(LEVEL_INFO, FILE_LINE_INFO " called for ASPA dequeue [uID: %08X] ", *uID);
      uint32_t pathId= 0;
      if (getUpdateResult(uCache, uID, 0, NULL, &srxRes, &defaultRes, &pathId))
      {
        valRes.valType |= VRT_ASPA;
        valRes.valResult.aspaResult = srxRes.aspaResult;
      }
      else
      {
        LOG(LEVEL_WARNING, "Update 0x%08X not found during de-queuing of RPKI "
            "QUEUE!", queueElem.updateID);
      }
    }
    
    if (uCache->resChangedCallback != NULL)
    {
      // Notify of the change of validation result. (call handleUpdateResultChange)
      uCache->resChangedCallback(&valRes);     
    }
    else
    {
      RAISE_ERROR("No resChangedCallback function registered!\n"
                  "Cannot propagate the changes of the validation result!\n"
                  "Abort operation!");
      rq_empty(rQueue);
      break;
    }
  }
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

/**
 * Determine the algorithm ID depending on the key information.
 *
 * @param keyInfo the key information
 *
 * @return The algorithm id or 0 if unknown / error.
 */
static u_int8_t getAlgoID(const char* keyInfo)
{
  //TODO: Normally we define the algorithm ID according to the key format we
  //      receive. For now we hard code it with a define.
  return SCA_ECDSA_ALGORITHM;
}

/**
 * This function is called for each prefix announcement / withdrawal received
 * from the RPKI validation cache.
 *
 * @param valCacheID  This Id represents the cache. It is used to be able to
 *                    later on identify the white-list / ROA entry in case the
 *                    cache state changes.
 * @param sessionID   The cache sessionID entry for this data. It is be useful
 *                    for sessionID changes in case SRx is implementing a
 *                    performance driven approach.
 * @param isAnn       Indicates if this in an announcement or not.
 * @param asn         The as number in host format
 * @param ski         the ski buffer ()
 * @param keyInfo     Pointer to the key in DER format.
 * @param rpkiHandler Some user data. (might be deleted later on)             // THIS MIGHT BE DELETED LATER ON
 *
 * @since 0.5.0.0
 */
static void handleRouterKey (uint32_t valCacheID, uint16_t session_id,
                             bool isAnn, uint32_t asn, const char* ski,
                             const char* keyInfo, void* rpkiHandler)
{

  SRxCryptoAPI* srxCAPI  = getSrxCAPI();
  SKI_CACHE* sCache      = getSKICache();
  sca_status_t status = API_STATUS_OK;
  u_int8_t res;
  BGPSecKey bsKey;
  
  memset(&bsKey, 0, sizeof(BGPSecKey));
  // Determine the algorithm ID
  bsKey.algoID = getAlgoID(keyInfo);
    
  // At this point only ECDSA algorithm is supported.
  if (bsKey.algoID == SCA_ECDSA_ALGORITHM)
  {
    // Is handed over in network format.
    bsKey.asn = htonl(asn);
    memcpy(bsKey.ski, ski, SKI_LENGTH);
    bsKey.keyLength = ECDSA_PUB_KEY_DER_LENGTH;
    bsKey.keyData = (u_int8_t*)calloc(1, ECDSA_PUB_KEY_DER_LENGTH);
    memcpy(bsKey.keyData, keyInfo, ECDSA_PUB_KEY_DER_LENGTH);

    if (isAnn)
    {
      // A new key is announced
      res = srxCAPI->registerPublicKey(&bsKey, (sca_key_source_t)valCacheID, 
                                       &status);

      if (res == API_SUCCESS)
      {
        LOG(LEVEL_INFO, "RPKI/Router Key Stored in srxcryptoapi ");
        // Now register the key with the SKI_CACHE
        ski_registerKey(sCache, asn, (u_int8_t*)ski, bsKey.algoID);
      }
      else
      {
        LOG(LEVEL_WARNING, "Failed to store RPKI/Router Key in srxcryptoapi "
                           "with status:%i [0x%04X]", status, status);
      }
    }
    else
    {
      // A key is withdrawn
      res = srxCAPI->unregisterPublicKey(&bsKey, (sca_key_source_t)valCacheID, 
                                         &status);
      ski_unregisterKey(sCache, asn, (u_int8_t*)ski, bsKey.algoID);

      if (res == API_SUCCESS)
      {
        LOG(LEVEL_INFO, "A key was removed from SCA.");
        // Now register the key with the SKI_CACHE
      }
      else
      {
        LOG(LEVEL_WARNING, "Failed to remove RPKI/Router Key from srxcryptoapi "
                           "with status:%i [0x%04X]", status, status);
      }
    }
  }
  else
  {
    LOG(LEVEL_WARNING, "Key format specified buy algorithm if %u is not "
                       "supported!", bsKey.algoID);
  }
}

/**
 * Process the ASPA PDU received from the Validation Cache and store the data
 * in the ASPA database.
 * 
 * @param rpkiHandler      Pointer to the RPKI Handler itself.
 * @param customerAsn      The ASN of the customer
 * @param providerAsCount  Number of providers in the providersAsns list.
 * @param providerAsns     The list of provider ASNs
 * @param addrFamilyType   (0: IPv4, 1: IPv6)
 * @param announce         Indicates if this in an announcement or not.
 * 
 * @return 1 for success, 0 for failure.
 * 
 * @since 0.6.0.0
 */
int handleAspaPdu(void* rpkiHandler, uint32_t customerAsn, 
                  uint16_t providerAsCount, uint32_t* providerAsns, 
                  uint8_t addrFamilyType, uint8_t announce)
{
// 
// ASPA validation (called from params -> cbHandleAspaPdu in handleReceiveAspaPdu function)
// work1. parsing ASPA objects into AS number in forms of string
// work2. call DB to store
//  
  LOG(LEVEL_INFO, FILE_LINE_INFO " ASPA handler called for registering ASPA object(s) into DB");
  RPKIHandler* handler = (RPKIHandler*)rpkiHandler;
  ASPA_DBManager* aspaDBManager = handler->aspaDBManager;
  int retVal = 0;
  
  uint16_t afi = AFI_IP; // default
  if (addrFamilyType == 0)
  {
    afi = AFI_IP;
  }
  else if (addrFamilyType == 1)
  {
    afi = AFI_IP6;
  }
  else 
  {
    LOG(LEVEL_WARNING, "AFI value error");
    return retVal;
  }

  TrieNode *node = NULL;
  ASPA_Object *aspaObj = NULL;
  aspaObj = newASPAObject(customerAsn, providerAsCount, providerAsns, afi);

  char strWord[6];
  sprintf(strWord, "%d", customerAsn);
  

  if (announce == 1) // 1 == announce, 0 == withdraw
  {
    LOG(LEVEL_INFO, "[Announce] ASPA object, search key in DB: %s", strWord);
    node = insertAspaObj(aspaDBManager, strWord, strWord, aspaObj);
    if (node)
    {
      retVal = 1; // success
    }
  }
  else if (announce == 0) // withdraw
  {
    // XXX: Draft didn't mention about withdraw clearly
  //
    LOG(LEVEL_INFO, "[Withdraw] ASPA object, search key in DB: %s", strWord);
    bool resWithdraw = delete_TrieNode_AspaObj (aspaDBManager, strWord, aspaObj);

    if (resWithdraw)
    {
      LOG(LEVEL_INFO, "[Withdraw] Withdraw executed successfully");
      retVal = 1; // success
    }
    else
    {
      LOG(LEVEL_WARNING, "[Withdraw] Withdraw Failed due to not found or mismatch");
    }

    if (aspaObj) // release memory unless used for inserting db
    {
      if (aspaObj->providerAsns)
      {
        free(aspaObj->providerAsns);
      }
      free (aspaObj);
      aspaObj = NULL;
    }
  }
  else
  {
    LOG(LEVEL_WARNING, " Cannot recognize the flag set");
    if (aspaObj) // release memory unless used for inserting db
    {
      if (aspaObj->providerAsns)
      {
        free(aspaObj->providerAsns);
      }
      free (aspaObj);
      aspaObj = NULL;
    }
  }

  return retVal;

}











