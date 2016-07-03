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
 * Methods in this file are called by the command handler. The command handler
 * runs in its own thread and gets fed using the command queue. The command
 * queue is fed by the srx-proxy communication thread.
 *
 *
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2016/01/21 - kyehwanl
 *            * added pthread handler function for unexpected error
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed unused variables from functions _processHandshake,
 *              handleCommands, _processUpdateValidation, and broadcastResult
 * 0.3.0    - 2013/01/28 - oborchert
 *            * Changed a log entry from INFO to WARNING
 *            * Added Version Control
 * 0.2.0    - 2011/11/01 - oborchert
 *            * Rewritten
 * 0.1.0    - 2012/05/15 - pgleichm
 *            * Code Created.
 */
#include "server/command_handler.h"
#include "shared/srx_defs.h"
#include "shared/srx_identifier.h"
#include "shared/srx_packets.h"
#include "server/srx_packet_sender.h"
#include "util/log.h"
#include "util/math.h"
#include "util/prefix.h"
#include "util/slist.h"

#define HDR "([0x%08X] Command Handler): "

// Forward declaration
static void* handleCommands(void* arg);

/**
 * Registers a BGPSec Handler, RPKI Handler and Update Cache.
 *
 * @param self Variable that should be initialized
 * @param cfg The system configuration.
 * @param bgpsecHandler Existing BGPSec Handler instance
 * @param rpkiHandler Existing RPKI Handler instance
 * @param updCache Existing Update Cache instance
 *
 * @return true if the command handler was initialized successful
 */
bool initializeCommandHandler(CommandHandler* self, Configuration* cfg,
                              ServerConnectionHandler* svrConnHandler,
                              BGPSecHandler* bgpsecHandler,
                              RPKIHandler* rpkiHandler, UpdateCache* updCache)
{
  self->sysConfig = cfg;
  self->svrConnHandler = svrConnHandler;
  self->bgpsecHandler = bgpsecHandler;
  self->rpkiHandler = rpkiHandler;
  self->updCache = updCache;

  // Queue can be changed every time 'start' is called
  self->queue = NULL;

  // 'start' has not been called
  self->numThreads = 0;

  return true; // Does not fail
}

/**
 * Frees all allocated resources.
 *
 * @param self Instance
 */
void releaseCommandHandler(CommandHandler* self)
{
  LOG(LEVEL_DEBUG, HDR "Send goodbye to all proxies!", pthread_self());
  ServerSocket* srvSoc = &self->svrConnHandler->svrSock;
  if (sizeOfSList(&self->svrConnHandler->clients) > 0)
  {
    SListNode*      cnode;
    ServerClient**  clientPtr;

    // Walk through the list of proxies
    FOREACH_SLIST(&self->svrConnHandler->clients, cnode)
    {
      clientPtr = (ServerClient**)getDataOfSListNode(cnode);
      if (clientPtr != NULL)
      {
        if (!sendGoodbye(srvSoc, *clientPtr, false))
        {
          LOG(LEVEL_DEBUG, HDR "Could not send packet to proxy!",
                           pthread_self());
        }
      }
    }
  }

  LOG(LEVEL_DEBUG, HDR "Command Handler released!", pthread_self());
  // Do nothing
}

bool startProcessingCommands(CommandHandler* self, CommandQueue* cmdQueue)
{
  int idx;

  self->queue = cmdQueue;
  LOG(LEVEL_DEBUG, HDR "Start Processing Commands...", pthread_self());

  for (idx = 0; idx < NUM_COMMAND_HANDLER_THREADS; idx++)
  {
    LOG (LEVEL_DEBUG, HDR "Create command handler Thread No %u", pthread_self(),
                      idx);
    if (pthread_create(&self->threads[idx], NULL, handleCommands, self) > 0)
    {
      // Continue with less threads
      if (idx > 0)
      {
        RAISE_ERROR("Failed to initiate a command handler thread "
                    "- continuing with %d threads",
                    self->numThreads);
        break;

        // No thread
      }
      else
      {
        RAISE_ERROR("Failed to initiate a command handler thread - stopping");
        return false;
      }
    }

    self->numThreads++;
  }

  return true;
}

#include <errno.h>
#define handle_error_en(en, msg) \
                 do { errno = en; perror(msg);  pthread_exit(0); } while (0)
/**
 * This method stops all command handler thread loops.
 *
 * @param self The command handler
 */
void stopProcessingCommands(CommandHandler* self)
{
  if (self->queue)
  {
    int idx;
    int s;

    // First remove all pending commands
    removeAllCommands(self->queue);

    // Send SHUTDOWN to terminate the thread
    // TODO: Revisit this - It might cause errors during shutdown
    for (idx = 0; idx < self->numThreads; idx++)
    {
      queueCommand(self->queue, COMMAND_TYPE_SHUTDOWN,
                   NULL, NULL, 0, 0, NULL);
    }

    // Wait until each thread terminated
    for (idx = 0; idx < self->numThreads; idx++)
    {
      s = pthread_join(self->threads[idx], NULL);
      if (s != 0)
        handle_error_en(s, "pthread_join");
    }
  }
}

/**
 * This method is called when a HELLO packet is received. Here the handshake
 * will be performed. This message will send either a Hello Response or an error
 * followed by Goodbye. The TCP session itself will NOT be closed.
 *
 * @param cmdHandler The command handler instance.
 * @param item The command item to process. It contains the packet.
 *
 * @return true if the the handshake was successful, otherwise false;
 */
static bool _processHandshake(CommandHandler* cmdHandler,
                                CommandQueueItem* item)
{
  SRXPROXY_HELLO* hdr  = (SRXPROXY_HELLO*)item->data;
  uint32_t proxyID     = 0;
  uint8_t  clientID    = 0;
  ClientThread* clientThread = (ClientThread*)item->client; // for easier access

  if (ntohs(hdr->version) != SRX_PROTOCOL_VER)
  {
    RAISE_ERROR("Received Hello packet is of protocol version %u but expected "
                "is a Hello packet of protocol version %u",
                ntohs(hdr->version), SRX_PROTOCOL_VER);
    sendError(SRXERR_WRONG_VERSION, item->serverSocket, item->client, false);
    sendGoodbye(item->serverSocket, item->client, false);
  }
  else
  {
    // Figure out the proxyID if it can be used or not. If not, answer with a
    // new proxy ID.
    proxyID = ntohl(hdr->proxyIdentifier);

    clientID = findClientID(cmdHandler->svrConnHandler, proxyID);
    if (clientID == 0)
    {
      // no client information about this proxy found. determine next free
      // client ID:
      clientID = createClientID(cmdHandler->svrConnHandler);
    }

    if (clientID > 0)
    {
      if (!addMapping(cmdHandler->svrConnHandler, proxyID, clientID,
                      item->client, true))
      {
        clientID = 0; // FAIL HANDSHAKE
      }
    }

    if (clientID == 0)
    {
      if (cmdHandler->svrConnHandler->noMappings < MAX_PROXY_CLIENT_ELEMENTS)
      {
        LOG(LEVEL_NOTICE, "Handshake: The provided proxyID[0x%08X] is already "
                          "in use! Connection not accepted, return error and "
                          "send goodbye!", proxyID);
        sendError(SRXERR_DUPLICATE_PROXY_ID, item->serverSocket, item->client,
                  false);
      }
      else
      {
        LOG(LEVEL_WARNING, "Handshake: Too many proxy clients connected, "
                           "New connection to proxy [0x%08X] refused, return "
                           "error and send goodbye!", proxyID);
        sendError(SRXERR_INTERNAL_ERROR, item->serverSocket, item->client,
                  false);
      }

      sendGoodbye(item->serverSocket, item->client, false);
      //TODO: Close the Socket and unregister?? - maybe done in sendGoodbye??
    }
    else
    {
      LOG (LEVEL_INFO, "Handshake: Connection to proxy[0x%08X] accepted. Proxy "
                       "registered as internal client[0x%02X]",
                       proxyID, clientID);

      clientThread->proxyID  = proxyID;
      clientThread->routerID = clientID;
      if (sendHelloResponse(item->serverSocket, item->client, proxyID))
      {
        clientThread->initialized = true;
        if (cmdHandler->sysConfig->syncAfterConnEstablished)
        {
          LOG(LEVEL_DEBUG, HDR "The configuration requires a sync request to be"
                               " send after establishing an SRx/proxy "
                               "connection!", pthread_self());
          if (!sendSynchRequest(item->serverSocket, item->client, false))
          {
            RAISE_SYS_ERROR("Could not send the synchronization request!");
          }
        }
      }
      else
      {
        RAISE_SYS_ERROR("Client Handshake with proxy[0x%08X] / client[0x%02X]"
                        "failed", proxyID, clientID);
      }
    }
  }

  return (clientID == 0) ? false : true;
}

/**
 * The update did not have any result stored. This means that the update was
 * not yet validates using RPKI. This will be started here.
 *
 * @param rpkiHandler The RPKI validation handler
 * @param updId The update ID
 * @param prefix The prefix of the update
 * @param originAS The origin AS of the update
 * @param srxRes The result container.
 *
 * @return true if the validation could be performed, otherwise false.
 */
static bool verifyUpdateViaRPKI(RPKIHandler* rpkiHandler, SRxUpdateID* updateID,
                                IPPrefix* prefix, uint32_t originAS,
                                SRxResult* srxRes)
{
  // @TODO: Might be deleted, not used yet
  RAISE_ERROR("\n\nCALL DIRECTLY requestPrefixOriginValidation IN RPKI_CACHE!!! ");
  return true;
}

/**
 * The update did not have any result stored. This means that the update was
 * not yet validated using BGPSEC. This will be started here.
 *
 * @param rpkiHandler The RPKI validation handler
 * @param updId The update ID
 * @param srxRes The result container.
 *
 * @return true if the validation could be performed.
 */
static bool verifyViaBGPSEC(void* bgpsecHandler, SRxUpdateID updateID,
                            SRxResult* srxRes, SRxDefaultResult* defResult)
{
  LOG(LEVEL_DEBUG, HDR " " FILE_LINE_INFO "BGPSEC Validation requested for "
                 "update [0x%08X] can not be performed, implementation for this"
                 " does not exist yet!", pthread_self(), updateID);
  srxRes->bgpsecResult = defResult->result.bgpsecResult;
  return true;
}

/**
 * Return true if the "bits" are set in the given "bitmask", otherwise false.
 *
 * @param bitmask the bitmask to examine
 * @param bits the bits to check if they are set
 *
 * @return true if the bits are set.
 */
bool _isSet(uint32_t bitmask, uint32_t bits)
{
  return (bitmask & bits) == bits;
}

/**
 * This method is used to verify an update it is called by the command handlers
 * loop method that works through the command queue!
 *
 * It might be that the very first time only once of the validations is
 * requested. In such a case the ROA value will be SRx_RESULT_DONOTUSE.
 * If now the validation is requested for this type the command the update
 * validation must be started. For instance ROA validation means an update is
 * stored in the prefix cache.
 *
 * @param cmdHandler The command handler itself
 * @param item The command item that contains the information.
 *
 * @return false if the packet could not be processed.
 */
static bool _processUpdateValidation(CommandHandler* cmdHandler,
                                     CommandQueueItem* item)
{
  bool processed = true;

  SRXRPOXY_BasicHeader_VerifyRequest* bhdr =
                                (SRXRPOXY_BasicHeader_VerifyRequest*)item->data;

  // 1. get an idea what validations are requested:
  bool originVal = _isSet(bhdr->type, SRX_PROXY_FLAGS_VERIFY_PREFIX_ORIGIN);
  bool pathVal   = _isSet(bhdr->type, SRX_PROXY_FLAGS_VERIFY_PATH);
  SRxUpdateID updateID = (SRxUpdateID)item->dataID;

  if (!originVal && !pathVal)
  {
    RAISE_SYS_ERROR("Invalid call to process update validation, flags are not "
                    "set properly");
    return false;
  }

  // 2. get the current stored validation results
  SRxDefaultResult defRes;
  SRxResult srxRes;

  if(!getUpdateResult(cmdHandler->updCache, &item->dataID, 0, NULL,
                      &srxRes, &defRes))
  {
    RAISE_SYS_ERROR("Command handler attempts to start validation for update"
                    "[0x%08X] but it does not exist!", updateID);
    return false;
  }

  // Only do origin validation if not already performed
  if (originVal && (srxRes.roaResult == SRx_RESULT_UNDEFINED))
  {
    IPPrefix*  prefix  = malloc(sizeof(IPPrefix));
    uint32_t   asn;
    memset(prefix, 0, sizeof(IPPrefix));

    if (bhdr->type == PDU_SRXPROXY_VERIFY_V4_REQUEST)
    {
      SRXPROXY_VERIFY_V4_REQUEST* v4 = (SRXPROXY_VERIFY_V4_REQUEST*)item->data;
      prefix->ip.version = 4;
      prefix->length = v4->common.prefixLen;
      cpyIPv4Address(&prefix->ip.addr.v4, &v4->prefixAddress);
      asn = ntohl(v4->originAS);
    }
    else
    {
      SRXPROXY_VERIFY_V6_REQUEST* v6 = (SRXPROXY_VERIFY_V6_REQUEST*)item->data;
      prefix->length = v6->common.prefixLen;
      prefix->ip.version = 6;
      cpyIPv6Address(&prefix->ip.addr.v6, &v6->prefixAddress);
      asn = ntohl(v6->originAS);
    }

    if (!requestUpdateValidation(cmdHandler->rpkiHandler->prefixCache,
                                 &updateID, prefix, asn))
    {
      RAISE_SYS_ERROR( HDR "An error occurred during the validation for "
                           "update [0x%08X] within the prefix cache!",
                      pthread_self(), item->dataID);
      processed = false;
    }
    free(prefix);
  }

  // Only do bgpdsec path validation if not already performed
  if (pathVal && (srxRes.bgpsecResult == SRx_RESULT_UNDEFINED))
  {
    // VerifyViaBGPSEC will notify the update cache with the newest result.
    if (!verifyViaBGPSEC(cmdHandler->rpkiHandler, updateID, &srxRes,
                         &defRes))
    {
      RAISE_SYS_ERROR("Update could not be validated using BGPSEC");
      processed = false;
    }
  }

  return processed;
}

/**
 * This method performs the signing of updates.
 *
 * @param cmdHandler The command handler
 * @param item The item containing all data needed to sign.
 */
static void _processUpdateSigning(CommandHandler* cmdHandler,
                                 CommandQueueItem* item)
{
  // TODO Sign the data
  LOG(LEVEL_INFO, "Signing of updates is currently not supported!");
}

/**
 * This method handles the delete request for updates.
 *
 * @param cmdHandler The command handler.
 * @param item The item containing all information needed.
 */
static void _processDeleteUpdate(CommandHandler* cmdHandler,
                                 CommandQueueItem* item)
{
  // For now the delete will NOT remove the update from the cache. It will
  // remove the client - update association though or return an error in case
  // no association existed.
  SRxUpdateID   updateID = (SRxUpdateID)item->dataID;
  ClientThread* clThread = (ClientThread*)item->client;
  SRXPROXY_DELETE_UPDATE* duHdr = (SRXPROXY_DELETE_UPDATE*)item->data;

  if (deleteUpdateFromCache(cmdHandler->updCache, clThread->routerID,
                            &updateID, htons(duHdr->keepWindow)))
  {
    // Reduce the updates by one. BZ308
    cmdHandler->svrConnHandler->proxyMap[clThread->routerID].updateCount--;
  }
  else
  {
    // The update was either not found or the client was not associated to the
    // specified update.
    sendError(SRXERR_UPDATE_NOT_FOUND, item->serverSocket, item->client, false);
    LOG(LEVEL_NOTICE, "Deletion request for update [0x%08X] from client "
                      "[0x%02X] failed, update not found in update cache!");
  }
}

/**
 * This method handles the peer change.
 *
 * @param cmdHandler The command handler.
 * @param item The item containing all information needed.
 */
static void _processPeerChange(CommandHandler* cmdHandler,
                               CommandQueueItem* item)
{
  // TODO@ add code for deletion of peer data
  LOG(LEVEL_WARNING, "Peer Changes are not supported prior Version 0.4.0!");
}

/**
 * This method implements the command handler loop. Once commands are added into
 * the command queue this loop will receive them and process them. Commands
 * can be added by receiving a white list entry, BGPSEC entry, as well as a
 * request or action received from the SRx proxy.
 *
 * @param arg The Command Handler
 *
 */
static void* handleCommands(void* arg)
{
  CommandHandler* cmdHandler = (CommandHandler*)arg;
  CommandQueueItem* item;
  bool keepGoing = true;
  uint8_t clientID = 0; // only used in process handshake and goodbye

  generalSignalProcess();

  LOG (LEVEL_DEBUG, "([0x%08X]) > Command Handler Thread started!", pthread_self());

  while (keepGoing)
  {
    LOG(LEVEL_DEBUG, HDR "Fetch Command ...", pthread_self());
    // Block until the next command is available for this thread
    LOG(LEVEL_DEBUG, HDR "recvLock request ...%s", pthread_self(),__FUNCTION__);

    item = fetchNextCommand(cmdHandler->queue);

    switch (item->cmdType)
    {
      case COMMAND_TYPE_SHUTDOWN:
        LOG(LEVEL_DEBUG, HDR "Received shutdown!", pthread_self());
        LOG(LEVEL_INFO, "SRx server shutdown...");
        keepGoing = false;
        break;
      case COMMAND_TYPE_SRX_PROXY:
        if ((item->dataLength == 0) && (item->data == NULL))
        {
          RAISE_ERROR("SRX-PROXY command but no data! [%u].");
          // Don't stop, just pass on this command.
        }
        else
        {
          SRXPROXY_BasicHeader* bhdr = (SRXPROXY_BasicHeader*)item->data;
          SRXPROXY_GOODBYE* gbhdr;
          // Logging
          LOG(LEVEL_DEBUG, HDR "SRXPROXY PDU type [%u] (%s) fetched!",
            pthread_self(), bhdr->type,
            packetTypeToStr(bhdr->type));
          // Depending on the type
          switch (bhdr->type)
          {
            case PDU_SRXPROXY_HELLO:
              // The mapping information will be maintained during the handshake
              if (!_processHandshake(cmdHandler, item))
              {
                RAISE_ERROR("Handshake between SRx and proxy failed. Shutdown "
                            "TCP connection!");

                closeClientConnection(&cmdHandler->svrConnHandler->svrSock,
                                      item->client);
		            deleteFromSList(&cmdHandler->svrConnHandler->clients,
                                item->client);
              }
              break;
            case PDU_SRXPROXY_VERIFY_V4_REQUEST:
            case PDU_SRXPROXY_VERIFY_V6_REQUEST:
              _processUpdateValidation(cmdHandler, item);
              break;
            case PDU_SRXPROXY_SIGN_REQUEST:
              _processUpdateSigning(cmdHandler, item);
              break;
            case PDU_SRXPROXY_GOODBYE:
              gbhdr = (SRXPROXY_GOODBYE*)item->data;
              closeClientConnection(&cmdHandler->svrConnHandler->svrSock,
                                    item->client);
              clientID = ((ClientThread*)item->client)->routerID;
              //cmdHandler->svrConnHandler->proxyMap[clientID].isActive = false;
              // The deaktivation will also delete because it did not crash
              deactivateConnectionMapping(cmdHandler->svrConnHandler, clientID,
                                          false, htons(gbhdr->keepWindow));
              //delMapping(cmdHandler->svrConnHandler, clientID);

              deleteFromSList(&cmdHandler->svrConnHandler->clients,
                              item->client);
              LOG(LEVEL_DEBUG, HDR "GoodBye!", pthread_self());
              break;
            case PDU_SRXPROXY_DELTE_UPDATE:
              _processDeleteUpdate(cmdHandler, item);
              break;
            case PDU_SRXPROXY_PEER_CHANGE:
              _processPeerChange(cmdHandler, item);
              break;
            default:
              RAISE_ERROR("Unknown/unsupported pdu type: %d",
                          item->dataID);
              sendError(SRXERR_INVALID_PACKET, item->serverSocket,
                        item->client, false);
              sendGoodbye(item->serverSocket, item->client, false);
              closeClientConnection(&cmdHandler->svrConnHandler->svrSock,
                                    item->client);

              clientID = ((ClientThread*)item->client)->routerID;
              // The deaktivatio will also delete the mapping because it was NOT
              // a crash.
              deactivateConnectionMapping(cmdHandler->svrConnHandler, clientID,
                               false, cmdHandler->sysConfig->defaultKeepWindow);
              //cmdHandler->svrConnHandler->proxyMap[clientID].isActive = false;
              //delMapping(cmdHandler->svrConnHandler, clientID);

              deleteFromSList(&cmdHandler->svrConnHandler->clients,
                              item->client);
          }
        }
        break;
      default:
        RAISE_ERROR("Unknown Command Handler Command! [%u].", item->cmdType);
      // Still keep going.
    }

    if (cmdHandler->queue->nextItemNode != NULL)
    {
      LOG(LEVEL_DEBUG, HDR "recv Unlock request ...%s", pthread_self(),
                       __FUNCTION__);
      //unlockMutex(&cmdHandler->queue->recvMutex);
      //signalCond(&cmdHandler->queue->recvCond);
    }

    // Now remove the item from command handler. it is processed.
    deleteCommand(cmdHandler->queue, item);

  } /* end of while */

  LOG (LEVEL_DEBUG, "([0x%08X]) < Command Handler Thread stopped!",
       pthread_self());

  pthread_exit(0);
}


/**
 * Sends a (new) result to all connected clients.
 *
 * @param self Instance
 * @param updId Update identifier
 * @param res Result
 * @return true if at least one broadcast could be successfully send to any
 *              registered client
 */
bool broadcastResult(CommandHandler* self, SRxValidationResult* valResult)
{
  SRXPROXY_VERIFY_NOTIFICATION* pdu;
  uint32_t pduLength = sizeof(SRXPROXY_VERIFY_NOTIFICATION);
  bool retVal = true;
  // Prepare the array of clients.
  uint8_t clientSize = self->updCache->minNumberOfClients;
  uint8_t clients[clientSize];
  ServerClient* client = NULL;

  int clientCt = getClientIDsOfUpdate(self->updCache, &valResult->updateID,
                                      clients, clientSize);
  if (clientCt == -1)
  {
    RAISE_SYS_ERROR("Cannot send update results, client management failed!!");
    return false;
  }

  // The client count might be 0 if the update is still in the cache but no
  // client is currently attached to it. This could be because the update was
  // requested to be removed or it could be that previous registered clients
  // are in reboot. Therefore we only need to prepare the packet for updates
  // that have listeners / clients installed.
  if (clientCt > 0)
  {
    pdu = malloc(pduLength);
    memset(pdu,0,pduLength);
    pdu->type         = PDU_SRXPROXY_VERI_NOTIFICATION;
    pdu->resultType   = (valResult->valType & SRX_FLAG_ROA_AND_BGPSEC);
    pdu->roaResult    = valResult->valResult.roaResult;
    pdu->bgpsecResult = valResult->valResult.bgpsecResult;

    pdu->length           = htonl(pduLength);
    pdu->updateID = htonl(valResult->updateID);

    /* extract a specific client to send packet */
    retVal = false;
    while  (clientCt-- > 0)
    {
      // work the clients array backwards - saves maintaining a counter variable
      if (self->svrConnHandler->proxyMap[clients[clientCt]].isActive)
      {
        client = self->svrConnHandler->proxyMap[clients[clientCt]].socket;

        retVal |= sendPacketToClient(&self->svrConnHandler->svrSock,
                                     client , pdu, pduLength);
      }
      // If the mapping is inactive the proxy might be in reboot.
    }

    free(pdu);
  }

  return retVal;
}

