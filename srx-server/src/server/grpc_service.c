

#include <stdio.h>
#include "server/grpc_service.h"
#include "server/command_handler.h"

#define HDR  "(GRPC_ServiceHandler): "
static void _processDeleteUpdate_grpc(unsigned char *data, RET_DATA *rt, unsigned int grpcClientID);
static void _processUpdateSigning_grpc(unsigned char *data, RET_DATA *rt, unsigned int grpcClientID);
static bool processValidationRequest_grpc(unsigned char *data, RET_DATA *rt, unsigned int grpcClientID);
static bool processHandshake_grpc(unsigned char *data, RET_DATA *rt);
static bool sendSynchRequest_grpc();

extern bool sendError(uint16_t errorCode, ServerSocket* srvSoc, ServerClient* client, bool useQueue);
extern uint32_t generateIdentifier(uint32_t originAS, IPPrefix* prefix, BGPSecData* data);
extern void cb_proxyGoodBye(SRXPROXY_GOODBYE p0);

__attribute__((always_inline)) inline void printHex(int len, unsigned char* buff) 
{                                                                                 
  int i;                                                                          
  for(i=0; i < len; i++ )                                                         
  {                                                                               
      if(i%16 ==0) printf("\n");                                                  
      printf("%02x ", buff[i]);                                                   
  }                                                                               
  printf("\n");                                                                   
}  

        
static bool processHandshake_grpc(unsigned char *data, RET_DATA *rt)
{
  LOG(LEVEL_INFO, HDR "[SRx server][grpc service] %s function called ", __FUNCTION__);
  LOG(LEVEL_INFO, HDR "[SRx server][grpc service] grpcServiceHandler : %p  \n", &grpcServiceHandler );
  LOG(LEVEL_INFO, HDR "[SRx server][grpc service] grpcServiceHandler.CommandQueue   : %p  ", grpcServiceHandler.cmdQueue);
  LOG(LEVEL_INFO, HDR "[SRx server][grpc service] grpcServiceHandler.CommandHandler : %p  ", grpcServiceHandler.cmdHandler );
  LOG(LEVEL_INFO, HDR "[SRx server][grpc service] grpcServiceHandler.UpdateCache    : %p  ", grpcServiceHandler.updCache);
  LOG(LEVEL_INFO, HDR "[SRx server][grpc service] grpcServiceHandler.svrConnHandler : %p  ", grpcServiceHandler.svrConnHandler);

  SRXPROXY_HELLO* hdr  = (SRXPROXY_HELLO*)data;
  uint32_t proxyID     = 0;
  uint8_t  clientID    = 0;
  
  
  /* 
   * To make clientID in accordance with porxyID with proxyMap 
   */
  ClientThread* cthread;
  cthread = (ClientThread*)appendToSList(&grpcServiceHandler.svrConnHandler->svrSock.cthreads, sizeof (ClientThread));

  cthread->active          = true;
  cthread->initialized     = false;
  cthread->goodByeReceived = false;

  cthread->proxyID  = 0; // will be changed for srx-proxy during handshake
  cthread->routerID = 0; // Indicates that it is currently not usable, 
  //cthread->clientFD = cliendFD;
  cthread->svrSock  = &grpcServiceHandler.svrConnHandler->svrSock;
  //cthread->caddr	  = caddr;
  cthread->type_grpc_client = true;

  // the same way of calling  handleStatusChange()
  if (cthread->svrSock->statusCallback != NULL)
  {
    cthread->svrSock->statusCallback (cthread->svrSock, cthread, -1, true, 
                                        (void*)grpcServiceHandler.svrConnHandler);
  }

  LOG(LEVEL_INFO, HDR "[SRx server][grpc service](Hello Resonse) Obtained cthread: %p \n", cthread);


  if (ntohs(hdr->version) != SRX_PROTOCOL_VER)
  {
    RAISE_ERROR("Received Hello packet is of protocol version %u but expected "
                "is a Hello packet of protocol version %u",
                ntohs(hdr->version), SRX_PROTOCOL_VER);
    sendError(SRXERR_WRONG_VERSION, NULL, NULL, false);
    //sendGoodbye(item->serverSocket, item->client, false);
  }
  else
  {
    // Figure out the proxyID if it can be used or not. If not, answer with a new proxy ID.
    proxyID = ntohl(hdr->proxyIdentifier);

    clientID = findClientID(grpcServiceHandler.svrConnHandler, proxyID);
    if (clientID == 0)
    {
      clientID = createClientID(grpcServiceHandler.svrConnHandler);
    }


    if (clientID > 0)
    {
      if (!addMapping(grpcServiceHandler.svrConnHandler, proxyID, clientID, cthread, true))
      {
        clientID = 0; // FAIL HANDSHAKE
      }

      LOG(LEVEL_INFO, HDR "[SRx server][grpc service](Hello Resonse) proxyID: 0x%08X --> mapping[clientID:%d] cthread: %p\n", 
          proxyID,  clientID, grpcServiceHandler.svrConnHandler->proxyMap[clientID].socket);
    }

    LOG (LEVEL_INFO, "\033[0;36m [SRx server][grpc service](Hello Resonse) Handshake: Connection to proxy[0x%08X] accepted."
        "Proxy registered as internal client[0x%02X] \033[0m", proxyID, clientID);

    cthread->proxyID  = proxyID;
    cthread->routerID = clientID;

    grpcServiceHandler.cmdHandler->grpcEnable = true;

    // TODO: client registration should be followed
    //  _processHandshake()
    //  command_handler.c: 233 -


    /* Send Hello Response */
    LOG (LEVEL_INFO, HDR "[SRx server][grpc service](Hello Resonse) send Hello Response");

    bool retVal = true;
    uint32_t length = sizeof(SRXPROXY_HELLO_RESPONSE);
    SRXPROXY_HELLO_RESPONSE* pdu = malloc(length);
    memset(pdu, 0, length);

    pdu->type    = PDU_SRXPROXY_HELLO_RESPONSE;
    pdu->version = htons(SRX_PROTOCOL_VER);
    pdu->length  = htonl(length);
    pdu->proxyIdentifier = htonl(proxyID);


    rt->size = length;
    rt->data = (unsigned char*) malloc(length);
    memcpy(rt->data, pdu, length);
    free(pdu);


    if(rt->size != 0 && rt->data)
      cthread->initialized = true;


    // This proxy hello function is not stream function, so first it needs to respond
    // with Hello REsponse value and later have to send 'send sync request' if applicable
    // In order to do that, send SyncRequest_grpc function should enable some sort of queuing 
    // mechanism to store 'sync request'
    //
    // NOTE : sendSynchRequest  (command_handler.c:307)
#if 1
    if (grpcServiceHandler.cmdHandler->sysConfig->syncAfterConnEstablished)
    {
      LOG (LEVEL_INFO, HDR "[SRx server][grpc service](Hello Resonse) call sendSyncRequest ");
      sendSynchRequest_grpc();
    }
#endif

    
    // TODO: send goodbye in case there is error 

  }

  return (rt->size == 0) ? false : true;
}

static bool processValidationRequest_grpc(unsigned char *data, RET_DATA *rt, unsigned int grpcClientID)
{
  LOG(LEVEL_INFO, HDR "[%s] function called, grpc clientID: %d \n", __FUNCTION__, grpcClientID);
  LOG(LEVEL_INFO, HDR "Enter processValidationRequest");
    
  bool retVal = true;
  SRXRPOXY_BasicHeader_VerifyRequest* hdr =
                                (SRXRPOXY_BasicHeader_VerifyRequest*)data;

  // Determine if a receipt is requested and a result packet must be send
  bool     receipt =    (hdr->flags & SRX_FLAG_REQUEST_RECEIPT)
                      == SRX_FLAG_REQUEST_RECEIPT;
  // prepare already the send flag. Later on, if this is > 0 send a response.
  uint8_t  sendFlags = hdr->flags & SRX_FLAG_REQUEST_RECEIPT;

  bool     doOriginVal = (hdr->flags & SRX_FLAG_ROA) == SRX_FLAG_ROA;
  bool     doPathVal   = (hdr->flags & SRX_FLAG_BGPSEC) == SRX_FLAG_BGPSEC;
  bool     doAspaVal   = (hdr->flags & SRX_FLAG_ASPA) == SRX_FLAG_ASPA;

  bool      v4     = hdr->type == PDU_SRXPROXY_VERIFY_V4_REQUEST;

  // 1. get an idea what validations are requested:
  //bool originVal = _isSet(hdr->flags, SRX_PROXY_FLAGS_VERIFY_PREFIX_ORIGIN);
  //bool pathVal   = _isSet(hdr->flags, SRX_PROXY_FLAGS_VERIFY_PATH);
  //SRxUpdateID updateID = (SRxUpdateID)item->dataID;


  uint32_t requestToken = receipt ? ntohl(hdr->requestToken)
                                  : DONOTUSE_REQUEST_TOKEN;
  uint32_t originAS = 0;
  SRxUpdateID collisionID = 0;
  SRxUpdateID updateID = 0;

  bool doStoreUpdate = false;
  IPPrefix* prefix = NULL;
  // Specify the client id as a receiver only when validation is requested.
  uint8_t clientID = findClientID(grpcServiceHandler.svrConnHandler, grpcClientID);

  // 1. Prepare for and generate the ID of the update
  prefix = malloc(sizeof(IPPrefix));
  memset(prefix, 0, sizeof(IPPrefix));
  prefix->length     = hdr->prefixLen;
  BGPSecData bgpData;
  memset (&bgpData, 0, sizeof(BGPSecData));

  uint8_t* valPtr = (uint8_t*)hdr;
  AS_TYPE     asType;
  AS_REL_DIR  asRelDir;
  AS_REL_TYPE asRelType;
  if (v4)
  {
    SRXPROXY_VERIFY_V4_REQUEST* v4Hdr = (SRXPROXY_VERIFY_V4_REQUEST*)hdr;
    valPtr += sizeof(SRXPROXY_VERIFY_V4_REQUEST);
    prefix->ip.version  = 4;
    prefix->ip.addr.v4  = v4Hdr->prefixAddress;
    originAS            = ntohl(v4Hdr->originAS);
    // The next two are in host format for convenience
    bgpData.numberHops  = ntohs(v4Hdr->bgpsecValReqData.numHops);
    bgpData.attr_length = ntohs(v4Hdr->bgpsecValReqData.attrLen);
    // Now in network format as required.
    bgpData.afi         = v4Hdr->bgpsecValReqData.valPrefix.afi;
    bgpData.safi        = v4Hdr->bgpsecValReqData.valPrefix.safi;
    bgpData.local_as    = v4Hdr->bgpsecValReqData.valData.local_as;
    asType              = v4Hdr->common.asType;
    asRelType           = v4Hdr->common.asRelType;
  }
  else
  {
    SRXPROXY_VERIFY_V6_REQUEST* v6Hdr = (SRXPROXY_VERIFY_V6_REQUEST*)hdr;
    valPtr += sizeof(SRXPROXY_VERIFY_V6_REQUEST);
    prefix->ip.version  = 6;
    prefix->ip.addr.v6  = v6Hdr->prefixAddress;
    originAS            = ntohl(v6Hdr->originAS);
    // The next two are in host format for convenience
    bgpData.numberHops  = ntohs(v6Hdr->bgpsecValReqData.numHops);
    bgpData.attr_length = ntohs(v6Hdr->bgpsecValReqData.attrLen);
    // Now in network format as required.
    bgpData.afi         = v6Hdr->bgpsecValReqData.valPrefix.afi;
    bgpData.safi        = v6Hdr->bgpsecValReqData.valPrefix.safi;
    bgpData.local_as    = v6Hdr->bgpsecValReqData.valData.local_as;
    // TODO: v6 protocol 
    //asType           = ntohl(v6Hdr->asType);
    //asRelType        = ntohl(v6Hdr->asRelType);
  }

  // Check if AS path exists and if so then set it
  if (bgpData.numberHops != 0)
  {
    bgpData.asPath = (uint32_t*)valPtr;
  }
  // Check if BGPsec path exits and if so then set it
  if (bgpData.attr_length != 0)
  {
    // BGPsec attribute comes after the as4 path
    bgpData.bgpsec_path_attr = valPtr + (bgpData.numberHops * 4);
  }

  // 2. Generate the CRC based updateID
  updateID = generateIdentifier(originAS, prefix, &bgpData);
  // test for collision and attempt to resolve
  collisionID = updateID;
  while(detectCollision(grpcServiceHandler.svrConnHandler->updateCache, &updateID, prefix, originAS, 
                        &bgpData))
  {
    updateID++;
  }
  if (collisionID != updateID)
  {
    LOG(LEVEL_NOTICE, "UpdateID collision detected!!. The original update ID"
      " could have been [0x%08X] but was changed to a collision free ID "
      "[0x%08X]!", collisionID, updateID);
  }
  LOG(LEVEL_INFO, HDR "\n[SRx server] Generated Update ID: %08X, client ID:%d \n\n", updateID, clientID);

  //  3. Try to find the update, if it does not exist yet, store it.
  SRxResult        srxRes;
  SRxDefaultResult defResInfo;
  // The method getUpdateResult will initialize the result parameters and
  // register the client as listener (only if the update already exists)
  ProxyClientMapping* clientMapping = clientID > 0 ? &grpcServiceHandler.svrConnHandler->proxyMap[clientID]
                                                   : NULL;

  LOG(LEVEL_INFO, HDR "[SRx Server] proxyMap[clientID:%d]: %p\n", clientID, clientMapping);
  uint32_t pathId = 0;

  doStoreUpdate = !getUpdateResult (grpcServiceHandler.svrConnHandler->updateCache, &updateID,
                                    clientID, clientMapping,
                                    &srxRes, &defResInfo, &pathId);

  LOG(LEVEL_INFO, FILE_LINE_INFO "\033[1;33m ------- Received ASpath info ------- \033[0m");
  LOG(LEVEL_INFO, "     updateId: [0x%08X] pathID: [0x%08X] "
      " AS Type: %s  AS Relationship: %s", 
      updateID, pathId, 
      asType==2 ? "AS_SEQUENCE": (asType==1 ? "AS_SET": "ETC"),
      asRelType == 2 ? "provider" : (asRelType == 1 ? "customer":         
        (asRelType == 3 ? "sibling": (asRelType == 4 ? "lateral" : "unknown"))));

  AS_PATH_LIST *aspl;
  SRxResult srxRes_aspa; 
  bool modifyUpdateCacheWithAspaValue = false;

  switch (asRelType)
  {
    case AS_REL_CUSTOMER:
      asRelDir = ASPA_UPSTREAM; break;
    case AS_REL_PROVIDER:
      asRelDir = ASPA_DOWNSTREAM; break;
    case AS_REL_SIBLING:
      asRelDir = ASPA_UPSTREAM; break;
    case AS_REL_LATERAL:
      asRelDir = ASPA_DOWNSTREAM; break;
    default:
      asRelDir = ASPA_UNKNOWNSTREAM;     
  }


  if (pathId == 0)  // if not found in  cEntry
  {
    pathId = makePathId(bgpData.numberHops, bgpData.asPath, asType, true);
    LOG(LEVEL_INFO, FILE_LINE_INFO " generated Path ID : %08X ", pathId);

    // to see if there is already exist or not in AS path Cache with path id
    aspl = getAspathListFromAspathCache (grpcServiceHandler.svrConnHandler->aspathCache, pathId, &srxRes_aspa);
    
    // AS Path List already exist in Cache
    if(aspl)
    {
      // once found aspa result value in Cache, no need to validate operation
      //  this value is some value not undefined
      if (srxRes_aspa.aspaResult == SRx_RESULT_UNDEFINED)
      {
        LOG(LEVEL_INFO, FILE_LINE_INFO " Already registered with the previous pdu");
      }
      else
      {
        // in case the same update message comes from same peer, even though same update, 
        // bgpsec pdu is different, so that it results in a new updateID, which in turn 
        // makes not found in updatecahe. So this case makes not found pathId, but aspath cache 
        // stores srx result value in db with the matched path id. So srxRes_aspa.aspaResult is
        // not undefined
        LOG(LEVEL_INFO, FILE_LINE_INFO " ASPA validation Result[%d] is already exist", srxRes_aspa.aspaResult);

        // Modify UpdateCache's srx Res -> aspaResult with srxRes_aspa.aspaResult
        // But UpdateCache's cEntry here dosen't exist yet
        // so, after calling storeUpdate, put this value into cEntry directly
        modifyUpdateCacheWithAspaValue = true;
      }

      srxRes.aspaResult = srxRes_aspa.aspaResult;

    }
    // AS Path List not exist in Cache
    else
    {
      aspl = newAspathListEntry(bgpData.numberHops, bgpData.asPath, pathId, asType, asRelDir, bgpData.afi, true);
      if(!aspl)
      {
        LOG(LEVEL_ERROR, " memory allocation for AS path list entry resulted in fault");
        //return false;
      }
  
      if (doStoreUpdate)
      {
        defResInfo.result.aspaResult = hdr->aspaDefRes; // router's input value (Undefined, Unverifiable, Invalid)
        defResInfo.resSourceASPA     = hdr->aspaResSrc;
      }

      // in order to free aspl, need to copy value inside the function below
      //
      storeAspathList(grpcServiceHandler.svrConnHandler->aspathCache, &defResInfo, pathId, asType, aspl);
      srxRes.aspaResult   = defResInfo.result.aspaResult;

    }
    // free 
    if (aspl)
      deleteAspathListEntry(aspl);
  }

  // -------------------------------------------------------------------

  if (doStoreUpdate)
  {
    defResInfo.result.roaResult    = hdr->roaDefRes;
    defResInfo.resSourceROA        = hdr->roaResSrc;

    defResInfo.result.bgpsecResult = hdr->bgpsecDefRes;
    defResInfo.resSourceBGPSEC     = hdr->bgpsecResSrc;

    if (!storeUpdate(grpcServiceHandler.svrConnHandler->updateCache, clientID, clientMapping,
                     &updateID, prefix, originAS, &defResInfo, &bgpData, pathId))
    {
      RAISE_SYS_ERROR("Could not store update [0x%08X]!!", updateID);
      free(prefix);
      return false;
    }

    // Use the default result.
    srxRes.roaResult    = defResInfo.result.roaResult;
    srxRes.bgpsecResult = defResInfo.result.bgpsecResult;
  }
  free(prefix);
  prefix = NULL;

  LOG(LEVEL_INFO, HDR "+ from update cache srxRes.roaResult : %02x", srxRes.roaResult);
  LOG(LEVEL_INFO, HDR "+ from update cache srxRes.bgpsecResult : %02x", srxRes.bgpsecResult);
  LOG(LEVEL_INFO, HDR "+ from update cache srxRes.aspaesult : %02x", srxRes.aspaResult);


  if (modifyUpdateCacheWithAspaValue)
  {
    // modify UpdateCache with srxRes_aspa.aspaResult, then later this value 
    // in UpdateCahe will be used 
    modifyUpdateCacheResultWithAspaVal(grpcServiceHandler.svrConnHandler->updateCache, &updateID, &srxRes_aspa);

  }

  // Just check if the client has the correct values for the requested results
  if (doOriginVal && (hdr->roaDefRes != srxRes.roaResult))
  {
    sendFlags = sendFlags | SRX_FLAG_ROA;
  }
  if (doPathVal && (hdr->bgpsecDefRes != srxRes.bgpsecResult))
  {
    sendFlags = sendFlags | SRX_FLAG_BGPSEC;
  }


  LOG(LEVEL_DEBUG, HDR"\033[0;35m sendflag: %x \033[0m", sendFlags);
  if (sendFlags > 0) // a notification is needed. flags specifies the type
  {
    // TODO: Check specification if we can send a receipt without results, if
    // not the following 6 lines MUST be included, otherwise not.
    if (doOriginVal)
    {
      sendFlags = sendFlags | SRX_FLAG_ROA;
    }
    if (doPathVal)
    {
      sendFlags = sendFlags | SRX_FLAG_BGPSEC;
    }
    if (doAspaVal)
    {
      sendFlags = sendFlags | SRX_FLAG_ASPA;
    }

  
    // Now send the results we know so far;
    
    /*
       sendVerifyNotification(svrSock, client, updateID, sendFlags,
       requestToken, srxRes.roaResult,
       srxRes.bgpsecResult,
       !self->sysConfig->mode_no_sendqueue);
    */

    uint32_t length = sizeof(SRXPROXY_VERIFY_NOTIFICATION);
    SRXPROXY_VERIFY_NOTIFICATION* pdu = malloc(length);
    memset(pdu, 0, length);

    pdu->type          = PDU_SRXPROXY_VERI_NOTIFICATION;
    pdu->resultType    = sendFlags;
    pdu->requestToken  = htonl(requestToken);
    pdu->roaResult     = srxRes.roaResult;
    pdu->bgpsecResult  = srxRes.bgpsecResult;
    pdu->aspaResult    = srxRes.aspaResult;
    pdu->length        = htonl(length);
    pdu->updateID      = htonl(updateID);

    if ((pdu->requestToken != 0) && (sendFlags < SRX_FLAG_REQUEST_RECEIPT))
    {
      LOG(LEVEL_NOTICE, "Send a notification of update 0x%0aX with request "
          "token 0x%08X but no receipt flag set!", updateID, requestToken);
    }

    pdu->length = htonl(length);

    // return value for response grpc
    rt->size = length;
    rt->data = (unsigned char*) malloc(length);
    memcpy(rt->data, pdu, length);
    free(pdu);

    LOG(LEVEL_INFO, HDR "+ rt size: %d", rt->size);
    LOG(LEVEL_INFO, HDR "+ rt data: ");

    LogLevel lv = getLogLevel();
    if (lv >= LEVEL_INFO) {
      printHex(rt->size, rt->data);
    }
  
    if ((doOriginVal || doPathVal || doAspaVal) && ((sendFlags & SRX_FLAG_ROA_BGPSEC_ASPA) > 0))
    {
      rt->info = 0x1; // queue enable info
      LOG(LEVEL_INFO, HDR "+ rt info: %x", rt->info);

      // Only keep the validation flags.
      hdr->flags = sendFlags & SRX_FLAG_ROA_BGPSEC_ASPA;

      /*
      if (!queueCommand(grpcServiceHandler.cmdQueue, COMMAND_TYPE_SRX_PROXY, NULL, NULL,
            updateID, ntohl(hdr->length), (uint8_t*)hdr))
      //  TODO XXX: should I put a client thread to queue command function above instead of NULL ?
      //    --> client thread (ClientThread*) was created and associated with the info 
      //    from server_socket.c::runServerLoop()
      //
      //    --> (Answer) No need, because _processUpdateValidation() doesn't use client thread at all
      {
        RAISE_ERROR("Could not add validation request to command queue!");
        retVal = false;
      }
      */
    }

    LOG(LEVEL_INFO, HDR "Exit processValidationRequest", pthread_self());

  }
  return retVal;
}


void RunQueueCommand(int size, unsigned char *data, RET_DATA *rt, unsigned int grpcClientID)
{
  
  LOG(LEVEL_INFO, HDR "[%s] for Notification Queueing Command", __FUNCTION__);
    
  LogLevel lv = getLogLevel();
  if ( lv >= LEVEL_INFO)
    printHex(size, data);

  LOG(LEVEL_INFO, HDR "[%s] rt size: %d\n", __FUNCTION__, rt->size);
  LOG(LEVEL_INFO, HDR "[%s] rt data: \n", __FUNCTION__);
  if ( lv >= LEVEL_INFO)
    printHex(rt->size, rt->data);

  bool retVal = true;
  SRXRPOXY_BasicHeader_VerifyRequest* hdr =
    (SRXRPOXY_BasicHeader_VerifyRequest*)data;

  SRXPROXY_VERIFY_NOTIFICATION* pdu = (SRXPROXY_VERIFY_NOTIFICATION*)rt->data;

  SRxUpdateID updateID = 0;
  updateID = ntohl(pdu->updateID);
  LOG(LEVEL_INFO, HDR "[%s] updateID: %08x hdr length: %d\n", __FUNCTION__, updateID, ntohl(hdr->length));


  // create the validation command! 
  // here, do not need server sock and client thread (3rd, 4th parameter below)
  if (!queueCommand(grpcServiceHandler.cmdQueue, COMMAND_TYPE_SRX_PROXY, NULL, NULL,
        updateID, ntohl(hdr->length), (uint8_t*)hdr))
  {
    RAISE_ERROR("Could not add validation request to command queue!");
    retVal = false;
  }
}

void RunQueueCommand_uid(int size, unsigned char *data, uint32_t updateId, unsigned int grpcClientID)
{
  LOG(LEVEL_INFO, HDR "[%s] for General purpose Queueing Command", __FUNCTION__);
  LogLevel lv = getLogLevel();
  if ( lv >= LEVEL_INFO)
    printHex(size, data);


  bool retVal = true;
  SRxUpdateID updateID = 0;

  SRXPROXY_DELETE_UPDATE*  duHdr = NULL;

  SRXPROXY_BasicHeader*    bhdr  = NULL; 
  bhdr = (SRXPROXY_BasicHeader*)data;

  switch (bhdr->type)                   
  {                                     
    case PDU_SRXPROXY_DELTE_UPDATE:
      duHdr = (SRXPROXY_DELETE_UPDATE*)data;
      updateID = ntohl(duHdr->updateIdentifier);
      break;

    default:
      break;
  }

  uint8_t  clientID    = 0;
  clientID = findClientID(grpcServiceHandler.svrConnHandler, grpcClientID);

  // find cthread from client ID 
  ClientThread* cthread = NULL;
  SListNode* node =  getRootNodeOfSList(&grpcServiceHandler.svrConnHandler->svrSock.cthreads);
    
  while (!(node == NULL))
  {
      cthread = (ClientThread*)node->data;
      if (cthread && cthread->proxyID == grpcClientID)
        break;
      node = node->next;
  }


  LOG(LEVEL_INFO, HDR "[%s] updateID: %08x duHdr length: %d clientID: %d\n",
      __FUNCTION__, updateID, ntohl(duHdr->length), clientID);

  if (!queueCommand(grpcServiceHandler.cmdQueue, COMMAND_TYPE_SRX_PROXY, 
        &grpcServiceHandler.svrConnHandler->svrSock, cthread,
        updateID, ntohl(duHdr->length), (uint8_t*)duHdr))
  {
    RAISE_ERROR("Could not add validation request to command queue!");
    retVal = false;
  }
}

static void _processUpdateSigning_grpc(unsigned char *data, RET_DATA *rt, unsigned int grpcClientID)
{
  // TODO Sign the data
  LOG(LEVEL_INFO, "Signing of updates is currently not supported!");
}

//static void _processDeleteUpdate(CommandHandler* cmdHandler, CommandQueueItem* item)
static void _processDeleteUpdate_grpc(unsigned char *data, RET_DATA *rt, unsigned int grpcClientID)
{

  CommandHandler* cmdHandler =  grpcServiceHandler.cmdHandler;

  // TODO: replace item with real pointer variable
  CommandQueueItem* item;
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

static void _processPeerChange_grpc(unsigned char *data, RET_DATA *rt, unsigned int grpcClientID)
{
  // TODO@ add code for deletion of peer data
  LOG(LEVEL_WARNING, "Peer Changes are not supported prior Version 0.4.0!");
}


// Called by Go module
//int responseGRPC (int size, unsigned char* data)
RET_DATA responseGRPC (int size, unsigned char* data, unsigned int grpcClientID)
{
    LogLevel lv = getLogLevel();
    LOG(LEVEL_INFO, HDR "initial srx server log Level: %d", lv);

    //setLogLevel(LEVEL_INFO);
    LOG(LEVEL_INFO, HDR "response GRPC call");
    LOG(LEVEL_INFO, HDR "[SRx server] [%s] calling - size: %d, grpcClient ID: %02x", __FUNCTION__, size, grpcClientID);


    //LogLevel lv = getLogLevel();
    LOG(LEVEL_INFO, HDR "srx server log Level: %d", lv);

    if (lv >= LEVEL_INFO) {
      printf(" ---- received data ----\n");
      printHex(size, data);
      printf(" -----------------------\n");
    }

    RET_DATA rt;
    memset(&rt, 0x0, sizeof(RET_DATA));

    SRXPROXY_BasicHeader* bhdr = (SRXPROXY_BasicHeader*)data;
    uint8_t clientID;
    ClientThread* cthread;
          
    uint32_t length = sizeof(SRXPROXY_GOODBYE);     
    uint8_t pdu[length];                            
    SRXPROXY_GOODBYE* hdr = (SRXPROXY_GOODBYE*)pdu; 

    switch (bhdr->type)
    {                   
      case PDU_SRXPROXY_HELLO:
        processHandshake_grpc(data, &rt);
        break;

      case PDU_SRXPROXY_VERIFY_V4_REQUEST:
      case PDU_SRXPROXY_VERIFY_V6_REQUEST:
        processValidationRequest_grpc(data, &rt, grpcClientID);
        break;

      case PDU_SRXPROXY_SIGN_REQUEST:
        _processUpdateSigning_grpc(data, &rt, grpcClientID);
        break;
      case PDU_SRXPROXY_GOODBYE:
        LOG(LEVEL_INFO, HDR "[SRx Server] Received GOOD BYE from proxyID: %d\n", grpcClientID);
        clientID = findClientID(grpcServiceHandler.svrConnHandler, grpcClientID);
      
        LOG(LEVEL_INFO, HDR "[SRx server] proxyID: %d --> mapping[clientID:%d] cthread: %p\n", 
          grpcClientID,  clientID, grpcServiceHandler.svrConnHandler->proxyMap[clientID].socket);

        cthread = (ClientThread*)grpcServiceHandler.svrConnHandler->proxyMap[clientID].socket;
        // in order to skip over terminating a client pthread which was not generated if grpc enabled
        cthread->active  = false;
        closeClientConnection(&grpcServiceHandler.cmdHandler->svrConnHandler->svrSock, cthread);

        //clientID = ((ClientThread*)item->client)->routerID;
        deactivateConnectionMapping(grpcServiceHandler.svrConnHandler, clientID, false, 0);
        deleteFromSList(&grpcServiceHandler.cmdHandler->svrConnHandler->clients, cthread);
        grpcServiceHandler.cmdHandler->grpcEnable = false;
        LOG(LEVEL_INFO, HDR "GoodBye!", pthread_self());
        break;

      case PDU_SRXPROXY_DELTE_UPDATE:
        //_processDeleteUpdate(cmdHandler, item);
        _processDeleteUpdate_grpc(data, &rt, grpcClientID);
        break;
      case PDU_SRXPROXY_PEER_CHANGE:
        //_processPeerChange(cmdHandler, item);
        _processPeerChange_grpc(data, &rt, grpcClientID);
        break;
      default:
        RAISE_ERROR("Unknown/unsupported pdu type: %d", bhdr->type);

        memset(pdu, 0, length);                         
        LOG(LEVEL_INFO, HDR" send Goodbye! called" );  
        hdr->type       = PDU_SRXPROXY_GOODBYE;         
        hdr->keepWindow = htons(900);            
        hdr->length     = htonl(length);                

        LOG(LEVEL_INFO, HDR "\n\nCalling CallBack function forGoodbye STREAM\n\n");         
        cb_proxyGoodBye(*hdr);
        
        // XXX: NOTE: do the same way in GoodBye above
        clientID = findClientID(grpcServiceHandler.svrConnHandler, grpcClientID);
        LOG(LEVEL_INFO, HDR "[SRx server] proxyID: %d --> mapping[clientID:%d] cthread: %p\n", 
          grpcClientID,  clientID, grpcServiceHandler.svrConnHandler->proxyMap[clientID].socket);
        cthread = (ClientThread*)grpcServiceHandler.svrConnHandler->proxyMap[clientID].socket;
        cthread->active  = false;
        closeClientConnection(&grpcServiceHandler.cmdHandler->svrConnHandler->svrSock, cthread);
        deactivateConnectionMapping(grpcServiceHandler.svrConnHandler, clientID, false, 0);
        deleteFromSList(&grpcServiceHandler.cmdHandler->svrConnHandler->clients, cthread);
        grpcServiceHandler.cmdHandler->grpcEnable = false;
        LOG(LEVEL_INFO, HDR "GoodBye!", pthread_self());
    }

    if (lv >= LEVEL_INFO) {
      printf("======= [SRx server][responseGRPC] [pdu type: %d]======= \n "
          " final Return data which will be sent to the client\n", bhdr->type);
      printHex(rt.size, rt.data);
    }
    return rt;
}




static bool sendSynchRequest_grpc()
//static bool sendSynchRequest_grpc(proxy, grpc id ...etc)
{
  bool retVal = true;
  uint32_t length = sizeof(SRXPROXY_SYNCH_REQUEST);
  SRXPROXY_SYNCH_REQUEST* pdu = malloc(length);
  memset(pdu, 0, length);

  pdu->type      = PDU_SRXPROXY_SYNC_REQUEST;
  pdu->length    = htonl(length);

      
  LOG (LEVEL_INFO, HDR "[SRx server][sendSynchRequest](Hello Resonse) using queue-command to send sync request to client ");
  if (!queueCommand(grpcServiceHandler.cmdQueue, COMMAND_TYPE_SRX_PROXY, NULL, NULL,
        0, length, (uint8_t*)pdu))
  {
    RAISE_ERROR("Could not add validation request to command queue!");
    retVal = false;
  }

  free(pdu);


  return retVal;
}









