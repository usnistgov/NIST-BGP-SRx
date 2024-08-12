
#include <stdio.h>
#include "client/grpc_client_service.h"
#include "client/client_connection_handler.h"
#define HDR  "(GRPC_Client_ServiceHandler): "


static void dispatchPackets_grpc(SRXPROXY_BasicHeader* packet, void* proxyPtr);

extern SRxProxy* g_proxy;


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



void processVerifyNotify_grpc(SRXPROXY_VERIFY_NOTIFICATION* hdr)
{
    //LOG(LEVEL_DEBUG, HDR "+++ [%s] called in proxy: %p \n", __FUNCTION__, g_proxy);
    SRxProxy* proxy = g_proxy;

    //printHex(sizeof(SRXPROXY_VERIFY_NOTIFICATION), (unsigned char*)hdr);

    if (proxy)
    {
        if (proxy->resCallback != NULL)
        {
            bool hasReceipt = (hdr->resultType & SRX_FLAG_REQUEST_RECEIPT)
                == SRX_FLAG_REQUEST_RECEIPT;
            bool useROA     = (hdr->resultType & SRX_FLAG_ROA) == SRX_FLAG_ROA;
            bool useBGPSEC  = (hdr->resultType & SRX_FLAG_BGPSEC) == SRX_FLAG_BGPSEC;
            bool useASPA    = (hdr->resultType & SRX_FLAG_ASPA) == SRX_FLAG_ASPA;

            uint32_t localID = ntohl(hdr->requestToken);
            SRxUpdateID updateID = ntohl(hdr->updateID);

#ifdef BZ263
            ct++;
            //LOG(LEVEL_DEBUG, HDR "#%u - uid:0x%08x lid:0x%08X (%u)\n", ct, updateID, localID,
            //        localID);
#endif

            if (localID > 0 && !hasReceipt)
            {
                LOG(LEVEL_DEBUG, HDR " -> ERROR, no receipt flag set.\n");
                LOG(LEVEL_WARNING, HDR "Unusual notification for update [0x%08X] with "
                        "local id [0x%08X] but receipt flag NOT SET!",
                        updateID, localID);
                localID = 0;
            }
            else
            {
                //LOG(LEVEL_DEBUG, HDR "Update [0x%08X] with localID [0x%08X]: %d",
                //        updateID, localID, localID);
            }

            uint8_t roaResult    = useROA ? hdr->roaResult : SRx_RESULT_UNDEFINED;
            uint8_t bgpsecResult = useBGPSEC ? hdr->bgpsecResult : SRx_RESULT_UNDEFINED;
            uint8_t aspaResult   = useASPA ? hdr->aspaResult : SRx_RESULT_UNDEFINED;
            ValidationResultType valType = hdr->resultType & SRX_FLAG_ROA_BGPSEC_ASPA;

            // hasReceipt ? localID : 0 is result of BZ263  // in qsrx, calls handleSRxValidationResult()
            proxy->resCallback(updateID, localID, valType, roaResult, bgpsecResult,
                       aspaResult, proxy->userPtr); // call handleSRxValidationResult
        }
        else
        {
            LOG(LEVEL_INFO, "processVerifyNotify: NO IMPLEMENTATION PROVIDED FOR "
                    "proxy->resCallback!!!\n");
        }
    }
    else
    {
        LOG(LEVEL_WARNING, HDR "this client doens't have a proxy pointer set, maybe due to simple test\n");
    }
}

void processGoodbye_grpc(SRXPROXY_GOODBYE* hdr)
{
    LOG(LEVEL_INFO, HDR "+++ [%s] called in proxy: %p ", __FUNCTION__, g_proxy);
    SRxProxy* proxy = g_proxy;

  
    LOG(LEVEL_INFO, HDR "Release SRx Proxy flags and Connection Handler's flags");
    if (proxy)
    {
        // The client connection handler
        ClientConnectionHandler* connHandler =
            (ClientConnectionHandler*)proxy->connHandler;
        LOG(LEVEL_DEBUG, HDR "Received Goodbye", pthread_self());
        // SERVER CLOSES THE CONNECTION. END EVERYTHING.
        connHandler->established = false;
        connHandler->stop = true;

        proxy->grpcClientEnable = false;  
        proxy->grpcConnectionInit = false;

        //releaseClientConnectionHandler(connHandler);

        // It is possible to receive a Goodbye during handshake in this case the 
        // connection handler is NOT initialized yet. The main process is still in 
        // init process and the init process has to cleanup.
        if (connHandler->initialized)
        {
            // Do not receive or try to connect anymore
            connHandler->stop = true;

            // Make sure the SIGINT does not terminate the program
            signal(SIGINT, SIG_IGN); // Ignore the signals


            // Reinstall the default signal handler
            signal(SIGINT, SIG_DFL);

            // Deallocate the send queue and lock
            acquireWriteLock(&connHandler->queueLock);
            releaseSList(&connHandler->sendQueue);
            releaseRWLock(&connHandler->queueLock);

            // Deallocate The packet receive monitor
            if (connHandler->rcvMonitor != NULL)
            {
                pthread_mutex_destroy(connHandler->rcvMonitor);
                free(connHandler->rcvMonitor);
                connHandler->rcvMonitor = NULL;
            }

            if (connHandler->cond != NULL)
            {
                pthread_cond_destroy(connHandler->cond);
                free(connHandler->cond);
                connHandler->cond       = NULL;
            }
        }
    }
    else
    {
        LOG(LEVEL_WARNING, HDR "this client doens't have a proxy pointer set, maybe due to simple test\n");
    }

}

void processSyncRequest_grpc(SRXPROXY_SYNCH_REQUEST* hdr)
{
    LOG(LEVEL_INFO, HDR "++ [%s] called in proxy: %p \n", __FUNCTION__, g_proxy);
    SRxProxy* proxy = g_proxy;

    if (proxy)
    {
        if (proxy->syncNotification != NULL)
        {
            proxy->syncNotification(proxy->userPtr);  // call --> handleSRxSynchRequest()
        }
        else
        {
            LOG(LEVEL_INFO, "processSyncRequest: NO IMPLEMENTATION PROVIDED FOR "
                    "proxy->syncNotification!!!\n");
        }
    }
    else{

        LOG(LEVEL_WARNING, HDR "this client doens't have a proxy pointer set, maybe due to simple test\n");
    }
}

void processSignNotify_grpc(SRXPROXY_SIGNATURE_NOTIFICATION* hdr)
{
    LOG(LEVEL_DEBUG, HDR "+++ [%s] called in proxy: %p \n", __FUNCTION__, g_proxy);
    SRxProxy* proxy = g_proxy;
    
    if (proxy)
    {
        // @TODO: Finishe the implementation with the correct data.
        if (proxy->sigCallback != NULL)
        {
            LOG(LEVEL_INFO, "processSignNotify: NOT IMPLEMENTED IN THIS PROTOTYPE!!!\n");
            SRxUpdateID updId = hdr->updateIdentifier;
            //TODO finish processSigNotify - especially the bgpsec data
            BGPSecCallbackData bgpsecCallback;
            bgpsecCallback.length = 0;
            bgpsecCallback.data = NULL;
            proxy->sigCallback(updId, &bgpsecCallback, proxy->userPtr);
        }
        else
        {
            LOG(LEVEL_INFO, "processSignNotify: NO IMPLEMENTATION PROVIDED FOR "
                    "proxy->sigCallback!!!\n");
        }
    }
}




extern void callCMgmtHandler(SRxProxy* proxy, SRxProxyCommCode mainCode, int subCode);

void processError_grpc(SRXPROXY_ERROR* hdr)
{
  LOG(LEVEL_INFO, HDR "+++ [%s] called in proxy: %p ", __FUNCTION__, g_proxy);
  SRxProxy* proxy = g_proxy;

  uint32_t errCode = ntohs(hdr->errorCode);
  switch (errCode)
  {
    case SRXERR_WRONG_VERSION:
      LOG(LEVEL_ERROR, "SRx server reports compatibility issues in the "
          "communication protocol!");
      callCMgmtHandler(proxy, COM_ERR_PROXY_COMPATIBILITY,
          COM_PROXY_NO_SUBCODE);
      break;
    case SRXERR_DUPLICATE_PROXY_ID:
      LOG(LEVEL_ERROR, "SRx server reports a conflict with the proxy id!");
      callCMgmtHandler(proxy, COM_ERR_PROXY_DUPLICATE_PROXY_ID,
          COM_PROXY_NO_SUBCODE);
      break;
    case SRXERR_INVALID_PACKET:
      LOG(LEVEL_ERROR, "SRx server received an invalid packet!");
      callCMgmtHandler(proxy, COM_ERR_PROXY_SERVER_ERROR, SVRINVPKG);
      break;
    case SRXERR_INTERNAL_ERROR:
      LOG(LEVEL_ERROR, "SRx server reports an internal error!");
      callCMgmtHandler(proxy, COM_ERR_PROXY_SERVER_ERROR, SVRINTRNL);
      break;
    case SRXERR_ALGO_NOT_SUPPORTED:
      LOG(LEVEL_ERROR, "SRx server reports the requested signature algorithm "
          "is not supported!");
      callCMgmtHandler(proxy, COM_ERR_PROXY_UNKNOWN_ALGORITHM,
          COM_PROXY_NO_SUBCODE);
      break;
    case SRXERR_UPDATE_NOT_FOUND:
      LOG(LEVEL_NOTICE, "SRx server reports the last delete/signature request "
          "was aborted, the update could not be found!");
      callCMgmtHandler(proxy, COM_ERR_PROXY_UNKNOWN_UPDATE,
          COM_PROXY_NO_SUBCODE);
      break;
    default:
      RAISE_ERROR("SRx server reports an unknown Error(%u)!", errCode);
      callCMgmtHandler(proxy, COM_ERR_PROXY_UNKNOWN, errCode);
  }
}
