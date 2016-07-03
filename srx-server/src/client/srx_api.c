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
 * Secure Routing extension (SRx) client API - This API provides a fully
 * functional proxy client to the SRx server.
 *
 * Version: 0.4.0.0
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.4.0.0  - 2016/06/19 - oborchert
 *            * redesigned the BGPSEC data blob and adjusted the code 
 *              accordingly
 * 0.3.0.10 - 2015/11/10 - oborchert
 *            * Removed unused variables.
 * 0.3.0    - 2013/02/27 - oborchert
 *             * Added #ifdef BZ263 for BZ263 / BZ280 handling.
 *             * Downgraded ERROR to WARNING while attempting to connect.
 *             * Changed the error management to a more broader communication 
 *               management. This resulted also in renaming some defines as well 
 *               as parameters in the proxy structure to be more meaningful.
 *             * Renamed _setProxyError into _setProxyCommCode
 *           - 2013/02/11 - oborchert
 *             * Pass local ID only if receipt flag is set in notification.
 *           - 2013/01/24 - oborchert
 *             * Added resetProxyError, _setProxyError
 *             * Fixed Segmentation fault in pLog
 *             * fixed handshake timeout
 *           - 2013/01/08 - oborchert
 *             * Added error control when server encounters buffer overflow.
 *             * Added experimental structure ProxySocketConfig;
 *           - 2012/12/17 - oborchert
 *             * Removed enumeration SRxOpMode
 *             * Added enumeration SRxProxyError
 *             * Changed signature of callback function (*ValidationReady),
 *             * Modified parameter type of callback function (*SignaturesReady)
 *             * Added  callback function (*ErrorManagement)
 *             * Modified structure of SRxProxy
 *             * Changed signature of the following functions:
 *               createProxy; deleteUpdate; connectToSRx; vreifyUpdate;
 *             * Added function:
 *               reconnectWithSRx; processPackets; getInternalSocketFD
 *
 * 0.2.0     - 2011/01/07 - oborchert
 *             * Changelog added with version 0.2.0 and date 2011/01/07
 *             * Version tag added
 * 0.1.0     - 2010/03/10 - pgleichm
 *             * Code Created
 * -----------------------------------------------------------------------------
 */
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include "client/srx_api.h"
#include "client/client_connection_handler.h"
#include "shared/srx_packets.h"
#include "util/mutex.h"
#include "util/log.h"
#include "util/socket.h"

#define HDR "( SRX API): "

static ProxyLogger _pLogger = NULL;

////////////////////////////////////////////////////////////////////////////////
// Forward declaration
////////////////////////////////////////////////////////////////////////////////
static void dispatchPackets(SRXPROXY_BasicHeader* packet, void* proxyPtr);
void callCMgmtHandler(SRxProxy* proxy, SRxProxyCommCode mainCode, int subCode);
void pLog(LogLevel level, const char* fmt, va_list args);


////////////////////////////////////////////////////////////////////////////////
// Implementation of header file
////////////////////////////////////////////////////////////////////////////////

/**
 * Creates a proxy instance and registers the callback methods for signature
 * generation and validation notification..
 *
 * @param vallidationReadyCallback The function the proxy calls to communicate
 *                   the validation result or changes in prior validation 
 *                   results to the proxy user. This can be for instance the
 *                   router or policy module, etc.
 * @param signatureReadyCallback The function, the SRx calls once the requested
 *                   signature is generated.
 * @param requestSynchronizationCallback This function is used to request a
 *                   synchronization. A call of this method should initiate a
 *                   complete validation request from the routers side to
 *                   guarantee that SRx has a complete view on the validated
 *                   data within the user.
 * @param communicationMgmtCallback This function is used to allow external
 *                   management of proxy management messages and errors by 
 *                   assigning a handler.
 * @param proxyID    The id of the proxy used during the handshake with SRx. If
 *                   SRx is requested to generate the ID this value MUST be "0"
 *                   zero.
 * @param proxyAS    The AS of the user that uses this proxy.
 *
 * @param userPtr    This parameter is used or not by the router or policy
 *                   module or other that accesses the proxy. It does not have
 *                   any meaning for SRx or the proxy itself but might be
 *                   meaningful for the software (router, policy module, etc)
 *                   that uses this API.
 *
 * @return the instance of the SRx proxy, or NULL in case of an error
 */
SRxProxy* createSRxProxy(ValidationReady   validationReadyCallback,
                         SignaturesReady   signatureReadyCallback,
                         SyncNotification  requestSynchronizationCallback,
                         SrxCommManagement communicationMgmtCallback,
                         uint32_t proxyID, uint32_t proxyAS, void* userPtr)
{
  SRxProxy* proxy;

  // Install the logging framework;
  setLogMethodToCallback(pLog);

  // Allocate the internal structure
  proxy = malloc(sizeof(SRxProxy));
  if (proxy == NULL)
  {
    RAISE_ERROR("Not enough memory to create an SRx instance!!");
    return NULL;
  }
  // Initialize it to zero
  memset(proxy, 0, sizeof(SRxProxy));

  // Initialize the member variables
  proxy->resCallback      = validationReadyCallback;
  proxy->sigCallback      = signatureReadyCallback;
  proxy->syncNotification = requestSynchronizationCallback;
  proxy->commManagement   = communicationMgmtCallback;
  resetProxyError(proxy);

  proxy->proxyAS = proxyAS;
  proxy->proxyID = proxyID;

  initSList(&proxy->peerAS);

  proxy->userPtr = userPtr;

  // Configure experimental socket configuration.
  proxy->socketConfig.enablePSC = true;
  proxy->socketConfig.maxAttempts = 25;
  proxy->socketConfig.maxSleepMillis = 1;

  proxy->socketConfig.totalCountOfMultipleAttempts = 0;
  proxy->socketConfig.sendErrors = 0;
  proxy->socketConfig.sendErrorThreshold = 300;
  proxy->socketConfig.resetSendErrors = 1000;
  proxy->socketConfig.succsessSend = 0;

  //setLogLevel(LEVEL_DEBUG);
  setLogLevel(LEVEL_ERROR);

  // By default the socket is controlled internally
  proxy->externalSocketControl = false;

  // initialize the connection handler
  proxy->connHandler = createClientConnectionHandler(proxy);

  return proxy;
}

/**
 * Disconnect proxy SRx server if necessary and frees up the memory again.
 *
 * @param proxy the proxy instance.
 */
void releaseSRxProxy(SRxProxy* proxy)
{
  if (proxy != NULL)
  {
    disconnectFromSRx(proxy, SRX_DEFAULT_KEEP_WINDOW);
    releaseSList(&proxy->peerAS);
    free(proxy->connHandler);
    free(proxy);
  }
}

/**
 * Add peers to the configuration of the proxy. In case the proxy is already
 * connected, the peer change will be communicated to SRx.
 *
 * @param proxy The proxy instance
 * @param noPeers The number of peers.
 * @param peerAS The array of peers.
 */
void addPeers(SRxProxy* proxy, uint32_t noPeers, uint32_t* peerAS)
{
  uint32_t  i;
  uint32_t* dataVal = NULL;
  // The client connection handler
  ClientConnectionHandler* connHandler =
                                   (ClientConnectionHandler*)proxy->connHandler;

  //if (connHandler->initialized)
  if (isConnected(proxy))
  {
    uint32_t pduSize = sizeof(SRXPROXY_PEER_CHANGE);
    uint32_t dataSize = noPeers * pduSize;
    uint8_t  data[dataSize];
    SRXPROXY_PEER_CHANGE* hdr = (SRXPROXY_PEER_CHANGE*)data;

    memset(data, 0, sizeof(dataSize));

    for (i = 0;i < noPeers; i++, hdr++, peerAS++)
    {
      // Create header element
      hdr->type       = PDU_SRXPROXY_PEER_CHANGE;
      hdr->changeType = SRX_PROXY_PEER_CHANGE_TYPE_ADD;
      hdr->length     = htonl(pduSize);
      hdr->peerAS     = htonl(*peerAS);

      // Add peerAS to list
      dataVal = appendToSList(&proxy->peerAS, sizeof(uint32_t));
      memcpy(dataVal, peerAS, sizeof(uint32_t));
    }

    // Send peerAS changes to SRx
    sendData(&connHandler->clSock, &data, dataSize);
  }
  else
  {
    for (i = 0;i < noPeers; i++, peerAS++)
    {
      // Add peerAS to list
      dataVal  = appendToSList(&proxy->peerAS, sizeof(uint32_t));
      *dataVal = *peerAS;
    }
  }
}

/**
 * Remove peers from the proxy configuration. In case the proxy is already
 * connected, the peer change will be communicated to SRx.
 *
 * @param proxy The proxy instance
 * @param noPeers The number of peers.
 * @param peerAS The array of peers.
 */
void removePeers(SRxProxy* proxy, uint32_t noPeers, uint32_t* peerAS)
{
  uint32_t  i;
  // The client connection handler
  ClientConnectionHandler* connHandler =
                                   (ClientConnectionHandler*)proxy->connHandler;

  //if (connHandler->initialized)
  if (isConnected(proxy))
  {
    uint32_t pduSize = sizeof(SRXPROXY_PEER_CHANGE);
    uint32_t dataSize = noPeers * pduSize;
    uint8_t  data[dataSize];
    SRXPROXY_PEER_CHANGE* hdr = (SRXPROXY_PEER_CHANGE*)data;

    memset(data, 0, sizeof(dataSize));

    hdr->type       = PDU_SRXPROXY_PEER_CHANGE;
    hdr->changeType = SRX_PROXY_PEER_CHANGE_TYPE_REMOVE;
    hdr->length     = htonl(pduSize);
    for (i = 0;i < noPeers; i++, hdr++, peerAS++)
    {
      // Create header element
      hdr->peerAS     = htonl(*peerAS);
      // Remove peerAS from list
      deleteFromSList(&proxy->peerAS, peerAS);
      sendData(&connHandler->clSock, &data, dataSize);
    }
  }
  else
  {
    for (i = 0;i < noPeers; i++, peerAS++)
    {
      // Remove peerAS from list
      deleteFromSList(&proxy->peerAS, peerAS);
    }
  }
}

/**
 * Remove peers from the proxy configuration. In case the proxy is already
 * connected, the peer change will be communicated to SRx.
 *
 * @param proxy The proxy instance
 * @param keep_window The number of seconds requested to keep the data on the
 *        server side.
 * @param updateID The ID of the update to deleted.
 */
void deleteUpdate(SRxProxy* proxy, uint16_t keep_window, SRxUpdateID updateID)
{
  // The client connection handler
  ClientConnectionHandler* connHandler =
                                   (ClientConnectionHandler*)proxy->connHandler;

  //if (connHandler->initialized && connHandler->established)
  if (isConnected(proxy))
  {
    uint32_t length = sizeof(SRXPROXY_DELETE_UPDATE);
    SRXPROXY_DELETE_UPDATE* hdr = malloc(length);

    memset(hdr, 0, length);

    hdr->type             = PDU_SRXPROXY_DELTE_UPDATE;
    hdr->keepWindow       = htons(keep_window);
    hdr->length           = htonl(length);
    hdr->updateIdentifier = htonl(updateID);

    sendData(&connHandler->clSock, hdr, length);

    free(hdr);
  }
  else
  {
    if (!connHandler->initialized)
    {
      RAISE_ERROR("Delete update [0x%08X] could not be send, Connection handler"
                  " is not initialized!", updateID);
    }
    else
    {
      RAISE_ERROR("Delete update [0x%08X] could not be send, connection to SRx"
                  " is not established!", updateID);
    }
  }
}

/**
 * Tries to establish a connection to an SRx server. The given proxy instance
 * is expected to be completely configured. Any previously established
 * connection will be ended.
 *
 * In case the connection handshake fails the connection is closed and the
 * connection handler is released.
 *
 * @param proxy The proxy instance
 * @param host Server host name
 * @param port Server port address
 * @param handshakeTimeout The time in seconds before a handshake is timed out.
 * @param externamSocketControl Allows the socket control (closing the socket)
 *                              to be done external. In this mode the socket
 *                              will be non blocking! Otherwise it will be
 *                              a blocking socket.
 *
 * @return true if connected, otherwise false if the connection failed.
 */
bool connectToSRx(SRxProxy* proxy, const char* host, int port,
                  int handshakeTimeout, bool externalSocketControl)
{
  // The client connection handler
  ClientConnectionHandler* connHandler =
                                   (ClientConnectionHandler*)proxy->connHandler;
  // Check if the connectionHandler is initialized.
  if (connHandler->initialized)
  {
    if (connHandler->stop)
    {
      LOG(LEVEL_WARNING, "Proxy [ID:%u] is already initialized and stopped!",
                  proxy->proxyID);
      return false;
    }
    else if (connHandler->established)
    {
      LOG(LEVEL_INFO, "Proxy [ID:%u] is already connected!");
      return true;
    }
  }
  else if (!initializeClientConnectionHandler(connHandler, host, port,
                                             dispatchPackets, handshakeTimeout))
  {
    RAISE_ERROR ("Proxy [ID:%u] could not be initialized - Check if server"
                      " %s:%u is accessible!", proxy->proxyID, host, port);
    return false;
  }

  if (connHandler->established)
  {
    // Maybe upgrade to RAISE_SYS_ERROR
    // If it ever reaches here the connection is unexpectedly established.
    RAISE_ERROR("BUG: Proxy [ID:%u] is unexpectedly connected to SRx, "
                "disconnect, stop proxy and return connection failed!");
    disconnectFromSRx(proxy, SRX_DEFAULT_KEEP_WINDOW);
    return false;
  }

  LOG(LEVEL_INFO, "Establish connection with proxy [%u]...", proxy->proxyID);
  uint32_t noPeers    = proxy->peerAS.size;
  uint32_t length     = 20 + (noPeers * 4);
  uint8_t  pdu[length];
  SRXPROXY_HELLO* hdr = (SRXPROXY_HELLO*)pdu;
  uint32_t peerASN    = 0;
  uint32_t* peerAS    = NULL;

  memset(pdu, 0, length);

  hdr->type            = PDU_SRXPROXY_HELLO;
  hdr->version         = htons(SRX_PROTOCOL_VER);
  hdr->length          = htonl(length);
  hdr->proxyIdentifier = htonl(proxy->proxyID);
  hdr->asn             = htonl(proxy->proxyAS);
  hdr->noPeers         = htonl(noPeers);

  peerAS = (uint32_t*)&hdr->peerAS;
  SListNode* node = getRootNodeOfSList(&proxy->peerAS);
  while (!(node == NULL))
  {
    peerASN = *((uint32_t*)node->data);
    *peerAS = htonl(peerASN);
    peerAS++;
    node = node->next;
  }

  if (handshakeWithServer(proxy->connHandler, hdr))
  {
    // connHandler->established is set in processHelloResponse
    LOG(LEVEL_INFO, "Connection with proxy [%u] established!",proxy->proxyID);
  }
  else
  {
    if (!connHandler->stop) // No Goodbye received
    {
      releaseClientConnectionHandler(connHandler);
    }

    LOG(LEVEL_ERROR, "Handshake with server (%s:%u) failed!", host, port);

    return false;
  }

  //TODO SVN No business here
  // 0: initial
  // 1: use for notifying the recv thread
  connHandler->bRecvSet = 0;

  if (connHandler->established)
  {
    proxy->externalSocketControl = externalSocketControl;

    if (externalSocketControl)
    {
      // Make socket non blocking if it isn't already
      int flags = fcntl(connHandler->clSock.clientFD, F_GETFL, 0);
      if ((flags & O_NONBLOCK) != O_NONBLOCK)
      {
        fcntl (connHandler->clSock.clientFD, F_SETFL, flags | O_NONBLOCK);
      }
      connHandler->clSock.canBeClosed = false;
    }
  }

  // IF WE GOT HERE ALL WENT WELL !
  return connHandler->established;
}

/**
 * Disconnects the proxy from the SRx Server instance on both, application and
 * transport layer.
 *
 * @param proxy The proxy instance.
 * @param keepWindow Sends a request to keep the proxy data with SRx for given
 *                   amount of seconds.
 * @param closeSocket Indicates if the underlying socket should be closed or
 *                    not.
 *
 * @return false if the given proxy is of unknown implementation, otherwise
 *         true;
 */
bool disconnectFromSRx(SRxProxy* proxy, uint16_t keepWindow)
{
  // The client connection handler
  ClientConnectionHandler* connHandler =
                                   (ClientConnectionHandler*)proxy->connHandler;
  // Macro for type casting back to the proxy.
  if (isConnected(proxy))
  {
    sendGoodbye(connHandler, keepWindow);
    connHandler->established = false;
    releaseClientConnectionHandler(connHandler);
    callCMgmtHandler(proxy, COM_PROXY_DISCONNECT, COM_PROXY_NO_SUBCODE);
  }

  return true;
}

/**
 * Returns if the proxy is connected or not.
 *
 * @param proxy The proxy itself.
 *
 * @return true if the proxy is connected, false otherwise.
 */
bool isConnected(SRxProxy* proxy)
{
  bool retVal = false;
  if (proxy != NULL)
  {
    if (proxy->connHandler != NULL)
    {
      ClientConnectionHandler* hdl=(ClientConnectionHandler*)proxy->connHandler;
      retVal = hdl->initialized && hdl->established;
    }
  }
  return retVal;
}

/**
 * Attempt to reconnect with the srx-server. This method disconnects to the
 * server on the application layer. In case the socket is managed elsewhere it
 * will not be closed. Here it is important to retrieve the socket file
 * descriptor prior calling this method. Precondition of this method is either
 * an existing connection that will be terminated* and Postcondition is a new
 * established connection to the server. The new connection will reuse the proxy
 * ID.
 *
 * @param proxy The proxy itself
 *
 * @return true if the reconnect was successful, otherwise false
 *
 * @since 0.3
 */
bool reconnectWithSRx(SRxProxy* proxy)
{
  // TODO: don't forget to clear send queue
  bool reConnected = false;
  ClientConnectionHandler* connHandler =
                                   (ClientConnectionHandler*)proxy->connHandler;

  // reconnect using  reconnectSRX of client_connection_handler
  reConnected = reconnectSRX(connHandler);

  if(reConnected)
  {
    LOG(LEVEL_DEBUG, HDR " %s: success", __FUNCTION__);
  }
  else
  {
    LOG(LEVEL_DEBUG, HDR " %s: failure", __FUNCTION__);
  }

  return reConnected;
}

/**
 * Return the internal socket descriptor. This method allows to manage the
 * socket from within the user of the API. For detailed information see the
 * users technical manual. This method only returns the internal socket
 * descriptor if the connection was established by specifying the usage of
 * external socket control. Otherwise the return value will be -1
 *
 * @param proxy The SRx-Proxy instance
 * @param main If true. it returns the main socket file descriptor. If false
 *        it returns the original file descriptor. In general both are the same
 *        except if a socket close command set the file descriptor to -1. This
 *        allows to retrieve the original file descriptor/
 *
 * @return The file descriptor of the connected socket or -1
 */
int getInternalSocketFD(SRxProxy* proxy, bool main)
{
  int socketFD = -1;

  if (proxy->externalSocketControl)
  {
    ClientConnectionHandler* connHandler =
                                   (ClientConnectionHandler*)proxy->connHandler;
    socketFD = main ? connHandler->clSock.clientFD : connHandler->clSock.oldFD;
  }

  return socketFD;
}

/**
 * Reset the error attributes of this proxy. Post condition of this function
 * is proxy->lastError=ERR_PROXY_NONE and
 * proxy->lastErrorSubCodee=PROXY_ERROR_NO_SUBCODE
 *
 * @param proxy The proxy.
 *
 * @since 0.3
 */
void resetProxyError(SRxProxy* proxy)
{
  proxy->lastCode    = COM_PROXY_NONE;
  proxy->lastSubCode = COM_PROXY_NO_SUBCODE;
}

////////////////////////////////////////////////////////////////////////////////
// Local helper functions
////////////////////////////////////////////////////////////////////////////////


void processDeleteUpdate(SRxProxy* proxy, SRXPROXY_DELETE_UPDATE* hdr);


/**
 * Create an IPv4 update validation request
 * @param pdu The allocated space for this PDU
 * @param method The verification method
 * @param rToken The request token.
 * @param defaultResult the provided result information
 * @param prefix The IPv4 prefix
 * @param as32 The origin as
 * @param bgpsec The bgpsec blob
 * @return The filled PDU
 */
uint8_t* createV4Request(uint8_t* pdu, SRxVerifyFlag method, uint32_t rToken,
                         SRxDefaultResult* defaultResult, IPPrefix* prefix,
                         uint32_t as32, BGPSecData* bgpsec)
{
  int i;
  uint32_t bgpsecLength = 0;
  uint16_t numHops      = 0;
  uint16_t attrLength   = 0;
  if (bgpsec != NULL)
  {
    bgpsecLength = (bgpsec->numberHops * 4) + bgpsec->attr_length;
    numHops      = bgpsec->numberHops;
    attrLength   = bgpsec->attr_length;
  }
  uint32_t length = sizeof(SRXPROXY_VERIFY_V4_REQUEST) + bgpsecLength; 
  SRXPROXY_VERIFY_V4_REQUEST* hdr = (SRXPROXY_VERIFY_V4_REQUEST*)pdu;

  hdr->common.type          = PDU_SRXPROXY_VERIFY_V4_REQUEST;
  hdr->common.flags         = method;
  hdr->common.roaResSrc     = defaultResult->resSourceROA;
  hdr->common.bgpsecResSrc  = defaultResult->resSourceBGPSEC;
  hdr->common.length        = htonl(length);
  hdr->common.roaDefRes     = defaultResult->result.roaResult;
  hdr->common.bgpsecDefRes  = defaultResult->result.bgpsecResult;
  hdr->common.prefixLen     = prefix->length;
  hdr->common.requestToken  = htonl(rToken);
  hdr->prefixAddress = prefix->ip.addr.v4;
  hdr->originAS      = htonl(as32);
  hdr->bgpsecLength  = htonl(bgpsecLength);
  
  // Now store the number of hops.
  hdr->bgpsecValReqData.numHops = htons(numHops);
  hdr->bgpsecValReqData.attrLen = htons(attrLength);
  if ((numHops + attrLength) != 0)
  {
    uint8_t* pduPtr = pdu + sizeof(SRXPROXY_VERIFY_V4_REQUEST);
    memcpy(pduPtr, bgpsec->asPath, (numHops*4));
    pduPtr += (numHops*4);
    memcpy(pduPtr, bgpsec->bgpsec_path_attr, attrLength);
  }
  return pdu;
}

/**
 * Create an IPv6 update validation request
 * @param pdu The allocated space for this PDU
 * @param method The verification method
 * @param defaultResult the provided result information
 * @param prefix The ipv6 prefix
 * @param as32 The origin as
 * @param bgpsec The bgpsec blob
 * @return The filled PDU
 */
uint8_t* createV6Request(uint8_t* pdu, SRxVerifyFlag method, uint32_t rToken,
                     SRxDefaultResult* defaultResult, IPPrefix* prefix,
                     uint32_t as32, BGPSecData* bgpsec)
{
  int i;
  uint32_t bgpsecLength = 0;
  uint16_t numHops      = 0;
  uint16_t attrLength   = 0;
  if (bgpsec != NULL)
  {
    bgpsecLength = (bgpsec->numberHops * 4) + bgpsec->attr_length;
    numHops      = bgpsec->numberHops;
    attrLength   = bgpsec->attr_length;
  }
  uint32_t length = sizeof(SRXPROXY_VERIFY_V6_REQUEST) + bgpsecLength; 
  
  SRXPROXY_VERIFY_V6_REQUEST* hdr = (SRXPROXY_VERIFY_V6_REQUEST*)pdu;

  hdr->common.type          = PDU_SRXPROXY_VERIFY_V6_REQUEST;
  hdr->common.flags         = method;
  hdr->common.roaResSrc     = defaultResult->resSourceROA;
  hdr->common.bgpsecResSrc  = defaultResult->resSourceBGPSEC;
  hdr->common.length        = htonl(length);
  hdr->common.roaDefRes     = defaultResult->result.roaResult;
  hdr->common.bgpsecDefRes  = defaultResult->result.bgpsecResult;
  hdr->common.prefixLen     = prefix->length;
  hdr->common.requestToken  = htonl(rToken);
  hdr->prefixAddress = prefix->ip.addr.v6;
  hdr->originAS      = htonl(as32);
  hdr->bgpsecLength  = htonl(bgpsecLength);
  
  // Now store the number of hops.
  hdr->bgpsecValReqData.numHops = htons(numHops);
  hdr->bgpsecValReqData.attrLen = htons(attrLength);
  if ((numHops + attrLength) != 0)
  {
    uint8_t* pduPtr = pdu + sizeof(SRXPROXY_VERIFY_V4_REQUEST);
    memcpy(pduPtr, bgpsec->asPath, (numHops*4));
    pduPtr += (numHops*4);
    memcpy(pduPtr, bgpsec->bgpsec_path_attr, attrLength);
  }
  
  return pdu;
}

/**
 * Verifies the given update data. All parameters except the result parameter
 * are IN parameters, result is an OUT parameter that will be filled within this
 * function. The memory MUST be allocated outside of this function.
 *
 * @param proxy The proxy instance
 * @param localID Specifies the local ID associated to this Update. This is NOT
 *                the updateID and if an update id is known, this value should
 *                be "0" zero. If the value is other than "0" zero the
 *                SRx-server WILL send a notification back, regardless if the
 *                given default result is a correct validation result or not.
 * @param usePrefixOriginVal specify if srx-server should perform a prefix
 *                origin validation.
 * @param usePpathVal specify if srx-server should perform a path validation.
 * @param defaultResult The parameter contains the default information to be
 *                used in case the validation result is not readily available.
 * @param prefix The prefix of the request. (both v4/v6 possible)
 * @param as32 Origin AS (32-bit)
 * @param bgpsec the bgpsec information.
 *
 */
void verifyUpdate(SRxProxy* proxy, uint32_t localID,
                  bool usePrefixOriginVal, bool usePathVal,
                  SRxDefaultResult* defaultResult,
                  IPPrefix* prefix, uint32_t as32,
                  BGPSecData* bgpsec)
{
  if (!isConnected(proxy))
  {
    RAISE_ERROR(HDR "Abort verify, not connected to SRx server!" ,
                pthread_self());
    return;
  }

  // Specify the verify request method.
  uint8_t method =   (usePrefixOriginVal ? SRX_FLAG_ROA : 0)
                   | (usePathVal ? SRX_FLAG_BGPSEC : 0)
                   | (localID != 0 ? SRX_FLAG_REQUEST_RECEIPT : 0);

  bool isV4 = prefix->ip.version == 4;
  // The client connection handler
  ClientConnectionHandler* connHandler =
                                   (ClientConnectionHandler*)proxy->connHandler;

  // create data packet.
  uint16_t bgpsecLength = 0;
  if (bgpsec != NULL)
  {
    bgpsecLength = (bgpsec->numberHops * 4) + bgpsec->attr_length;
  }
  uint32_t length = (isV4 ? sizeof(SRXPROXY_VERIFY_V4_REQUEST)
                          : sizeof(SRXPROXY_VERIFY_V6_REQUEST)) + bgpsecLength;
  uint8_t  pdu[length];
  uint32_t requestToken = localID;

  memset(pdu, 0, length);

  // Generate VERIFY PACKET
  if (isV4)
  {
    createV4Request(pdu, method, requestToken, defaultResult, prefix, as32, bgpsec);
  }
  else
  {
    createV6Request(pdu, method, requestToken, defaultResult, prefix, as32, bgpsec);
  }

  // Send Data
  int maxAttempt = proxy->socketConfig.enablePSC
                   ? proxy->socketConfig.maxAttempts : 1;
  int attempt = 0;
  int transmissionError = 0;
  do
  {
    attempt++;
    if(sendPacketToServer(connHandler, (SRXPROXY_PDU*)pdu, length))
    {
      // Leave the loop
      if (   proxy->socketConfig.resetSendErrors
          <= proxy->socketConfig.succsessSend)
      {
        // save one extra comparison and just reset every
        // proxy->socketConfig.resetSendErrors times the error counter.
        proxy->socketConfig.succsessSend = 0;
        proxy->socketConfig.sendErrors = 0;
      }
      else
      {
        proxy->socketConfig.succsessSend++;
      }
      break;
    }
    else
    {
      transmissionError = getLastSendError();
      if (transmissionError == EAGAIN)
      {
        if (attempt < maxAttempt)
        {
          // Brut force sleep!!!
          usleep(proxy->socketConfig.maxSleepMillis / 1000);
          // reset transmission error for next turn
          transmissionError = 0;
        }
      }
    }
  } while (transmissionError == 0);

  if (attempt > 1)
  {
    // note that this send included multiple attempts
    proxy->socketConfig.totalCountOfMultipleAttempts++;
  }

//  if (!sendPacketToServer(connHandler, (SRXPROXY_PDU*)pdu, length))
  if (transmissionError != 0)
  {
    // Count this send error
    proxy->socketConfig.sendErrors++;
    // SEt the consecutive success counter to 0
    proxy->socketConfig.succsessSend = 0;

    LOG(LEVEL_ERROR, "Failure during sending update request (error=%u)!",
                      transmissionError);

    if (connHandler->clSock.clientFD == -1)
    {
      if (proxy->connHandler != NULL)
      {
        ClientConnectionHandler* hdl=
                                   (ClientConnectionHandler*)proxy->connHandler;
        hdl->established = false;
      }
      callCMgmtHandler(proxy, COM_ERR_PROXY_CONNECTION_LOST,
                              COM_PROXY_NO_SUBCODE);
    }
    else
    {
      if (   proxy->socketConfig.sendErrorThreshold
          <= proxy->socketConfig.sendErrors)
      {
        // Send a special error
        callCMgmtHandler(proxy, COM_ERR_PROXY_COULD_NOT_SEND, -1);
        proxy->socketConfig.sendErrors = 0;
      }
      else
      {
        callCMgmtHandler(proxy, COM_ERR_PROXY_COULD_NOT_SEND, 
                                transmissionError);
      }
    }

    // Store into send queue for re-transmit later
    // TODO: Send queue might not be used anymore.
    void* dataCopy;
    dataCopy = appendToSList(&connHandler->sendQueue, (size_t)length);
    if (dataCopy == NULL)
    {
      RAISE_ERROR("ERROR, could not store update in send Queue for delayed "
                  "sending!");
    }
  }
}

/**
 * This method generates a signature request. The signature will be returned
 * using the signature notification callback.
 *
 * @param proxy Pointer to the proxy instance
 * @param updId The update id the signature is requested for
 * @param onlyOwnSignature Return only the latest signature block generated for
 *                         this BGP router, otherwise the own signatures will be
 *                         concatenated to the previous given BGPSEC data block.
 * @param algorithm        The algorithm to use.
 * @param prependCounter   Number of times the own AS will be prepended into the
 *                         path. This allows traffic engineering.
 * @param peerAS           The peer AS the update will be send to.
 *
 * @return true if sending the signature request was successful.
 */
bool signUpdate(SRxProxy* proxy, SRxUpdateID updateId, bool onlyOwnSignature,
                uint16_t algorithm, uint32_t prependCounter, uint32_t peerAS)
{
  bool retVal = true;

  uint32_t length = sizeof(SRXPROXY_SIGN_REQUEST);
  uint8_t pdu[length];
  SRXPROXY_SIGN_REQUEST* hdr = (SRXPROXY_SIGN_REQUEST*)pdu;
  memset(pdu, 0, length);
  // Assemble the PDU
  hdr->type      = PDU_SRXPROXY_SIGN_REQUEST;
  hdr->algorithm = htons(algorithm);
  hdr->blockType = onlyOwnSignature ? SRX_PROXY_BLOCK_TYPE_LATEST_SIGNATURE
                                    : 0;
  hdr->length    = htonl(length);
  hdr->updateIdentifier = htonl(updateId);
  hdr->prependCounter   = htonl(prependCounter);
  hdr->peerAS           = htonl(peerAS);

  if (!sendPacketToServer(proxy->connHandler, (SRXPROXY_PDU*)pdu, length))
  {
    RAISE_ERROR("Failure during sending signature request for update "
                "[ID:0x%08X]!", updateId);
    retVal = false;
  }

  return retVal;
}

/**
 * Set the API Proxy logger.
 *
 * @param logger The logger method. NULL for deactivation.
 *
 * @since 0.3.0
 */
void setProxyLogger(ProxyLogger logger)
{
  _pLogger = logger;
}

/**
 * Set the logging mode. The following modes are supported:
 *
 * DISABLE     = 0:
 *        All logging will be suppressed.
 * LEVEL_ERROR = 3:
 *        Non-urgent failures - these should be relayed to developers or admins;
 *        each item must be resolved within a given time
 * LEVEL_WARNING = 4:
 *        Warning messages - not an error, but indication that an error will
 *        occur if action is not taken, e.g. file system 85% full - each item
 *        must be resolved within a given time
 * LEVEL_NOTICE  = 5:
 *        Events that are unusual but not error conditions - might be summarized
 *        in an email to developers or admins to spot potential problems - no
 *        immediate action required
 * LEVEL_INFO    = 6:
 *        Normal operational messages - may be harvested for reporting,
 *        measuring throughput, etc - no action required
 * LEVEL_DEBUG   = 7:
 *
 * @param logMode the logging mode level as described above
 *
 * @return true if the logging mode could be selected, otherwise false.
 *
 * @since 0.3.0
 */
bool setLogMode(int logMode)
{
  switch (logMode)
  {
    case LEVEL_ERROR:
    case LEVEL_WARNING:
    case LEVEL_NOTICE:
    case LEVEL_INFO:
    case LEVEL_DEBUG:
      setLogLevel(logMode);
      return true;
    default:
      return false;
  }
}

////////////////////////////////////////////////////////////////////////////////
// RECEIVE AND HANDLE PACKETS - for HEADER IMPLEMENTATION
////////////////////////////////////////////////////////////////////////////////

/**
 * Finish the handshake or raise an error.
 *
 * @param hdr The "Hello Response" Header.
 * @param self The instance of the connection handler.
 */
void processHelloResponse(SRXPROXY_HELLO_RESPONSE* hdr, SRxProxy* proxy)
{
  // The client connection handler
  ClientConnectionHandler* connHandler =
                                   (ClientConnectionHandler*)proxy->connHandler;

  if (ntohs(hdr->version) == SRX_PROTOCOL_VER)
  {
    connHandler->established = true;
  }
  else
  {
    RAISE_ERROR("Protocol version between SRx [%u] and proxy [%u] differ.",
                ntohs(hdr->version), SRX_PROTOCOL_VER);
  }
}

/**
 * Server send a connection closing.
 *
 * @param hdr The "Goodbye" Header
 * @param proxy The instance of the connection handler.
 */
void processGoodbye(SRXPROXY_GOODBYE* hdr, SRxProxy* proxy)
{
  // The client connection handler
  ClientConnectionHandler* connHandler =
                                   (ClientConnectionHandler*)proxy->connHandler;
  LOG(LEVEL_DEBUG, HDR "Received Goodbye", pthread_self());
  // SERVER CLOSES THE CONNECTION. END EVERYTHING.
  connHandler->established = false;
  connHandler->stop = true;
  // First send a signal just in case someone still waiting
  // (should not be)
  // Now release connection handler.

  // remove client socket from readfs in master queue,
  // otherwise it makes select error in quagga thread
  //utilThreadControl(proxy, 5);
  //TODO: IMPORTANT - Only close connection when socket not maintained elsewhere
  releaseClientConnectionHandler(connHandler);
}

#ifdef BZ263
static int ct = 0; 
#endif

/**
 * The SRx server send a verification notification. This method uses the proxy
 * callback.
 *
 * @param hdr The "Verify Notification" Header
 * @param self The instance of the connection handler.
 */
void processVerifyNotify(SRXPROXY_VERIFY_NOTIFICATION* hdr, SRxProxy* proxy)
{
  if (proxy->resCallback != NULL)
  {
    bool hasReceipt = (hdr->resultType & SRX_FLAG_REQUEST_RECEIPT)
                      == SRX_FLAG_REQUEST_RECEIPT;
    bool useROA     = (hdr->resultType & SRX_FLAG_ROA) == SRX_FLAG_ROA;
    bool useBGPSEC  = (hdr->resultType & SRX_FLAG_BGPSEC) == SRX_FLAG_BGPSEC;

    uint32_t localID = ntohl(hdr->requestToken);
    SRxUpdateID updateID = ntohl(hdr->updateID);

#ifdef BZ263
    ct++;    
    printf("#%u - uid:0x%08x lid:0x%08X (%u)\n", ct, updateID, localID, 
           localID);
#endif
    
    if (localID > 0 && !hasReceipt)
    {
      printf(" -> ERROR, no receipt flag set.\n");
      LOG(LEVEL_WARNING, HDR "Unusual notification for update [0x%08X] with "
                         "local id [0x%08X] but receipt flag NOT SET!",
          updateID, localID);
      localID = 0;
    }
    else
    {
      LOG(LEVEL_DEBUG, HDR "Update [0x%08X] with localID [0x%08X]: %d",
                       updateID, localID, localID);
    }

    uint8_t roaResult    = useROA ? hdr->roaResult : SRx_RESULT_UNDEFINED;
    uint8_t bgpsecResult = useBGPSEC ? hdr->bgpsecResult : SRx_RESULT_UNDEFINED;
    ValidationResultType valType = hdr->resultType & SRX_FLAG_ROA_AND_BGPSEC;

    // hasReceipt ? localID : 0 is result of BZ263
    proxy->resCallback(updateID, localID, valType, roaResult, bgpsecResult,
                       proxy->userPtr);
  }
  else
  {
    LOG(LEVEL_INFO, "processVerifyNotify: NO IMPLEMENTATION PROVIDED FOR "
                    "proxy->resCallback!!!\n");
  }
}

/**
 * Process signature notification.
 * NOT IMPLEMENTED YET
 *
 * @param hdr The "Signature Notification" Header
 * @param self The instance of the connection handler.
 */
void processSignNotify(SRXPROXY_SIGNATURE_NOTIFICATION* hdr, SRxProxy* proxy)
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

/**
 * If the user of this API registered a synchNotification handler it will be
 * called now, otherwise the request will just be logged.
 *
 * @param hdr The "Synchronization Request" Header
 * @param self The instance of the connection handler.
 */
void processSyncRequest(SRXPROXY_SYNCH_REQUEST* hdr, SRxProxy* proxy)
{
  if (proxy->syncNotification != NULL)
  {
    proxy->syncNotification(proxy->userPtr);
  }
  else
  {
    LOG(LEVEL_INFO, "processSyncRequest: NO IMPLEMENTATION PROVIDED FOR "
                    "proxy->syncNotification!!!\n");
  }
}

/**
 * Set the SRx communication code
 *
 * @param proxy   The proxy the error occurred within.
 * @param mainCode the last reported communication code.
 * @param subCode the sub code of the error.
 */
void _setProxyCommCode(SRxProxy* proxy, SRxProxyCommCode mainCode, int subCode)
{
  proxy->lastCode = mainCode;
  proxy->lastSubCode = subCode;
}

/**
 * This method calls the installed error handler or creates an error log entry.
 *
 * @param proxy    The proxy the error occurred within.
 * @param mainCode The communication code itself.
 * @param subCode  A sub-code of the main code. This is dependent if it is 
 *                 used or not.
 *
 * @since 0.3
 */
void callCMgmtHandler(SRxProxy* proxy, SRxProxyCommCode mainCode, int subCode)
{
  _setProxyCommCode(proxy, mainCode, subCode);

  if (proxy->commManagement != NULL)
  {
    proxy->commManagement(mainCode, subCode, proxy->userPtr);
  }
  else
  {
    LOG(LEVEL_NOTICE, "No communication management handler installed, SRxProxy "
                      "reported communication code [%u] with sub code [%u]",
                      mainCode, subCode);
  }
}

/**
 * An error is received from SRx server.
 *
 * @param hdr The "Synchronization Request" Header
 * @param self The instance of the connection handler.
 */
void processError(SRXPROXY_ERROR* hdr, SRxProxy* proxy)
{
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

/**
 * This method is called by the thread that reads the socket. This dipatcher is
 * called for each fully received packet. Here is moment where each packet will
 * be decoded.

 * @param packet   The SRXPROXY packet header.
 * @param proxyPtr The proxy that deals with this packet.
 *
 */
static void dispatchPackets(SRXPROXY_BasicHeader* packet, void* proxyPtr)
{
  SRxProxy* proxy = (SRxProxy*)proxyPtr;

  switch (packet->type)
  {
    case PDU_SRXPROXY_HELLO_RESPONSE:
      processHelloResponse((SRXPROXY_HELLO_RESPONSE*)packet, proxy);
      break;

    case PDU_SRXPROXY_GOODBYE:
      processGoodbye((SRXPROXY_GOODBYE*)packet, proxy);
      break;

    case PDU_SRXPROXY_VERI_NOTIFICATION:
      processVerifyNotify((SRXPROXY_VERIFY_NOTIFICATION*)packet, proxy);
      break;

    case PDU_SRXPROXY_SIGN_NOTIFICATION:
      processSignNotify((SRXPROXY_SIGNATURE_NOTIFICATION*)packet, proxy);
      break;

    case PDU_SRXPROXY_SYNC_REQUEST:
      processSyncRequest((SRXPROXY_SYNCH_REQUEST*)packet, proxy);
      break;

    case PDU_SRXPROXY_ERROR:
      processError((SRXPROXY_ERROR*)packet, proxy);
      break;
    default:
      RAISE_ERROR("Dispatcher received an unknown packet type (%u)",
                  packet->type);
  }
}

/**
 * This function is called to read packets received from srx-server and process
 * them accordingly. This function allows the caller to have the packet handling
 * been done within the scope of the caller process. This is a possible blocking
 * method. It will go into a loop of receiving messages until the connection is
 * closed, lost, or all data is read.
 *
 * @param proxy The proxy instance
 *
 * @return true if the receiver loop was ended clean, false in case an error
 *              occurred.
 * @since 0.3
 */
bool processPackets(SRxProxy* proxy)
{
  bool bRetVal=true;

  ClientConnectionHandler* connHandler =
                                   (ClientConnectionHandler*)proxy->connHandler;


  bRetVal = receivePackets(getClientFDPtr(&connHandler->clSock),
                          connHandler->packetHandler, proxy, PHT_PROXY);

  if(!bRetVal)
  {
    // TODO Error handling!!
    LOG(LEVEL_DEBUG, HDR " receive error occurred ");
    //proxy->cbThreadControl(proxy, 0); same as below
    //utilThreadControl(self->srxProxy, 0); // thread_control_call() type 0: don't activate timer event
  }

  return bRetVal;
}

/**
 * Uses either the internal logging or the provided logging framework. In both
 * cases, a logger will only be called if the given level matches the log-level
 *
 * @param proxy The proxy instance
 * @param level The logging level.
 * @param fmt The format string
 * @param ... The parameters
 *
 * @since 0.3.0
 */
void pLog(LogLevel level, const char* fmt, va_list args)
{
  if (_pLogger != NULL)
  {
    // Use the provided logger but only if there is something to log.
    if (level <= getLogLevel())
    {
      _pLogger((int)level, fmt, args);
    }
  }
  else
  {
    // fix for BZ 264
    // Use the default logger but only if there is something to log.
    if (level <= getLogLevel())
    { // Fix for BZ264
      printf("\r");
      vprintf(fmt, args);
      printf("\n");
    }
  }
}

/** 
 * Determines if the given code is an error code or not.
 * 
 * @param mainCode The code to be checked for an error.
 * 
 * @return true if the given code is an error. 
 * 
 * @since 0.3.0
 */
bool isErrorCode(SRxProxyCommCode code)
{
  // Error codes are between 0..127
  return (code & 0x7F) == code;
}
