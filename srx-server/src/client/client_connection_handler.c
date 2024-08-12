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
 * The Original implementation kept data in a queue in case the TCP connection
 * is not up anymore. This should be held transparent to this layer of
 * communication. In addition the design does NOT 
 *
 * The original idea of the sending queue was for the mode of send ad forget
 * about it to allow the router to dump a table to the SRx without having to
 * wait until each packet is send. The question here is:
 *
 * Do we really need that or can we just wait. I am not sure how long it would
 * take to send. The queue is anyhow max 100 entries wide and if it is for
 * performance issues than 100 are not enough anyhow, the queue then will slowly
 * fill up. If we need more than we have a memory issue.
 *
 * I guess we can wait at least for each one to be send at a time. If we can not
 * wait for the receipt then the proxy needs to generate the id and the receipt
 * will be ignored. (maybe a list with id and results and if they match, then
 * don't notify the router).
 *
 * Maybe the Verify Request  can use the zero field for indication if the
 * receipt is needed. (A dangerous game though)
 *
 * GET RID OFF SEND QUEUE ??
 *
 * Version 0.6.1.2
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.6.1.2  - 2021/11/18 - kyehwanl
 *            * Fixed bug in LOG print.
 * 0.3.0.10 - 2015/11/10 - oborchert
 *            * Removed un-used static function _suppressSIGINT. It was already
 *              replaced with SIG_IGN. 
 * 0.3.0    - 2013/02/27 - oborchert
 *            * Added Change log
 *            * Changed volatile attribute _handshakeSocket from int to pointer 
 *              of int. This allows a correct maintenance of the sockets file
 *              descriptor.
 *            * Removed setting of established. Is already maintained in srx_api.
 * 0.2.0    - 2011/11/01 - oborchert
 *            * rewritten
 * 0.1.0    - 2010/04/07 - pgleichm
 *            * Code Created
 * -----------------------------------------------------------------------------
 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include "client/client_connection_handler.h"
#include "shared/srx_packets.h"
#include "util/client_socket.h"
#include "util/log.h"
#include "util/mutex.h"
#include "util/socket.h"

/** Seconds between reconnect attempts */
#define RECONNECT_DELAY 2

/** THis value is used to prevent a deadlock during initialization and data
 * receiving. The data receiving waits in 1 seconds intervals until the client
 * connection handler is initialized. This wait could create a deadlock,
 * therefore the wait is reduced to a maximum of DEADLOCK_INDICATOR in seconds
 */
#define DEADLOCK_INDICATOR 30

/** Maximum attempts to connect to server during a connection request */
#define MAX_RECONNECT_ATTEMPT 2

/** Max. entries in the send queue */
#define MAX_SEND_QUEUE  100000

#define HDR "([0x%08X] Client Connection Handler): "

////////////////////////////////////////////////////////////////////////////////
// Status variables for handshake timeout - since 0.3.0
////////////////////////////////////////////////////////////////////////////////
/** Used to determine if a handshake timeout occured. */
volatile int _handshakeAlarm=0;
/** used to close a handshake-timed out socket  */
volatile int* _handshakeSocket=NULL;

////////////////////////////////////////////////////////////////////////////////
// Implementation of header file
////////////////////////////////////////////////////////////////////////////////
/**
 * Create the clientConnectionHandler by allocating the memory and setting
 * certain values to a pre-initialized state. The memory of the
 * ClientConnectionHandler MUST be freed by the caller of this method!!!
 *
 * @return an instance of ClientConnectionHandler of NULL.
 */
ClientConnectionHandler* createClientConnectionHandler(SRxProxy* proxy)
{
  if (proxy == NULL)
  {
    return NULL;
  }

  // Allocate the memory
  ClientConnectionHandler* self = malloc(sizeof(ClientConnectionHandler));

  if (self != NULL)
  {
    // Set the default values - uninitialized!!
    self->initialized = false;
    self->established = false;
    self->keepWindow  = SRX_DEFAULT_KEEP_WINDOW;
    // The connHandler->cond and connHandler->rcvMonitor are created, initialized
    // and released in the connection handlers init and release method
    self->cond        = NULL;
    self->rcvMonitor  = NULL;

    // Set default socket parameters
    self->clSock.type = SRX_PROXY_CLIENT_SOCKET;
    self->clSock.clientFD = -1;
    self->clSock.oldFD = -1;
    self->clSock.reconnect = false;
    self->clSock.canBeClosed = true;
    
    self->srxProxy = proxy;
  }
  
  return self;
}

/**
 * Initialized the client connection handler used by the SRx Proxy to connect 
 * to the SRx server. The instance must be created elsewhere. This method 
 * requires the attribute initialized to be set to false. Best is to have the
 * Handler created using the here provided create method.
 * Once set to true the instance must never be initialized again. The attribute
 * initialized will be set to true once this method exits with true.
 * This method also created the client socket but does NOT attempt to connect
 * the transport layer. This is done using the connectToSRx method.
 *
 * @param self             Instance that should be be initialized.
 * @param host             Server host name.
 * @param port             Server port address.
 * @param packetHandler    Received packets are passed to this function.
 * @param handshakeTimeout The time in seconds a handshake MUST be completed.
 *
 * @return true = connection established and handshake performed,
 *         false = failed to connect.
 *
 * @see releaseClientConnectionHandler
 */
bool initializeClientConnectionHandler(ClientConnectionHandler* self,
                                       const char* host, int port,
                                       SRxPacketHandler packetHandler,
                                       uint32_t handshakeTimeout)
{
  char* errPrefix = "[ClientConnectionHandler]";
  int iSemState =0;
  pthread_attr_t attr;

  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
 
  // already initialized
  if (self->initialized)
  {
    RAISE_ERROR("%s instance is already initialized!", errPrefix);
    return false;
  }

  // Initialize the client socket - This also creates it. By default the socket
  // can be closed.
  if (!createClientSocket(&self->clSock, host, port, true,
                          SRX_PROXY_CLIENT_SOCKET, true))
  {
    RAISE_ERROR("%s Could not create and initialize the client socket.!",
                errPrefix);
    return false;
  }

  if (!createRWLock(&self->queueLock))
  {
    closeClientSocket(&self->clSock);
    RAISE_ERROR("%s Could not aquire read write lock!", errPrefix);
    return false;
  }

  initSList(&self->sendQueue);

  // Set misc. variables
  self->packetHandler     = packetHandler;
  self->stop              = false;
  self->handshake_timeout = handshakeTimeout;
  
  // binary counter semaphore: inter-process shared: no,  initial value: 0
  iSemState = sem_init(&self->sem_transx, 0, 1); 
  if(iSemState != 0) 
  {
    RAISE_ERROR("%s Failed to create the semaphore", errPrefix);
    return false;
  }

  // binary counter semaphore: inter-process shared: no,  inital value: 0 
  iSemState = sem_init(&self->sem_register, 0, 0); 
  if(iSemState != 0) 
  {
    RAISE_ERROR("%s Failed to create the semaphore", errPrefix);
    return false;
  }
 
  // binary counter semaphore: inter-process shared: no,  inital value: 1 
  iSemState = sem_init(&self->sem_crit_sec, 0, 1); 
  if(iSemState != 0) 
  {
    RAISE_ERROR("%s Failed to create the semaphore", errPrefix);
    return false;
  }
 
  // Create the receive lock.
  self->cond       = (pthread_cond_t*)malloc(sizeof(pthread_cond_t));
  self->rcvMonitor = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
  
  // Initialize the receive lock.
  pthread_cond_init(self->cond, NULL);
  initMutex(self->rcvMonitor);

  // Instance is initialized and connected on TCP layer...
  self->initialized = true;
  // ... but not on application layer yet! This is to be done in the proxy.
  self->established = false;


  return true;
}

/**
 * Closes the connection to the server.
 *
 * @param self Instance that should be used
 */
void releaseClientConnectionHandler(ClientConnectionHandler* self)
{
  if (self != NULL)
  {
    // It is possible to receive a Goodbye during handshake in this case the 
    // connection handler is NOT initialized yet. The main process is still in 
    // init process and the init process has to cleanup.
    if (self->initialized)
    {
      // Do not receive or try to connect anymore
      self->stop = true;
      
      // Make sure the SIGINT does not terminate the program
      signal(SIGINT, SIG_IGN); // Ignore the signals

      if (self->established)
      {
        // disconnect on application layer.
        sendGoodbye(self, self->keepWindow);
      }

      //pthread_kill(self->recvThread, SIGINT);
      //pthread_cancel(self->recvThread);

      //Closing only if socket not maintained elsewhere - handled inside method
      closeClientSocket(&self->clSock);

      // Reinstall the default signal handler
      signal(SIGINT, SIG_DFL);

      // Deallocate the send queue and lock
      acquireWriteLock(&self->queueLock);
      releaseSList(&self->sendQueue);
      releaseRWLock(&self->queueLock);

      // Deallocate The packet receive monitor
      if (self->rcvMonitor != NULL)
      {
        pthread_mutex_destroy(self->rcvMonitor);
        free(self->rcvMonitor);
        self->rcvMonitor = NULL;
      }
      
      if (self->cond != NULL)
      {
        pthread_cond_destroy(self->cond);
        free(self->cond);
        self->cond       = NULL;
      }
    }
  }
}


////////////////////////////////////////////////////////////////////////////////
// METHODS FOR WAIT AND NOTIFY
////////////////////////////////////////////////////////////////////////////////


/**
 * This method waits until data is received. It is expected that the lock is
 * already set.
 *
 * @param self The connection handler to wait on.
 *
 * @return true if the wait could be executed, otherwise false.
 */
inline bool connHandlerWait(ClientConnectionHandler* self)
{
  bool retVal = false;
  if (self->cond != NULL)
  {
    LOG(LEVEL_DEBUG, HDR "connHandlerWait enter", pthread_self());
    pthread_cond_wait(self->cond, self->rcvMonitor);
    LOG(LEVEL_DEBUG, HDR "connHandlerWait exit", pthread_self());
    retVal = true;
  }
  return retVal;
}

/**
 * This method waits until data is received. It is expected that the lock is
 * already set.
 *
 * @param self The Client connection handler.
 *
 * @return true if the notify could be send, otherwise false.
 */
inline bool connHandlerNotify(ClientConnectionHandler* self)
{
  bool retVal = false;
  if (self->cond != NULL)
  {
    LOG(LEVEL_DEBUG, HDR "connHandlerNotify", pthread_self());
    pthread_cond_signal(self->cond);
    retVal = true;
  }
  return retVal;
}

/**
 * This method locks the mutex for wait and notification
 *
 * @param self The Client connection handler.
 *
 * @return true if the lock could be taken.
 */
inline bool connHandlerLock(ClientConnectionHandler* self)
{
  bool retVal = false;
  if (self->rcvMonitor != NULL)
  {
    LOG(LEVEL_DEBUG, HDR "connHandlerLock", pthread_self());
    lockMutex(self->rcvMonitor);
    retVal = true;
  }
  return retVal;
}

/**
 * This method unlocks the mutex for wait and notification
 *
 * @param self The Client connection handler.
 *
 * @return true if the lock could be removed.
 */
inline bool connHandlerUnlock(ClientConnectionHandler* self)
{
  bool retVal = false;
  if (self->rcvMonitor != NULL)
  {
    LOG(LEVEL_DEBUG, HDR "connHandlerUnlock", pthread_self());
    pthread_mutex_unlock(self->rcvMonitor);
    retVal = true;
  }
  return retVal;
}

////////////////////////////////////////////////////////////////////////////////
// METHODS USED TO SEND
////////////////////////////////////////////////////////////////////////////////

/**
 * Sends a packet to the server. If the TCP connection is down but the
 * application layer connection is established, the packet might be queued.
 *
 * @param self Instance that should be used
 * @param data The proxySRX PDU to be send.
 * @param length Data size in bytes. This method does not read the header length
 *               field, it goes with the length provided. This can allow to
 *               send a stream of multiple pdu's at once.
 * @return true = data sent successfully, false = sending failed
 *         (e.g. no connection)
 */
bool sendPacketToServer(ClientConnectionHandler* self, void* data,
                        uint32_t length)
{
  if (isConnectedToServer(&self->clSock))
  {
    // This can contain more than one packet depending on the length and content
    // of the header.
    return sendData(&self->clSock, data, length);
    // Not online - store a copy and send later
  }
  else if (self->established) // Application layer connected.
  {
    void* dataCopy;

    // Check if the queue is not already full
    acquireReadLock(&self->queueLock);

    if (sizeOfSList(&self->sendQueue) == MAX_SEND_QUEUE)
    {
        unlockReadLock(&self->queueLock);

        return false;
    }

    // Store
    changeReadToWriteLock(&self->queueLock);

    dataCopy = appendToSList(&self->sendQueue, (size_t)length);

    unlockWriteLock(&self->queueLock);

    if (dataCopy == NULL)
    {
      return false;
    }

    memcpy(dataCopy, data, length);
  }

  return true;
}

/**
 * Handler to catch the timeout alarm for handshake.
 * 
 * @param sig The signal
 * 
 * @since 0.3.0 
 */
void _catch_handshakeTimeout(int sig)
{
  _handshakeAlarm = 1;      // set timeout indicator
  close(*_handshakeSocket); // unblocks the read
  *_handshakeSocket = -1;
}

/*
 * Create the connection of application layer between srx and proxy. This method
 * uses active waiting (1 sec. at a time) for max 30 seconds
 *
 * @param clSock The socket to be used to talk to the server
 * @param noPeers The number of peers this proxy contains
 * @param peerAS the peer numbers
 * @return true if the handshake was successful.
 */
bool handshakeWithServer(ClientConnectionHandler* self, SRXPROXY_HELLO* pdu)
{  
  // Send 'HELLO' to the server
  if (!sendData(&self->clSock, (void*)pdu, ntohl(pdu->length)))
  {
    return false;
  }

  LOG(LEVEL_DEBUG, HDR "Wait for Handshake to complete...", pthread_self());
        
  // prepare handshake
  _handshakeAlarm  = 0;
  _handshakeSocket = &self->clSock.clientFD;
  __sighandler_t oldHandler = NULL;
  int oldAlarmTimer = 0;
  
  if (self->handshake_timeout)
  {
    // Retrieve the old settings and set the new ones
    oldAlarmTimer = alarm(0);
    oldHandler = signal(SIGALRM, _catch_handshakeTimeout);    
    // Set the alarm
    alarm(self->handshake_timeout);    
  }
  
  // The call returns with one packet received. Ideally it is the HelloResponse
  // but it also could be an Error. In this case we need to go back and receive
  // more.
  SRxProxyCommCode mainCode;
  bool isError = false;
  while (!isError && !isConnected(self->srxProxy)) 
  {
    // First clear all previous errors if any
    resetProxyError(self->srxProxy);
    receivePackets(getClientFDPtr(&self->clSock), self->packetHandler, 
                                  self->srxProxy, PHT_PROXY);
    mainCode = self->srxProxy->lastCode;
    isError = isErrorCode(mainCode);

    if (isError)
    {
      LOG(LEVEL_ERROR, "SRx-Server reported Error[%u] with sub code[%i]", 
                       mainCode, self->srxProxy->lastSubCode);
    }
    if (_handshakeAlarm == 1)
    {
      self->established = false; // timed out
      LOG(LEVEL_NOTICE, "Handshake timed out!!");
      break;
    }
  }

  // Turn off timeout and reset alarm to old settings.
  if (self->handshake_timeout > 0)
  {
    alarm(0);
    signal(SIGALRM, oldHandler);
    alarm(oldAlarmTimer);
    _handshakeAlarm=0;
    _handshakeSocket=NULL;
  }
  
  if (!self->established)
  {
    LOG(LEVEL_DEBUG, HDR "...Handshake %s!", pthread_self(), (self->established 
                                                              ? "suceeded"
                                                              : "failed"));
  }
    
  return self->established;
}

/**
 * Send the goodbye message to the server. This message is done by directly
 * calling the sendData method without using the sendPacketToServer method.
 * Most likely after a goodbye the socket will be closed right away and all
 * buffers are emptied!
 *
 * The attribute "established" will be set to false due to the fact that this
 * message the application layer connection closes. (only if the function
 * returns true)
 *
 * @param self The pointer to the client connection handler.
 * @param keepWindow the keep window value.
 *
 * @return true if the message could be send, otherwise false.
 */
bool sendGoodbye(ClientConnectionHandler* self, uint16_t keepWindow)
{
  uint32_t length = sizeof(SRXPROXY_GOODBYE);
  uint8_t pdu[length];
  SRXPROXY_GOODBYE* hdr = (SRXPROXY_GOODBYE*)pdu;
  memset(pdu, 0, length);

  LOG(LEVEL_DEBUG, HDR" send Goodbye! called", pthread_self());
  hdr->type       = PDU_SRXPROXY_GOODBYE;
  hdr->keepWindow = htons(keepWindow);
  hdr->length     = htonl(length);

  if (isConnectedToServer(&self->clSock))
  {
    if (sendData(&self->clSock, &pdu, length))
    {
      self->established = false;
      return true;
    }
  }

  return false;
}

#ifdef USE_GRPC
#include "client/libsrx_grpc_client.h"
bool sendGoodbye_grpc(ClientConnectionHandler* self, uint16_t keepWindow)
{
  uint32_t length = sizeof(SRXPROXY_GOODBYE);
  uint8_t pdu[length];
  SRXPROXY_GOODBYE* hdr = (SRXPROXY_GOODBYE*)pdu;
  memset(pdu, 0, length);

  hdr->type       = PDU_SRXPROXY_GOODBYE;
  hdr->keepWindow = htons(keepWindow);
  hdr->length     = htonl(length);

  LOG(LEVEL_INFO, HDR"+ send Goodbye! called", pthread_self());
  LOG(LEVEL_INFO, HDR"+ [%s] :%d \n", pthread_self(), __FUNCTION__, __LINE__);

  RunProxyGoodBye(*hdr, self->grpcClientID);
  self->established = false;

  return true;
}

typedef struct {
    SRxProxy* proxy;
    uint32_t proxyID;
} StreamThreadData;

// Imple GoStreamThread called for thread process
//
static void* GoodByeStreamThread(void *arg)
{
    StreamThreadData *std = (StreamThreadData*)arg;
  
    LOG(LEVEL_INFO, HDR "Run Proxy Good Bye Stream", pthread_self());
    printf("Run Proxy Good Bye Stream \n");
    printf("[%s:%d] arguments proxy: %p, proxyID: %08x\n", __FUNCTION__, __LINE__, std->proxy, std->proxyID);

    while(!std->proxy->grpcClientEnable)
    {
        sleep(1);
    }

    // This is dummy data for initiating stream operation to use grpc tranortation
    char buff_goodbye_stream_request[12] = {0x02, 0x03, 0x84, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0c};
    /* 
      typedef struct {                           
        uint8_t   type;              // 2        
        uint16_t  keepWindow;                    
        uint8_t   reserved8;                     
        uint32_t  zero32;                        
        uint32_t  length;            // 12 Bytes 
      } __attribute__((packed)) SRXPROXY_GOODBYE;
    */

    GoSlice goodbye_stream_pdu = {(void*)buff_goodbye_stream_request, (GoInt)12, (GoInt)12};
    int result = RunProxyGoodByeStream (goodbye_stream_pdu, std->proxyID);

    printf("Run Proxy Good Bye Stream terminated with result value: %d\n", result);
    

    // XXX: here general closure procedures by receiving GoodBye
    //  relase proxy function is blocked, because reconnect function needs to have the proxy pointer,
    //  so it should not be removed inside release SRxProxy ()
    //
    //releaseSRxProxy(std->proxy);
}

// This function for Proxy SyncRequest, Sign Notification and so on
//
static void* StreamThread(void *arg)
{
    StreamThreadData *std = (StreamThreadData*)arg;
    printf("Run Proxy Stream \n");
    printf("[%s:%d] arguments proxy: %p, proxyID: %08x\n", __FUNCTION__, __LINE__, std->proxy, std->proxyID);

    //while(!std->proxy->grpcClientEnable)
    {
     //   sleep(1);
    }

    // This is dummy data for initiating stream operation to use grpc tranortation
    char buff_stream_request[12] = {0x02, 0x00, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0c};
    GoSlice stream_pdu = {(void*)buff_stream_request, (GoInt)12, (GoInt)12};
    int result = RunProxyStream (stream_pdu, std->proxyID);

    printf("Run Proxy Stream terminated \n");

}

static void* WorkerPoolThread(void *arg)
{

    //bool ret = InitWorkerPool();
}

void ImpleGoStreamThread (SRxProxy* proxy, uint32_t proxyID)
{
    pthread_t tid, tid2, tid3;
    pthread_attr_t attr, attr2, attr3;
    pthread_attr_init(&attr);
    pthread_attr_init(&attr2);
    pthread_attr_init(&attr3);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setdetachstate(&attr2, PTHREAD_CREATE_DETACHED);
    pthread_attr_setdetachstate(&attr3, PTHREAD_CREATE_DETACHED);
    printf("+ pthread grpc service started...\n");


    StreamThreadData *std = (StreamThreadData*)malloc(sizeof(StreamThreadData));
    std->proxy = proxy;
    std->proxyID = proxyID;
    printf("[%s:%d] arguments proxy: %p, proxyID: %08x\n", __FUNCTION__, __LINE__, std->proxy, std->proxyID);

    int ret = pthread_create(&tid, &attr, GoodByeStreamThread, (void*)std);
    if (ret != 0)
    {
        RAISE_ERROR("Failed to create a grpc thread");
    }
    printf("+ GoodBye Stream Thread created \n");
    pthread_join(tid, NULL);



    int ret2 = pthread_create(&tid2, &attr2, StreamThread, (void*)std);
    if (ret2 != 0)
    {
        RAISE_ERROR("Failed to create a grpc thread");
    }
    printf("+ Stream Thread for notification created \n");
    pthread_join(tid2, NULL);


    /*
    int ret3 = pthread_create(&tid3, &attr3, WorkerPoolThread, (void*)NULL);
    if (ret3 != 0)
    {
        RAISE_ERROR("Failed to create a grpc workerPoll thread");
    }
    printf("+ Worker Pool Thread created \n");
    pthread_join(tid3, NULL);
    */
    
    printf("+ All Go Stream Threads Terminated \n");
}


#endif // USE_GRPC
////////////////////////////////////////////////////////////////////////////////
// Local helper functions
////////////////////////////////////////////////////////////////////////////////

/**
 * This method allows to re-establish a connection between proxy and srx-server
 * this method will close an existing connection to the srx server on the
 * application layer sending a GoodBye message and if the socket is not
 * maintained externally it closes the socket. In case the socket is managed
 * outside the socket will not be closed but a new one will be installed.
 * The reconnect will result in a handshake. The new socket will have the
 * same features as the old one. A ClientConnectionHandler can only be restarted
 * if it was not stopped.
 *
 * @param self The ClientConnection handler.
 *
 * @return true if the reconnect was successful, otherwise false.
 */
bool reconnectSRX(ClientConnectionHandler* self)
{
  bool retVal = false;
  SRxProxy* proxy = (SRxProxy*)self->srxProxy;

  LOG (LEVEL_INFO, "([0x%08X]) > Client Connection Handler Thread started!",
                     pthread_self());
  
  if (self->initialized && !self->stop)
  {
    // Check if the client socket was miss used
    if (self->clSock.oldFD != -1 && self->clSock.clientFD == -1)
    {
      self->clSock.clientFD = self->clSock.oldFD;
    }
    // Check if still connected
    if (self->clSock.clientFD != -1)
    {
      // Disconnect on application layer
      sendGoodbye(self, self->keepWindow);
      if (proxy->externalSocketControl)
      {
        self->clSock.clientFD = -1;
        self->clSock.oldFD = -1;
      }
    }
    // Try to reconnect - on TCP layer only
    if (!reconnectToServer(&self->clSock, RECONNECT_DELAY,
                                          MAX_RECONNECT_ATTEMPT))
    {
      return false;
    }

    // Reconnect on application layer
    LOG (LEVEL_INFO, " Transport-layer reconnect done, now initiate HELLO "
                      "handshake", pthread_self());
    //LOG(LEVEL_INFO, "Establish connection with proxy [%u]...", proxy->proxyID);
    SRxProxy* proxy =        (SRxProxy*)self->srxProxy;
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

    if (handshakeWithServer(self, hdr))
    {
      // established is set in srx_api.c::processHelloResponse 
      LOG(LEVEL_INFO, "Connection with proxy [%u] established!",proxy->proxyID);
    }
    else
    {
      if (!self->stop) // No Goodbye received
      {
        RAISE_ERROR("Handshake with server failed but connection handler is "
                    "not stopped!");
        //releaseClientConnectionHandler(self);
        //--> need to be something different, because it is really bad idea to pthread_cancel inside same thread.
      }
      LOG(LEVEL_WARNING, "Handshake with server failed!");
      return false;
    }

    return true;
  }

  return retVal;
}

