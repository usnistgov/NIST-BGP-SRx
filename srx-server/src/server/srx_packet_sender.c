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
 * This file contains the functions to send srx-proxy packets.
 * 
 * @version 0.3.0.10
 *
 * Changelog:
 * 
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/10 - oborchert
 *            * Fixed assignment bug in stopSendQueue
 *            * Added return value (NULL) to sendQueueThreadLoop
 * 0.3.0    - 2013/02/06 - oborchert
 *            * Changed logging within release of sending queue.
 *          - 2013/01/02 - oborchert
 *            * Added Changelog.
 *            * Added sending queue to prevent buffer overflows in the receiver 
 *              socket 
 * 0.1.0    - 2011/11/01 - oborchert
 *            * File Created.
 */
#include <stdint.h>
#include <stdbool.h>
#include "server/srx_packet_sender.h"
#include "shared/srx_packets.h"
#include "util/log.h"
#include "util/mutex.h"
#include "util/server_socket.h"

typedef struct {
  // The pdu to be send
  uint8_t*      pdu;    
  // The size of the pdu
  size_t        size;
  // The server socket to send from
  ServerSocket* srcSock;
  // The client to send to
  ServerClient* client;
  // The next packet in the queue
  void*         next; 
} SendPacket;

typedef struct {
  // the head element of the queue
  SendPacket* head;
  // the tail element of the queue
  SendPacket* tail;
  // the size of the queue
  int        size;
  // the queue handler itself
  pthread_t handler;
  // indicates if the queue is running.
  bool        running;
  // Mutex and Condition for thread handling
  Mutex       mutex;
  Cond        condition;
  
} SendPacketQueue;

////////////////////////////////////////////////////////////////////////////////
// Packet Sending Queue
////////////////////////////////////////////////////////////////////////////////

// wait until notify or 1 s timeout - this is just to allow a wakeup
#define SEND_QUEUE_WAIT_MS 1000

// The send queue 
static SendPacketQueue* SEND_QUEUE = NULL;

// Forward declaration
SendPacket* fetchSendPacket();

/**
 * Create the sender queue including the thread that manages the queue.
 * 
 * @return true if the queue cold be created otherwise false. 
 * 
 * @since 0.3.0
 */
bool createSendQueue()
{
  SendPacketQueue* queue = malloc(sizeof(SendPacketQueue));
  if (queue != NULL)
  {
    queue->head    = NULL;
    queue->tail    = NULL;
    queue->size    = 0;
    queue->running = false;
    
    if (initMutex(&queue->mutex))
    {
      if (!initCond(&queue->condition))
      {
        releaseMutex(&queue->mutex);
        free(queue);
        queue = NULL;
      }
    }
    else
    {
      free(queue);
      queue = NULL;
    }    
    SEND_QUEUE = queue;
  }
    
  return queue != NULL;
}

/**
 * Stops the queue is not already stopped and frees all memory associated with 
 * it.
 * 
 * @since 0.3.0
 */
void releaseSendQueue()
{
  if (SEND_QUEUE != NULL)
  {
    LOG(LEVEL_INFO, "Enter release send queue...");

    if (SEND_QUEUE->running)
    {
      // Stops and cleans the queue
      stopSendQueue(SEND_QUEUE);
    }
    if (SEND_QUEUE->head != NULL)
    {
      RAISE_SYS_ERROR("Queue should be already empty!");
    }
    releaseMutex(&SEND_QUEUE->mutex);
    destroyCond(&SEND_QUEUE->condition);
    free (SEND_QUEUE);
    SEND_QUEUE = NULL;
    
    LOG(LEVEL_INFO, ".. Exit release send queue!");
  }  
}

/** 
 * The thread loop of the queue. To stop the queue call stopSendQueue()
 * 
 * @param notused - Not Used
 * 
 * @return NULL
 * 
 * @since 0.3.0
 */
void* sendQueueThreadLoop(void* notused)
{
  SendPacketQueue* queue = SEND_QUEUE;
  if (queue == NULL)
  {
    RAISE_SYS_ERROR("Send queue is not initialized!");
  }
  else
  {
    SendPacket* packet = NULL;
    LOG(LEVEL_DEBUG, "Enter sendqueue loop.");
    while (queue->running)
    {
      packet = fetchSendPacket(queue);
      if (packet != NULL)
      {
        if (!sendPacketToClient(packet->srcSock, packet->client, packet->pdu, 
                                packet->size))
        {
          SRXPROXY_BasicHeader* bhdr = (SRXPROXY_BasicHeader*)packet->pdu;
          RAISE_ERROR("Could not send packet of type [%u]!", bhdr->type);
        }
        free(packet->pdu);
        free(packet);
      }
    }
    LOG(LEVEL_DEBUG, "Exit send queue loop!");
  }
  
  return NULL;
}

/**
 * Start the send queue. In case the queue is already started this method does 
 * not further start it.
 * 
 * @return true if the Queue is running.
 * 
 * @since 0.3.0
 */
bool startSendQueue()
{
  SendPacketQueue* queue = SEND_QUEUE;
  bool retVal = false;
  
  if (queue == NULL)
  {
    RAISE_SYS_ERROR("Send queue is not initialized!");
  }
  else
  {
    lockMutex(&queue->mutex);
    if (!queue->running)
    {
      queue->running = true;    
      if (pthread_create(&queue->handler, NULL, sendQueueThreadLoop, NULL) 
                         != 0)
      {
        queue->running = false;
        RAISE_SYS_ERROR("Could not start the send queue handler!");
      }
    }

    retVal = queue->running;
    unlockMutex(&queue->mutex);
  }
  return retVal;
}

/**
 * Stop the queue but does not destroy the thread itself.
 * 
 * @since 0.3.0
 */
void stopSendQueue()
{
  SendPacketQueue* queue = SEND_QUEUE;
  
  if (queue == NULL)
  {
    RAISE_SYS_ERROR("Send queue is not initialized!");
  }
  else
  {
    lockMutex(&queue->mutex);
    if (queue->running)
    {
      queue->running = false;
      // Stop the queue by waking it up
      LOG(LEVEL_INFO, "StopSendQueue: send notification...");
      signalCond(&queue->condition);
    }
    unlockMutex(&queue->mutex);
    // Give the queue thread a chance to process the notify or run into a
    // wait timeout.   
    LOG(LEVEL_INFO, "StopSendQueue: sleep for %u ms", SEND_QUEUE_WAIT_MS * 2);
    usleep(SEND_QUEUE_WAIT_MS * 2);
    
    lockMutex(&queue->mutex);
    // Free the remainder of the queue.
    LOG(LEVEL_INFO, "StopSendQueue: wait for queue thread to join...");
    pthread_join(queue->handler, NULL);
    LOG(LEVEL_INFO, "SendQueueThrealLoop STOPPED. Empty remainder of queue!");
    SendPacket* packet = NULL;
    while (queue->head != NULL)
    {
      packet = queue->head;
      queue->head = (SendPacket*)packet->next;
      // Free the allocated memory
      free(packet->pdu);
      free(packet);
      queue->size--;
    }
    queue->tail = NULL;
    unlockMutex(&queue->mutex);
  }
}

/**
 * Retrieve the next packet from the queue as long as the queue is running. 
 * in case the queue is not running this method returns NULL.
 * 
 * @return  the next packet of NULL if the queue is empty.
 * 
 * @since 0.3.0
 */
SendPacket* fetchSendPacket() 
{
  SendPacketQueue* queue = SEND_QUEUE;
  SendPacket* packet = NULL;
  
  if (queue != NULL)
  {
    lockMutex(&queue->mutex);
    while (queue->size == 0 && queue->running)
    {
      // wait until notify is called or after a timeout.      
      waitCond(&queue->condition, &queue->mutex, SEND_QUEUE_WAIT_MS);
      if(!queue->running)
      {
        LOG(LEVEL_INFO, "Sending queue received shutdown!");
      }
    }

    // If queue is still running and a packet is available take it
    if (queue->running && queue->head != NULL)
    {
      packet = queue->head;
      queue->size--;
      queue->head = (SendPacket*)packet->next;
      packet->next = NULL;   
    }
    unlockMutex(&queue->mutex);
  }
  return packet;
}

/**
 * Queue a copy of the the packet and return the size of the queue. The copy of 
 * the packet will be free'd by the queue handler thread itself.
 * 
 * @param pdu The PDU to be added to the queue.
 * @param srvSoc The server socket to be used for sending
 * @param client The client to send to
 * 
 * @return true if the packet was queued, otherwise false.
 * 
 * @since 0.3.0
 */
bool addToSendQueue(uint8_t* pdu, ServerSocket* srvSoc, ServerClient* client, 
                    size_t size)
{
  SendPacketQueue* queue = SEND_QUEUE;
  
  SendPacket* packet = malloc(sizeof(SendPacket));
  bool retVal = false;
  
  lockMutex(&queue->mutex);
  if (packet != NULL)
  {
    memset(packet, 0, sizeof(SendPacket));
    packet->pdu = malloc(size);
    if (packet->pdu == NULL)
    {
      free(packet);
    }
    else
    {
      retVal = true;
      packet->srcSock  = srvSoc;
      packet->client   = client;
      packet->next     = NULL;
      packet->size     = size;
      memcpy(packet->pdu, pdu, size);  
      if (queue->size == 0)
      {
        queue->head = packet;
        queue->tail = packet;
      }
      else
      {
        queue->tail->next = packet;
        queue->tail = packet;
      }
      queue->size++;
      // Signal a new packet is in the queue
      signalCond(&queue->condition);
    }
  }
  unlockMutex(&queue->mutex);
  
  if (!retVal)
  {
    RAISE_SYS_ERROR("Not enough memory to queue packets in send queue!");
  }
  
  return retVal;
}

////////////////////////////////////////////////////////////////////////////////
// Packet Sending methods
////////////////////////////////////////////////////////////////////////////////

/**
 * This method redirects the sending requests to the sending queue.
 * 
 * @param srvSoc The server socket
 * @param client The server client
 * @param data The data to be send
 * @param size The length of the data to be send.
 * @param useQueue Use the queue if possible.
 * 
 * @return 
 */
bool __sendPacketToClient(ServerSocket* srvSoc, ServerClient* client,
                          void* pdu, size_t size, bool useQueue)
{
  bool retVal = false;
  
  if (!useQueue)
  {
    retVal = sendPacketToClient(srvSoc, client, pdu, size);
  }
  else 
  {
    if (SEND_QUEUE==NULL)
    {
      LOG(LEVEL_WARNING, "The sender queue is not initialized, send PDU directly "
                         "without queue!");
    }
    else
    {
      retVal = addToSendQueue(pdu, srvSoc, client, size);
    }
  }
  
  return retVal;
}


/**
 * Send a hello response to the client. Does not use the sending queue.
 *
 * @param proxyID The id of the proxy
 * @param srvSoc The server socket
 * @param client The client who received the original message
 *
 * @return true if the packet could be send, otherwise false.
 */
bool sendHelloResponse(ServerSocket* srvSoc, ServerClient* client,
                       uint32_t proxyID)
{
  bool retVal = true;
  uint32_t length = sizeof(SRXPROXY_HELLO_RESPONSE);
  SRXPROXY_HELLO_RESPONSE* pdu = malloc(length);
  memset(pdu, 0, length);

  pdu->type    = PDU_SRXPROXY_HELLO_RESPONSE;
  pdu->version = htons(SRX_PROTOCOL_VER);
  pdu->length  = htonl(length);
  pdu->proxyIdentifier = htonl(proxyID);
  
  if (!sendPacketToClient(srvSoc, client, pdu, length))
  {
    RAISE_ERROR("Could not send Goodbye message!");
    retVal = false;
  }

  free(pdu);
  return retVal;
}

/**
 * Send a goodbye packet to the proxy. The proxy does not use the keepWindow,
 * therefore it will be 0.
 *
 * @param srvSoc The server socket
 * @param client The client who received the original message
 * 
 * @return true if the message could be send or not.
 */
bool sendGoodbye(ServerSocket* srvSoc, ServerClient* client, bool useQueue)
{
  bool retVal = true;
  uint32_t length = sizeof(SRXPROXY_GOODBYE);
  SRXPROXY_GOODBYE* pdu = malloc(length);
  memset(pdu, 0, length);

  pdu->type       = PDU_SRXPROXY_GOODBYE;
  pdu->keepWindow = 0; // Not used on the client side!
  pdu->length     = htonl(length);

  if (!__sendPacketToClient(srvSoc, client, pdu, length, useQueue))
  {
    RAISE_ERROR("Could not send Goodbye message!");
    retVal = false;
  }

  free(pdu);
  return retVal;
}

/**
 * Send a verification notification. Does use the sending queue.
 *
 * @param srvSoc The server socket
 * @param client The client of the communication.
 * @param updateID The id of the update.
 * @param resultType The type of results.
 * @param requestToken The token id of a request. Must be disabled 
 *                     (DONOTUSE_REQUEST_TOKEN) if the receipt flag is not set!
 * @param roaResult The ROA validation result.
 * @param bgpsecResult The BGPSEC validation result.
 * @param useQueue use the sending queue or not.
 *
 * @return true if the packet could be send, otherwise false.
 */
bool sendVerifyNotification(ServerSocket* srvSoc, ServerClient* client,
                            SRxUpdateID updateID, uint8_t resultType,
                            uint32_t requestToken,
                            uint8_t roaResult, uint8_t bgpsecResult, 
                            bool useQueue)
{
  bool retVal = true;
  uint32_t length = sizeof(SRXPROXY_VERIFY_NOTIFICATION);
  SRXPROXY_VERIFY_NOTIFICATION* pdu = malloc(length);
  memset(pdu, 0, length);

  pdu->type          = PDU_SRXPROXY_VERI_NOTIFICATION;
  pdu->resultType    = resultType;
  pdu->requestToken  = htonl(requestToken);
  pdu->roaResult     = roaResult;
  pdu->bgpsecResult  = bgpsecResult;
  pdu->length        = htonl(length);
  pdu->updateID      = htonl(updateID);
  
  if ((pdu->requestToken != 0) && (resultType < SRX_FLAG_REQUEST_RECEIPT))
  {
    LOG(LEVEL_NOTICE, "Send a notification of update 0x%0aX with request "
        "token 0x%08X but no receipt flag set!", updateID, requestToken);
  }

  pdu->length = htonl(length);
  
  if (!__sendPacketToClient(srvSoc, client, pdu, length, useQueue))
  {
    RAISE_ERROR("Could not send the verify notification for update [0x%08X]!",
                updateID);
    retVal = false;
  }
  
  if (retVal)
  {
    LOG(LEVEL_DEBUG, "Notification send for update [0x%08X]", updateID);    
  }

  free(pdu);
  return retVal;
}

/**
 * Send a signature notification.
 *
 * @param srvSoc The server socket
 * @param client The client of the communication.
 * @param updateID The id of the update.
 * @param bgpsecLength The length of the signature
 * @param bgpsecBlob The BGPSEC data blob
 * @param useQueue Use the sending queue.
 *
 * @return true if the packet could be send, otherwise false.
 */
bool sendSignatureNotification(ServerSocket* srvSoc, ServerClient* client,
                               SRxUpdateID updateID, uint32_t bgpsecLength,
                               uint8_t* bgpsecBlob, bool useQueue)
{
  bool retVal = true;
  uint32_t length = sizeof(SRXPROXY_SIGNATURE_NOTIFICATION) + bgpsecLength;
  SRXPROXY_SIGNATURE_NOTIFICATION* pdu = malloc(length);
  memset(pdu, 0, length);

  uint8_t* blob = (uint8_t*)pdu + sizeof(SRXPROXY_SIGNATURE_NOTIFICATION);

  pdu->type = PDU_SRXPROXY_SIGN_NOTIFICATION;
  pdu->length = htonl(length);
  pdu->updateIdentifier = htonl(updateID);
  pdu->bgpsecLength = htonl(bgpsecLength);
  memcpy(blob, bgpsecBlob, bgpsecLength);

  // Send the pdu to the client
  if (!__sendPacketToClient(srvSoc, client, pdu, length, useQueue))
  {
    RAISE_SYS_ERROR("Could not send the signature notification for update "
                    "[0x%08X]", updateID);
    retVal = false;
  }
  free(pdu);

  return retVal;
}


/**
 * Send a synchronization request to the proxy.
 *
 * @param srvSoc The server socket
 * @param client The client of the communication.
 * @param useQueue Use the sending queue.
 *
 * @return true if the packet could be send, otherwise false.
 */
bool sendSynchRequest(ServerSocket* srvSoc, ServerClient* client, bool useQueue)
{
  bool retVal = true;
  uint32_t length = sizeof(SRXPROXY_SYNCH_REQUEST);
  SRXPROXY_SYNCH_REQUEST* pdu = malloc(length);
  memset(pdu, 0, length);

  pdu->type      = PDU_SRXPROXY_SYNC_REQUEST;
  pdu->length    = htonl(length);

  // Send the pdu to the client
  if (!__sendPacketToClient(srvSoc, client, pdu, length, useQueue))
  {
    RAISE_SYS_ERROR("Could not send the synchonization request");
    retVal = false;
  }
  free(pdu);

  return retVal;
}


/**
 * Send an error report to the proxy.
 *
 * @param errorCode The code of the error
 * @param srvSoc The server socket
 * @param client The client of the communication.
 * @param useQueue Use the sending queue.
 *
 * @return true if the packet could be send, otherwise false.
 */
bool sendError(uint16_t errorCode, ServerSocket* srvSoc, ServerClient* client,
               bool useQueue)
{
  bool retVal = true;
  uint32_t length = sizeof(SRXPROXY_ERROR);
  SRXPROXY_ERROR* pdu = malloc(length);
  memset(pdu, 0, length);

  pdu->type      = PDU_SRXPROXY_ERROR;
  pdu->errorCode = htons(errorCode);
  pdu->length    = htonl(length);

  // Send the pdu to the client
  if (!__sendPacketToClient(srvSoc, client, pdu, length, useQueue))
  {
    RAISE_SYS_ERROR("Could not send the error report type [%0x04X]", errorCode);
    retVal = false;
  }
  free(pdu);

  return retVal;
}

