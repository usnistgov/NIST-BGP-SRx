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
 *
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Added Changelog
 *            * Fixed speller in documentations
 * 0.1.0    - 2010/04/09 -pgleichm
 *            * Code created. 
 */

#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include "client/client_connection_handler.h"
#include "server/server_connection_handler.h"
#include "util/packet.h"
#include "util/server_socket.h"
#include "util/log.h"
#include "util/mutex.h"
#include "util/socket.h"

#define HDR "([0x%08X] Packet): "

/**
 * This function runs in a loop to receive packets. This function is used as 
 * receiver loop on both sides, SRx server as well as SRx client. IN case the 
 * SRx server uses. this method the parameter connHandler MUST be NULL.
 *
 * @note Blocking call, only if in server mode. Clients run through only once.
 *
 * @param fdPtr        The file descriptor of the socket
 * @param dispatcher   The dispatcher method that receives all packets and
 *                     distributes them.
 * @param pHandler     Instance of the packet handler. On SRx server side this 
 *                     will be ClientThread, on the proxy side this will be 
 *                     SRxProxy.
 * @param pHandlerType The type of handler, srx-proxy or srx-server.
 *
 * @return true if the method ended clean.
 */
bool receivePackets(int* fdPtr, SRxPacketHandler dispatcher, void* pHandler, 
                    PacketHandlerType pHandlerType)
{
  // By default and as long as it is true, keep going
  bool retVal = true;
  // 8 bytes that contain the type and length
  uint32_t              basicLength = sizeof(SRXPROXY_BasicHeader);
  // Buffer that contains the bytes received.
  uint8_t*              buffer = malloc(basicLength);
  // A helper that points into the buffer at byte 9
  uint8_t*              buffHelper = buffer;//+basicLength;
  // The size of the current buffer. Can be larger than the message itself
  uint32_t              buffSize   = basicLength;
  // Bytes left after the basic length (of 8 bytes)
  uint32_t              remainder  = buffSize - basicLength;
  // The header mask layer put on top of the buffer for easier access
  SRXPROXY_BasicHeader* hdr        = (SRXPROXY_BasicHeader*)buffer;
  // The length of the PDU within the buffer
  uint32_t              pduLength = 0;

  ClientThread* cthread ;
  ServerConnectionHandler *hSvrConnection;
  CommandQueue* cmdQueue;

  if (pHandlerType == PHT_SERVER)
  {
    cthread = (ClientThread*)pHandler;
    hSvrConnection = (ServerConnectionHandler *)cthread->svrSock->user;
    cmdQueue = (CommandQueue *)hSvrConnection->cmdQueue;
  }

  // used to keep the receiver going.
  bool keepGoing = true;

  // Keeps the thread rolling - Process all packets
  while (keepGoing)
  {
    // initialize the buffer as \0
    // memset(buffer, 0, buffSize);
    // Only the basic header needs to be initialized at this point. The 
    // remainder will be initialized later.
    memset(buffer, 0, sizeof(SRXPROXY_BasicHeader));
    
    hdr = (SRXPROXY_BasicHeader*)buffer;
    if (pHandlerType == PHT_PROXY)
    {
      // When in proxy, don't continue looping, the client reads once and then 
      // leaves
      keepGoing = false;
    }

    retVal = true;    
    // Get the data
    if (!recvNum(fdPtr, buffer, basicLength))
    {
      // Just get the error, might not be used though!      
      int error = getLastRecvError();
      keepGoing = false;
      
      if (pHandlerType == PHT_PROXY)
      {
        // Within SRx Proxy
        ClientConnectionHandler* cHandler =  
                   (ClientConnectionHandler*)((SRxProxy*)pHandler)->connHandler;
        
        if (!cHandler->stop)
        {
          if(*fdPtr == -1)
          {
            retVal = false;
          }
          //return retVal;
        }
        else
        {
          LOG(LEVEL_DEBUG, HDR "Data delivery interrupted - End server loop!",
              pthread_self());
          retVal = false;
          //return;
        }
      }
      else if (pHandlerType == PHT_SERVER)
      {
        // Within SRx Server (or rpki_rtr test harness
        LOG(LEVEL_DEBUG, HDR "Connection to client closed (errno %d)", 
                         pthread_self(), error);
        retVal = false;
      }
      else
      {
        RAISE_SYS_ERROR("Invalid pHandler type!!!", pHandlerType);
        retVal = false;
      }
      
      continue;
      // return retVal;
    }

    // Data was received!!    
    pduLength = ntohl(hdr->length);
    if (buffSize < pduLength)
    {
      // The current packet is Larger than the current buffer size
      // - need to resize the buffer
      buffSize = (size_t)pduLength;
      buffer  = realloc(buffer, buffSize);

      if (buffer == NULL)
      {
        RAISE_ERROR("Not enough memory for receiving packets");
        retVal = false;
        keepGoing = false;
        continue;
        //break;
      	//return retVal;
      }
      // might be same address but just in case.
      buffHelper = buffer + basicLength;
    }
    
    // Determine how much data is missing to complete the packet
    remainder = pduLength - basicLength;
    if (remainder > pduLength)
    {
      RAISE_ERROR( HDR "Received PDU is invalid!", pthread_self());
      remainder = 0;
    }
    // initialize the extended memory with \0
    memset(buffHelper, 0, buffSize - basicLength);

    // Receive the remainder of the packet
    if (!recvNum(fdPtr, buffHelper, (size_t)remainder))
    {
      int error = getLastRecvError();
      RAISE_ERROR("Could not receive the basic remaining %u bytes, error %d!",
                  remainder, error);
      //break;
      retVal = false;
      keepGoing = false;
      continue;
      //return retVal;
    }

    if (retVal)
    {
      // the first byte of the buffer contains the pdu type
      LOG(LEVEL_DEBUG, HDR "Received data and call dispatcher.", 
          pthread_self());
      // call the dispatcher that deals with the packet
      // TODO: Good point to have a receiver queue handing it over to.
      dispatcher((SRXPROXY_BasicHeader*)buffer, pHandler);
    }
  }

  // Release the buffer and parameter structure
  if (buffer != NULL)
  {
    buffHelper = NULL;
    free(buffer);
  }
  LOG(LEVEL_DEBUG, HDR "Leave receive packets function.", pthread_self());

  return retVal;
}

