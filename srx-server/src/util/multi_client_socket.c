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
 * 0.3.0.10 - 2015/11/10 - oborchert
 *            * Added Initialization for function variables in monitorThread
 *          - 2015/11/09 - oborchert
 *            * Added Changelog
 *            * Fixed speller in documentation header
 * 0.1.0    - 2010/12/01 -pgleichm
 *            * Code created. 
 */
// @TODO: This can be deleted

#include "util/multi_client_socket.h"
#include "util/client_socket.h"
#include "util/log.h"
#include "util/socket.h"

/**
 * A single entry in the server queue - waiting for a response.
 */
typedef struct {
  uint32_t  id;
  Mutex     mutex; 
  void*     buffer;
  size_t    bufferSize;
  size_t    numRead;
} QueueData;  

/**
 * Waits for incoming data and depending on the id wakes up the corresponding
 * - currently sleeping - caller.
 *
 * @note PThread syntax
 *
 * @param data The client-socket (MultiClientSocket)
 */
static void* monitorThread(void* data) {
  RAISE_ERROR("NOT CHECKED YET!!!");
  
  MultiClientSocket*  cs = (MultiClientSocket*)data;
  uint32_t            id = 0;
  SListNode*          cnode = NULL;
  QueueData*          qdata = NULL;

  LOG (LEVEL_DEBUG, "([0x%08X]) > Multi Client Socket Thread started!", pthread_self());    
  
  // Process each
  for (;;) {
    // No connection anymore - terminate the monitor
    if (!recvNum(getClientFDPtr(&cs->clSock), &id, 
                 sizeof(uint32_t))) {
      break;
    }

    // Search the node for the id
    FOREACH_SLIST(&cs->queue, cnode) {
      if (((QueueData*)getDataOfSListNode(cnode))->id == id) {
        break; // Found
      }
    }
    
    // Read the data and then wake up the function
    qdata = (QueueData*)getDataOfSListNode(cnode);
    qdata->numRead = receiveData(&cs->clSock, qdata->buffer, qdata->bufferSize);
    unlockMutex(&qdata->mutex); 
  }

  // Unblock all remaining calls
  for (cnode = cs->queue.root; cnode; cnode = cnode->next) {
    ((QueueData*)getDataOfSListNode(cnode))->numRead = -1;
    unlockMutex(&((QueueData*)getDataOfSListNode(cnode))->mutex);
  }

  LOG (LEVEL_DEBUG, "([0x%08X]) < Multi Cient Socket Thread stopped!", pthread_self());      
  
  pthread_exit(0);
}

//TODO: Check this might be old code that can be removed!!
bool createMultiClientSocket(MultiClientSocket* self,
                             const char* host, int port)
{
  RAISE_ERROR("NOT CHECKED YET!!!");
  
  // Open the connection
  if (!createClientSocket(&self->clSock, host, port, true, 
                          UNDEFINED_CLIENT_SOCKET, true))
  {
    return false;
  }

  // Initialize the variables
  initSList(&self->queue);
  if (!initMutex(&self->idMutex))
  {
    RAISE_SYS_ERROR("Failed to create an Id mutex");
    closeClientSocket(&self->clSock);
    return false;
  }
  self->maxId = 0;

  // Start the monitor
  if (pthread_create(&self->monitor, NULL, monitorThread, 
                     (void*)self) != 0)
  {
    RAISE_ERROR("Not enough resource for the client socket monitor");
    closeClientSocket(&self->clSock);
    releaseMutex(&self->idMutex);
    return false;
  }

  return true;
}

void releaseMultiClientSocket(MultiClientSocket* self) {
  RAISE_ERROR("NOT CHECKED YET!!!");
  
  if (self != NULL) {
    closeClientSocket(&self->clSock);
    releaseSList(&self->queue);
    releaseMutex(&self->idMutex);
  }
}

/**
 * Returns a unique identifier.
 *
 * @param mcs Multi Client-socket
 * @return Numeric identifier
 */
static uint32_t getId(MultiClientSocket* mcs) {
  RAISE_ERROR("NOT CHECKED YET!!!");

  uint32_t id;

  lockMutex(&mcs->idMutex);
  id = mcs->maxId;
  mcs->maxId++;
  unlockMutex(&mcs->idMutex);

  return id;
}

size_t exchangeData(MultiClientSocket* self, 
                    void* data, size_t dataSize,
                    void* buffer, size_t bufferSize) {
  RAISE_ERROR("NOT CHECKED YET!!!");
  
  QueueData*  qdata;
  size_t      num;

  // Create a new queue node and corresponding mutex (locked)
  qdata = (QueueData*)appendToSList(&self->queue, sizeof(QueueData));
  if (qdata == NULL) {
    return -1;
  }
  if (!initMutex(&qdata->mutex)) {
    deleteFromSList(&self->queue, qdata);
    return -1;
  }
  lockMutex(&qdata->mutex);
 
  // Assign an id and copy the parameters so that the monitor can access them
  qdata->id         = getId(self);
  qdata->buffer     = buffer;
  qdata->bufferSize = bufferSize;

  // Send the id, and then the data
  if (sendNum(getClientFDPtr(&self->clSock), 
              &qdata->id, sizeof(uint32_t))
      && sendData(&self->clSock, data, dataSize)) {
  
    // Block until the monitor wakes us up
    waitMutex(&qdata->mutex);

    // Number of bytes read
    num = qdata->numRead;
  
  // Failed to send the id or data
  } else {
    num = -1;
  }

  // Remove the mutex and node
  releaseMutex(&qdata->mutex);
  deleteFromSList(&self->queue, qdata);

  return num;
}

