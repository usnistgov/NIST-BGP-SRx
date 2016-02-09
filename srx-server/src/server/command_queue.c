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
 * @version 0.3.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 *   0.3.0 - 2013/02/06 - oborchert
 *           * Added Version Control
 *           * Changed log level of output during shutdown
 *   0.2.0 - 2011/11/01 - oborchert
 *           * Rewritten.
 *   0.1.0 - 2010/05/05 - pgleichm
 *           * Code Created
 * -----------------------------------------------------------------------------
 */

#include "server/command_queue.h"
#include "shared/srx_defs.h"
#include "shared/srx_packets.h"
#include "util/log.h"
#include "util/math.h"

#define HDR "([0x%08X] Command Queue): "

/** 
 * Initializes and setup the command queue.
 *
 * @param self Variable that should be initialized
 * 
 * @return true if the queue could be initialized.
 */
bool initializeCommandQueue(CommandQueue* self)
{
  if (self->alive)
  {
    RAISE_ERROR("This command queue is already alive!!");  
    return false;
  }
  
  // Create read and write Mutex
  if (!initMutex(&self->cmdQueueMutex))
  {
    return false;
  }

  if(!initCond(&self->consumeCond))
  {
    releaseMutex(&self->cmdQueueMutex);
    pthread_cond_destroy(&self->consumeCond);
    return false;
  }

  // An empty list
  self->totalItems = 0;
  self->unprocessedItems = 0;
  initSList(&self->queue);

  // No item is available, i.e. block fetch
  self->nextItemNode = NULL;

  self->alive = true;
  
  return true;
}

/** Used to destroy command queue. The queue is not usable after executing 
 * this command.
 * 
 * @param self The comnand queue to be released
 */
void releaseCommandQueue(CommandQueue* self)
{
  if (self != NULL)
  {
    LOG(LEVEL_DEBUG, HDR "Release Command Queue", pthread_self());    
    lockMutex(&self->cmdQueueMutex);
    LOG(LEVEL_DEBUG, HDR "Set alive = false", pthread_self());    
    self->alive = false;
    LOG(LEVEL_DEBUG, HDR "Signal consumer (fetch thread)", pthread_self());        
    signalCond(&self->consumeCond);    
    
    unlockMutex(&self->cmdQueueMutex);
    
    LOG(LEVEL_DEBUG, HDR "Now empty command queue", pthread_self());    
    removeAllCommands(self);
       
    LOG(LEVEL_DEBUG, HDR "Release internal list and Mutex", pthread_self());    
    // Release all items and the mutexes
    releaseSList(&self->queue); 
    releaseMutex(&self->cmdQueueMutex);
  }
}

/**
 * Add a given command into the command queue. THe type of command is stored in 
 * the parameter cmdType.
 *
 * @param self The command queue where the command has to be added to
 * @param cmdType The type of the command.
 * @param svrSock The server socket
 * @param client The server client
 * @param dataID An identifier related to the data block. In case of SRX_PROXY
 *               this identifier contains either 0 or the update ID.
 * @param dataLength The length of the data attached to this command queue.
 * @param data The data package attached.
 *
 * @return true if the command could be added to the queue.
 */
bool queueCommand(CommandQueue* self, CommandQueueType cmdType,
                  ServerSocket* svrSock, ServerClient* client, uint32_t dataID,
                  uint32_t dataLength, uint8_t* data)
{
  // This method is changed in such that the wait mutex is synchronized with
  // the fetchCommand method. The waitmutex is locked and a notify is called 
  // once a command is placed and the counter is incresed. The mutex is released
  // afterwards.
  
  if (!self->alive)
  {
    LOG(LEVEL_DEBUG, HDR, "Command Queue is not alive anymore, cannot queue "
                          "command type (%u)!", pthread_self(), cmdType);
    return false;
  }
  
  LOG(LEVEL_DEBUG, HDR "queueComamnd type (%u)", pthread_self(), cmdType);
  CommandQueueItem* newItem;    

  // Try to add a new item - make sure no one modifies the queue
  lockMutex(&self->cmdQueueMutex);  
  newItem = (CommandQueueItem*)appendToSList(&self->queue, 
                                             sizeof(CommandQueueItem));
  newItem->consumed = false;
  
  // Set the new next node inside this mutex to make sure we -
  // - get the new item
  // - unlock only once
  if (self->nextItemNode == NULL)
  {
    self->nextItemNode = getLastNodeOfSList(&self->queue);
  }

  // Failed to add an item
  if (newItem == NULL)
  {
    unlockMutex(&self->cmdQueueMutex);
    return false;
  }

  // 'NULL' packet
  if (data == NULL)
  {
    newItem->data = NULL;
  } 
  else
  {
    // Try to copy the 'packet' into the command item
    newItem->data = malloc(dataLength);
    if (newItem->data == NULL)
    {
      RAISE_SYS_ERROR("Not enough memory to copy the data into the queue");
      deleteFromSList(&self->queue, newItem);
      
      return false;
    }
    //TODO: BZ197 This might be revisited - Dirty BUG test
    if (dataLength < 1000000) // dirty bug test - increased by factor 10
    {
      memcpy(newItem->data, data, dataLength); 
      // SEGV due to dataLength : 50529027 (0x03030303)
    }
    else
    {
      RAISE_SYS_ERROR("Given datalength too big due to transmission error "
        "- Inform developers with reference code BZ197!");
      deleteFromSList(&self->queue, newItem);
      unlockMutex(&self->cmdQueueMutex);
      return false;
    }
  }

  // Set the other item members
  newItem->serverSocket = svrSock;
  newItem->client       = client;
  newItem->cmdType      = cmdType;
  newItem->dataID       = dataID;
  newItem->dataLength   = dataLength;
    
  self->totalItems++;
  self->unprocessedItems++;
  
  LOG(LEVEL_DEBUG, HDR "Signale new data to consume...%s", pthread_self(),
                   __FUNCTION__);
  signalCond(&self->consumeCond);
  
  LOG(LEVEL_DEBUG, HDR "UNLOCK readWriteLock...%s", pthread_self(),
                   __FUNCTION__);
  unlockMutex(&self->cmdQueueMutex);

  return true;
}

/**
 * Retrieves the next command. This method DOES NOT clear the memory. 
 * After a command is processed the method 'deleteCommand' will remove it from 
 * the queue and free up all associated memory.
 * 
 * @param self The command queue
 * 
 * @return The command queue command.
 *  */
CommandQueueItem* fetchNextCommand(CommandQueue* self)
{
  // Changed the mutex management in this method. It will lock the wait mutex 
  // and wait unti la command is in the queue. once a command is read from the 
  // queue the wait mutesx will be unlocked and the command will be returned.
  // This method plays the loc/unlock mutex game with queuecommand
  
  CommandQueueItem* item;
  
  LOG(LEVEL_DEBUG, HDR "Fetch next command from command queue...", 
                   pthread_self());

  if (!self->alive)
  {
    RAISE_ERROR ("Command queue is not alive anymore, fetching commands is not"
                 " possible!");
    return NULL;
  }
 
  LOG(LEVEL_DEBUG, HDR "Request access lock to cmd Queue", pthread_self());
  lockMutex(&self->cmdQueueMutex);

  // Wait until a new item is in the queue
  while (self->alive && self->unprocessedItems == 0)
  {
    LOG(LEVEL_DEBUG, HDR "No command in queue, wait until command arrives.", 
                     pthread_self());
    // Will be woken up by queueCommand
    waitCond(&self->consumeCond, &self->cmdQueueMutex, 0);
    LOG(LEVEL_DEBUG, HDR "Received notification of command arrival.", 
                     pthread_self());
  }
  
  if (!self->alive)
  {
    LOG(LEVEL_INFO, HDR "Command queue is terminated during fetching command, "
                        "abort fetching!!!", pthread_self());
    unlockMutex(&self->cmdQueueMutex);
    return NULL;
  }
  
  // Retrieve the item and set the fetcher to the next one.
  item = (CommandQueueItem*)self->nextItemNode->data;
  self->unprocessedItems--;				// SEE also ./util/slist.c:106    
  if (item == NULL)
  {
    RAISE_ERROR("Fatal CommandQueue encountered an empty command.");
  }
  if (item->consumed)
  {
    RAISE_ERROR("Fetch an already consumed command!!");
  }
  // Indicate this item is consumed and can be deleted.
  item->consumed = true;
  
  //move to next item.
  self->nextItemNode = getNextNodeOfSListNode(self->nextItemNode);
  // TODO: Check what happens to the memory allocated to store the command!!!
  // Unlock the write mutex
  unlockMutex(&self->cmdQueueMutex);  

  return item;
}

/**
 * Remove the queue element that is already consumed from the list and frees 
 * up all allocated memory associated with this element.
 * 
 * @param self The command queue
 * @param item The item. It also will be freed!
 */
void deleteCommand(CommandQueue* self, CommandQueueItem* item)
{
  LOG(LEVEL_DEBUG, HDR "Delete the given command queue item.", pthread_self());
  lockMutex (&self->cmdQueueMutex);
  // Free The packet data within the item
  if(item != NULL) 
  {
    free(item->data);
  }
  self->totalItems--;
  // The delete from list also frees the item.
  deleteFromSList(&self->queue, item);
  unlockMutex(&self->cmdQueueMutex);
}

/**
 * Clears the complete queue.
 * 
 * @param self The command queue.
 */
void removeAllCommands(CommandQueue* self)
{
  LOG(LEVEL_DEBUG, HDR "Remove all commands from the command queue.",
                   pthread_self());
  SListNode* currNode;

  // No adding or single removing allowed
  lockMutex(&self->cmdQueueMutex);

  // Release all packets stored in the items
  FOREACH_SLIST(&self->queue, currNode)
  {
    void* p = ((CommandQueueItem*)getDataOfSListNode(currNode))->data;
    if (p)
    {
      free(p);
    }
  }
  // Now delete the items.
  emptySList(&self->queue);

  if (self->nextItemNode != NULL)
  {
    RAISE_SYS_ERROR("Queue[0x%08X] Removing of all commands without success!", 
                    self);
  };
  
  self->totalItems       = self->queue.size;
  self->unprocessedItems = self->nextItemNode == NULL ? 0 : self->totalItems;
  
  // Grant write access again
  unlockMutex(&self->cmdQueueMutex); 
}

/**
 * Return the maximum number of commands in the queue
 * 
 * @param self The command queue
 * 
 * @return the maximum number of items in the queue.
 */
inline int getTotalQueueSize(CommandQueue* self)
{
  return self->totalItems;
}

/**
 * Return the number of unprocessed commands in the queue
 * 
 * @param self The command queue
 * 
 * @return the number of unprocessed items in the queue.
 */
inline int getUnprocessedQueueSize(CommandQueue* self)
{
  return self->unprocessedItems;
}
