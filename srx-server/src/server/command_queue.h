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
#ifndef __COMMAND_QUEUE_H__
#define __COMMAND_QUEUE_H__

#include "shared/srx_defs.h"
#include "shared/srx_packets.h"
#include "util/mutex.h"
#include "util/packet.h"
#include "util/server_socket.h"
#include "util/slist.h"

// Specifies the types of commands the queue can handle.
typedef enum {
  COMMAND_TYPE_SRX_PROXY = 0,
  COMMAND_TYPE_SHUTDOWN  = 1
} CommandQueueType;
/** 
 * A Command Queue Item.
 */
typedef struct {
  ServerSocket*    serverSocket; // Server socket that received the packet
  ServerClient*    client;       // Client that sent the packet
  CommandQueueType cmdType;      // The type of the command
  uint32_t         dataID;       // For the case of SRX_PROXY  it contains the 
                                 // update id in host format.
  bool             consumed;     // Indicated if this element is already fetched
  uint32_t         dataLength;   // Length in Bytes of \c packet
  uint8_t*         data;         // The actual packet (= data)
} CommandQueueItem;

/**
 * A single Command Queue.
 */
typedef struct {
  SList       queue;          // The list that actually represents the queue.
  SListNode*  nextItemNode;   // The next node containing a CommandQueueItem to be 
                              // fetched.
  Mutex       cmdQueueMutex; // Used to safely access the queue in read and
                              // write
  Cond        consumeCond;    // The condition for consuming elements from the 
                              // command queue

  int         totalItems;     // Total number of Items in the queue, unprocessed 
                              // and processed.
  int         unprocessedItems; // THe number of unprocessed Items.
  bool        alive;          // used to stop fetching commands
} CommandQueue;

/** 
 * Initializes and setup the command queue.
 *
 * @param self Variable that should be initialized.
 * 
 * @return true if the queue could be initialized.
 */
bool initializeCommandQueue(CommandQueue* self);

/**
 * Frees the whole queue.
 *
 * @param self Queue instance
 */
void releaseCommandQueue(CommandQueue* self);

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
                  uint32_t dataLength, uint8_t* data);

/** 
 * Returns the next item in the queue. The Item is NOT removed from the queue
 * until dequeueCommand is called. 
 *
 * @note Blocks until a command is available!
 *
 * @param self Queue instance
 * @return The next item
 */
CommandQueueItem* fetchNextCommand(CommandQueue* self);

/**
 * Removes a command from the queue.
 *
 * @param self Queue instance
 * @param item Command to remove
 */
void deleteCommand(CommandQueue* self, CommandQueueItem* item);

/**
 * Empties the queue.
 *
 * @param self Queue instance
 */
void removeAllCommands(CommandQueue* self);

/**
 * Return the maximum number of commands in the queue
 * 
 * @param self The command queue
 * 
 * @return the maximum number of items in the queue.
 */
inline int getTotalQueueSize(CommandQueue* self);

/**
 * Return the number of unprocessed commands in the queue
 * 
 * @param self The command queue
 * 
 * @return the number of unprocessed items in the queue.
 */
inline int getUnprocessedQueueSize(CommandQueue* self);
#endif // !__COMMAND_QUEUE_H__

