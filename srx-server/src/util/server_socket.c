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
 * Provides functionality to handle the SRx server socket.
 *
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 *   0.3.0.10- 2013/01/25 - oborchert
 *             * Removed un-used include glib.h 
 *   0.3.0.0 - 2013/01/25 - oborchert
 *             * Removed error output if an attempt of removing an already removed
 *               client thread from the client list.
 *             * Removed dead code.
 *             * Re-formated some documentation and code.
 *           - 2013/01/04 - oborchert
 *             * Added parameter goodByeReceived to ClientThread structure.
 *           - 2012/12/13 - oborchert
 *             * //TODO Make SVN compare
 *   0.2.0.0 - 2011/01/07 - oborchert
 *             * Changelog added with version 0.2.0 and date 2011/01/07
 *             * Version tag added
 *   0.1.0.0 - 2009/12/23 - pgleichm
 *             * Code Created
 * -----------------------------------------------------------------------------
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "util/log.h"
#include "util/mutex.h"
#include "util/packet.h"
#include "util/slist.h"
#include "util/socket.h"
#include "util/server_socket.h"

#define HDR  "([0x%08X] Server Socket): "

/**
 * A single client thread.
 */

/**
 * Sends data as a packet (length, data).
 *
 * USE sendNum directly
 *
 * @param fd Socket file-descriptor
 * @param data Data to send
 * @param len Size of the data
 */
static inline void sendData(int* fd, void* data, PacketLength len)
{
  if (!sendNum(fd, data, (size_t)len))
  {
    RAISE_ERROR("Data could not be send!");
  }
}

/**
 * NULL-safe frees memory.
 *
 * @param ptr Memory to free
 */
static inline void safeFree(void* ptr)
{
  if (ptr != NULL)
  {
    free(ptr);
  }
}

/**
 * Initializes the writeMutex inside ClientThread.
 * 
 * @param cthread Instance of the client thread
 * @return \c true = created, \c false = failed to create
 */
static bool initWriteMutex(ClientThread* cthread)
{
  if (!initMutex(&cthread->writeMutex))
  {
    RAISE_ERROR("Failed to create a write-mutex for a client connection");
    return false;
  }
  return true;
}

/**
 * Clean-up of a single ClientThread.
 *
 * @param mode Client mode
 * @param ct Instance
 */
static void clientThreadCleanup(ClientMode mode, ClientThread* ct)
{
  // Let the user know about the client loss
  if (ct->svrSock->statusCallback != NULL)
  {
    ct->svrSock->statusCallback(ct->svrSock,
                                (mode == MODE_SINGLE_CLIENT) ? ct : NULL,
                                ct->clientFD, false, ct->svrSock->user);
  }

  // Information
  if (ct->svrSock->verbose)
  {
    char buf[MAX_SOCKET_STRING_LEN];

    LOG(LEVEL_INFO, "Client disconnected: %s",
        socketToStr(ct->clientFD, true, buf, MAX_SOCKET_STRING_LEN));
  }

  // The instance can be reused
  releaseMutex(&ct->writeMutex);
  ct->active = false;
}

/*----------------------------
 * MODE_SINGLE_CLIENT routines
 */

/** 
 * Sends a single packet.
 *
 * @note MODE_SINGLE_CLIENT
 * 
 * @param client The client thread for this connection.
 * @param data   The packet to send
 * @param size   The size of the packet to send.
 */
static bool single_sendResult(ServerClient* client, void* data, size_t size)
{
  ClientThread* clt = (ClientThread*)client;
  bool retVal = true;
  // Only when still active
  if (clt->active)
  {
    lockMutex(&clt->writeMutex);
    sendData(&clt->clientFD, data, (PacketLength)size);
    unlockMutex(&clt->writeMutex);
  }
  else
  {
    RAISE_ERROR("Trying to send a packet over an inactive connection");
    retVal = false;
  }
  
  return retVal;
}

/**
 * PacketReceived to ServerPacketReceived wrapper.
 * 
 * @param header the received data
 * @param clientThread the user ClientThread instance
 */
static void single_packetHandler(SRXPROXY_BasicHeader* header,
                                 void* clientThread)
{
  ClientThread* cthread = (ClientThread*)clientThread;
  cthread->svrSock->modeCallback(cthread->svrSock, cthread, header, 
                                 ntohl(header->length), cthread->svrSock->user);
}

/** 
 * Thread that handles the packets of a single client.
 *
 * @note MODE_SINGLE_CLIENT
 * @note PThread syntax
 *
 * @param data ClientThread instance
 */
#include <signal.h>

void sigusr_pipe_handler(int signo)
{
  LOG(LEVEL_DEBUG, "([0x%08X]) received SIGPIPE from broken socket --> keep alive ", pthread_self());
  //shutdown(g_single_thread_client_fd, SHUT_RDWR);
  close(g_single_thread_client_fd);
}


static void* single_handleClient(void* clientThread)
{
  ClientThread* cthread = (ClientThread*)clientThread;

  struct sigaction act;
  sigset_t errmask;
  sigemptyset(&errmask);
  sigaddset(&errmask, SIGPIPE);
  act.sa_handler = sigusr_pipe_handler;
  sigaction(SIGPIPE, &act, NULL);
  pthread_sigmask(SIG_UNBLOCK, &errmask, NULL);
  g_single_thread_client_fd = cthread->clientFD;

  LOG(LEVEL_DEBUG, "([0x%08X]) > Proxy Client Connection Thread started "
                   "(ServerSocket::single_handleClient)", pthread_self());
  LOG(LEVEL_DEBUG, HDR "Inside new client thread, about to start traffic "
                    "listener.", pthread_self());
  if (initWriteMutex(cthread))
  {
    // Start the receiver loop of this client connection.
    (void)receivePackets(&cthread->clientFD, single_packetHandler, cthread, 
                         PHT_SERVER);
  }

  clientThreadCleanup(MODE_SINGLE_CLIENT, cthread);
  
  LOG(LEVEL_DEBUG, "([0x%08X]) > Proxy Client Connection Thread stopped "
                   "(ServerSocket::single_handleClient)", pthread_self());
  
  pthread_exit(0);
}

/*----------------------
 * MODE_MULTIPLE_CLIENTS
 */

/**
 * A single packet thread.
 *
 * @note MODE_MULTIPLE_CLIENTS
 */
typedef struct
{
  // Data that never changes - just to pass it
  ClientThread* clThread;
  Mutex* readMutex;
  Mutex* writeMutex; // Unlike "readMutex" this is just a weak copy

  // "Pool" data
  pthread_t thread;
  bool active;
  void* buffer;
  size_t bufferSize;

  // Data that changes on every access
#pragma pack(1)

  struct
  {
    uint32_t id;
    PacketLength packetLen;
  } hdr;
#pragma pack(0)
} PacketThread;

/**
 * Sends the result back to the client.
 *
 * @note MODE_MULTIPLE_CLIENTS
 *
 * @param client Client
 * @param data Data (= result) to send
 * @param size Size of the \c data in Bytes
 */
static bool multi_sendResult(ServerClient* client, void* data, size_t size)
{
  PacketThread* pt = (PacketThread*)client;

  if (pt->clThread->active)
  {
    // Lock so that id and packet do not get separated
    lockMutex(pt->writeMutex);

    // Send the id and data
    if (sendNum(&pt->clThread->clientFD,
                &pt->hdr.id, sizeof (uint32_t)))
    {
      sendData(&pt->clThread->clientFD, data, (PacketLength)size);
    }

    // Now other threads can send too
    unlockMutex(pt->writeMutex);
    return true;
  }

  RAISE_ERROR("Invalid call - invoke inside the 'received' callback");
  return false;
}

/**
 * Receives a single packet, calls the callback and then waits until the
 * client-thread unblocks this call.
 *
 * @note MODE_MULTIPLE_CLIENTS
 * @note PThread syntax
 *
 * @param arg PacketThread instance
 * @return \c 0 = successful, \c 1+ = error
 */
static void* multi_handleSinglePacket(void* arg)
{
  PacketThread* pt = (PacketThread*)arg;
  bool succ;

  LOG (LEVEL_DEBUG, "([0x%08X]) > Server Socket (SinglePacketHandler) thread "
                    "started!", pthread_self());
  
  // Buffer not large enough - resize
  if (pt->bufferSize < pt->hdr.packetLen)
  {
    void* newBuf = realloc(pt->buffer, pt->hdr.packetLen);

    // Not enough memory
    if (newBuf == NULL)
    {
      if (pt->bufferSize > 0)
      {
        free(pt->buffer);
      }
      RAISE_SYS_ERROR("Not enough memory for the packet data");
      pthread_exit((void*)1);
    }

    pt->buffer = newBuf;
    pt->bufferSize = pt->hdr.packetLen;
  }

  // Receive the packet
  succ = recvNum(&pt->clThread->clientFD, pt->buffer, pt->hdr.packetLen);
  unlockMutex(pt->readMutex);

  // Let the user-callback process the packet 
  if (succ)
  {
    ((ServerPacketReceived)pt->clThread->svrSock->modeCallback)(
                                                  pt->clThread->svrSock, pt,
                                                  pt->buffer, pt->hdr.packetLen,
                                                  pt->clThread->svrSock->user);
  }

  pt->active = false;
  
  LOG (LEVEL_DEBUG, "([0x%08X]) < Server Socket (SinglePacketHandler) thread "
                    "stopped!", pthread_self());      
  
  pthread_exit(succ ? 0 : (void*)2);
}

/**
 * Thread that reads all packets and passes them to a callback.
 *
 * @note MODE_MULTIPLE_CLIENTS
 * @note PThread syntax
 *
 * @param data ClientThread instance
 * @return Always \c 0
 */
static void* multi_handleClient(void* data)
{
  RAISE_SYS_ERROR("LOOK1 ****************************************************");
  
  ClientThread* cthread = (ClientThread*)data;
  Mutex rmutex;
  SList packetThreads;
  SListNode* node;
  PacketThread* currPT;
  
  LOG(LEVEL_DEBUG, "([0x%08X]) > Proxy Client Connection Thread started "
                   "(ServerSocket::multi_handleClient)", pthread_self());
  
  // Write-mutex
  if (!initWriteMutex(cthread))
  {
    clientThreadCleanup(MODE_MULTIPLE_CLIENTS, cthread);
    
    LOG(LEVEL_DEBUG, "([0x%08X]) < Proxy Client Connection Thread stopped (1) "
                     " (ServerSocket::multi_handleClient)", pthread_self());
    
    pthread_exit((void*)1);
  }

  // Create the read-mutex
  if (!initMutex(&rmutex))
  {
    RAISE_ERROR("Failed to create a read mutex for the client thread");
    clientThreadCleanup(MODE_MULTIPLE_CLIENTS, cthread);

    LOG(LEVEL_DEBUG, "([0x%08X]) < Proxy Client Connection Thread stopped (2) "
                     "(ServerSocket::multi_handleClient)", pthread_self());
    
    pthread_exit((void*)2);
  }

  // A thread per command
  initSList(&packetThreads);

  // Process all packets
  for (;;)
  {
    // Look for an inactive node and recycle it

    FOREACH_SLIST(&packetThreads, node)
    {
      if (!((PacketThread*)getDataOfSListNode(node))->active)
      {
        break;
      }
    }

    // Found an inactive node - use it
    if (node != NULL)
    {
      currPT = (PacketThread*)getDataOfSListNode(node);

      // Otherwise, create a new node
    }
    else
    {
      currPT = appendToSList(&packetThreads, sizeof (PacketThread));
      if (currPT == NULL)
      {
        RAISE_SYS_ERROR("Not enough space to receive another packet");
        break;
      }
      currPT->clThread = cthread;
      currPT->writeMutex = &cthread->writeMutex;
      currPT->readMutex = &rmutex;
      currPT->buffer = NULL;
      currPT->bufferSize = 0;
    }

    // Get the id and packet length
    lockMutex(&rmutex);
    if (!recvNum(&cthread->clientFD, (void*)&currPT->hdr,
                 sizeof (PacketLength) + sizeof (uint32_t)))
    {
      break;
    }

    // Receive and process in a separate thread
    currPT->active = true;
    pthread_create(&currPT->thread, NULL, multi_handleSinglePacket,
                   (void*)currPT);
  }

  // Thread list and internal buffers clean-up

  FOREACH_SLIST(&packetThreads, node)
  {
    safeFree(((PacketThread*)getDataOfSListNode(node))->buffer);
  }
  releaseSList(&packetThreads);

  // Mutex
  releaseMutex(&rmutex);

  // Finish up
  clientThreadCleanup(MODE_MULTIPLE_CLIENTS, cthread);

  LOG(LEVEL_DEBUG, "([0x%08X]) < Proxy Client Connection Thread stopped (3) "
                   "(ServerSocket::multi_handleClient)", pthread_self());
  
  pthread_exit(0);
}

/*---------------------
 * MODE_CUSTOM_CALLBACK
 */

/**
 * Thread that simply passes execution to the user's callback.
 *
 * @note MODE_CUSTOM_CALLBACK
 * @note PThread syntax
 *
 * @param data ClientThread instance
 * @return Always \c 0
 */
static void* custom_handleClient(void* data)
{
  ClientThread* cthread = (ClientThread*)data;
  
  LOG(LEVEL_DEBUG, "([0x%08X]) > Proxy Client Connection Thread started "
                   "(ServerSocket::custom_handleClient)", pthread_self());

  if (initWriteMutex(cthread))
  {
    cthread->svrSock->modeCallback(cthread->svrSock, cthread->clientFD, 
                                   cthread->svrSock->user);
// ((ClientConnectionAccepted)cthread->svrSock->modeCallback)(cthread->svrSock, 
//                                                            cthread->clientFD,
//                                                      cthread->svrSock->user);
  }
  clientThreadCleanup(MODE_CUSTOM_CALLBACK, cthread);
  
  LOG(LEVEL_DEBUG, "([0x%08X]) < Proxy Client Connection Thread stopped "
                   "(ServerSocket::custom_handleClient)", pthread_self());
  
  pthread_exit(0);
}

/*--------
 * Exports
 */

/**
 * Create the server socket where SRx is listening on.
 * @param self
 * @param port
 * @param verbose
 * @return
 */
bool createServerSocket(ServerSocket* self, int port, bool verbose)
{
  struct sockaddr_in addr;
  int yes = 1;

  // Create a TCP socket
  self->serverFD = socket(AF_INET, SOCK_STREAM, 0);
  if (self->serverFD < 0)
  {
    RAISE_SYS_ERROR("Failed to open a socket");
    return false;
  }

  // Bind to a server-address
  bzero(&addr, sizeof (struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY; // inet_pton
  addr.sin_port = htons(port);

  // Inserted to be able to restart after crash without having to wait for the 
  // socket to be released by the OS.
  setsockopt(self->serverFD, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (yes));

  if (bind(self->serverFD, (struct sockaddr*)&addr, 
           sizeof (struct sockaddr_in)) < 0)
  {
    switch (errno)
    {
      case EADDRINUSE:
        RAISE_ERROR("The specified address is already in use.");
        break;
      case EADDRNOTAVAIL:
        RAISE_ERROR("The specified address is not available from the local "
          "machine.");
        break;
      case EAFNOSUPPORT:
        RAISE_ERROR("The specified address is not a valid address for the "
          "address family of the specified socket.");
        break;
      case EBADF:
        RAISE_ERROR("The socket argument is not a valid file descriptor.");
        break;
      case EINVAL:
        RAISE_ERROR("The socket is already bound to an address, and the "
          "protocol does not support binding to a new address; or the socket "
          "has been shut down.");
        break;
      case ENOTSOCK:
        RAISE_ERROR("The socket argument does not refer to a socket.");
        break;
      case EOPNOTSUPP:
        RAISE_ERROR("The socket type of the specified socket does not support "
          "binding to an address.");
        break;
      case EACCES:
        RAISE_ERROR("A component of the path prefix denies search permission, "
          "or the requested name requires writing in a directory with a mode "
          "that denies write permission.");
        break;
      case EDESTADDRREQ:
      case EISDIR:
        RAISE_ERROR("The address argument is a null pointer.");
        break;
      case EIO:
        RAISE_ERROR("An I/O error occurred.");
        break;
      case ELOOP:
        RAISE_ERROR("A loop exists in symbolic links encountered during "
          "resolution of the pathname in address.");
        break;
      case ENAMETOOLONG:
        RAISE_ERROR("A component of a pathname exceeded {NAME_MAX} characters, "
          "or an entire pathname exceeded {PATH_MAX} characters.");
        break;
      case ENOENT:
        RAISE_ERROR("A component of the pathname does not name an existing "
          "file or the pathname is an empty string.");
        break;
      case ENOTDIR:
        RAISE_ERROR("A component of the path prefix of the pathname in address "
          "is not a directory.");
        break;
      case EROFS:
        RAISE_ERROR("The name would reside on a read-only file system.");
        break;
      case EISCONN:
        RAISE_ERROR("The socket is already connected.");
        break;
      case ENOBUFS:
        RAISE_ERROR("Insufficient resources were available to complete the "
          "call.");
        break;
      default:
        RAISE_ERROR("Unknown Error.");
    }    
    LOG(LEVEL_INFO, "Failed to bind the socket to the address, check if "
      "another process locks the port \'fuser -n tcp %u\'", port);
    close(self->serverFD);
    return false;
  }

  // Misc. variables
  self->stopping = 0;
  self->verbose = verbose;

  return true;
}

/**
 * This is the server loop for the SRx - Proxy server connection.
 * 
 * @param self
 * @param clMode
 * @param modeCallback
 * @param statusCallback
 * @param user
 */
void runServerLoop(ServerSocket* self, ClientMode clMode,
                   void (*modeCallback)(), ClientStatusChanged statusCallback,
                   void* user)
{
  static void* (*CL_THREAD_ROUTINES[NUM_CLIENT_MODES])(void*) = {
                               single_handleClient,
                               multi_handleClient,
                               custom_handleClient
  };

  int cliendFD;
  struct sockaddr caddr;
  socklen_t caddrSize;
  char infoBuffer[MAX_SOCKET_STRING_LEN];
  ClientThread* cthread;
  int ret;

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

  // Store the arguments
  self->mode = clMode;
  self->modeCallback = modeCallback;
  self->statusCallback = statusCallback;
  self->user = user;

  // No active threads
  initSList(&self->cthreads);

  // Prepare socket to accept connections
  listen(self->serverFD, MAX_PENDING_CONNECTIONS);
  
  for (;;)
  {
    LOG(LEVEL_DEBUG, HDR "Server loop, wait for proxy clients...", 
                     pthread_self());
    // Wait for a connection from SRX proxy
    caddrSize = sizeof (struct sockaddr);
    cliendFD = accept(self->serverFD, &caddr, &caddrSize);

    // An (maybe intentional) error occurred - quit the loop
    if (cliendFD < 0)
    {
      // Socket has been closed
      if (errno == EBADF || errno == ECONNABORTED)
      {
        break;
      }

      // A non-processable error
      RAISE_SYS_ERROR("An error occurred while waiting for connections");
      break;
    }

    // Information
    if (self->verbose)
    {
      LOG(LEVEL_DEBUG, HDR "New client connection: %s", pthread_self(),
          sockAddrToStr(&caddr, infoBuffer, MAX_SOCKET_STRING_LEN));
      LOG(LEVEL_INFO, "New client connection: %s",
          sockAddrToStr(&caddr, infoBuffer, MAX_SOCKET_STRING_LEN));
    }

    // Spawn a thread for the new connection
    cthread = (ClientThread*)appendToSList(&self->cthreads,
                                           sizeof (ClientThread));
    if (cthread == NULL)
    {
      RAISE_ERROR("Not enough memory for another connection");
      close(cliendFD);
    }
    else
    {
      bool accepted = true;
      
      // Let the user know about the new client
      if (self->statusCallback != NULL)
      {
////////////////////////////////////////////////////////////////////////////////
        //TODO: the mode might not be needed anymore
        accepted = self->statusCallback(self,
                                        (clMode == MODE_SINGLE_CLIENT) ? cthread
                                                                       : NULL,
                                        cliendFD, true, self->user);
      }

      // Start the thread
      if (accepted)
      {
        cthread->active          = true;
        cthread->initialized     = false;
        cthread->goodByeReceived = false;
        
        cthread->proxyID  = 0; // will be changed for srx-proxy during handshake
        cthread->routerID = 0; // Indicates that it is currently not usable, 
                               // must be set during handshake
        cthread->clientFD = cliendFD;
        cthread->svrSock  = self;
        cthread->caddr	  = caddr;

        ret = pthread_create(&(cthread->thread), &attr,
                             CL_THREAD_ROUTINES[clMode],
                             (void*)cthread);
        if (ret != 0)
        {
          accepted = false;
          RAISE_ERROR("Failed to create a client thread");
        }
      }

      // Error or the callback denied the client
      if (!accepted)
      {
        close(cliendFD);
        deleteFromSList(&self->cthreads, cthread);
      }
    }
  }
}

/**
 * Stops the particular client thread by closing the connection, ending the 
 * thread and releasing the mutex.
 *
 * @param clt A ClientThread instance
 */
static void _killClientThread(void* clt)
{
  ClientThread* clientThread = (ClientThread*)clt;

  if (clientThread->active)
  {
    // Close the client connection
    close(clientThread->clientFD);

    // Wait until the thread terminated - if necessary
    //pthread_join(clientThread->thread, NULL);
    pthread_cancel(clientThread->thread);

    // Release the write-mutex
    releaseMutex(&clientThread->writeMutex);
    
    // Set it inactive
    clientThread->active = false;
  }
}

/**
 * Stop the server loop, kills all client threads and closes the sockets.
 * 
 * @param self The server socket instance.
 */
void stopServerLoop(ServerSocket* self)
{
  if (++self->stopping == 1)
  {
    // Stop accepting connections 
    close(self->serverFD);

    // Kill all threads
    foreachInSList(&self->cthreads, _killClientThread);
    releaseSList(&self->cthreads);
  }
}

//TODO: Maybe Change the signature and remove the ServerSocket instance. 
// Not needed in the future, it only provides the mode and this will disappear
bool sendPacketToClient(ServerSocket* self, ServerClient* client,
                        void* data, size_t size)
{
  if (self == NULL)
  {
    RAISE_ERROR("Server Socket instance is NULL");
    return false;
  }

  if (self->mode == MODE_SINGLE_CLIENT)
  {
    return single_sendResult(client, data, size);
  }
  if (self->mode == MODE_MULTIPLE_CLIENTS)
  {
    return multi_sendResult(client, data, size);
  }
  RAISE_ERROR("Cannot send packets in this mode");
  return false;
}

/**
 * Closes the connection associated with the given client.
 * 
 * @param self The server socket whose client has to be handled,
 * @param client The client connection object to be closed.
 * 
 * @return true if the socket could be closed.
 */
int closeClientConnection(ServerSocket* self, ServerClient* client)
{
  ClientThread* clientThread = (ClientThread*)client;

  LOG(LEVEL_DEBUG, HDR "Close and remove client: Thread [0x%08X]; [ID :%u]; "
                       "[FD: 0x%08X]", pthread_self() , clientThread->thread,
                       clientThread->proxyID, clientThread->clientFD);
  
  //deleteMapping(self, clientThread);
  _killClientThread(clientThread);
  LOG(LEVEL_DEBUG, HDR "Client connection [ID:%u] closed!", pthread_self(),
                  clientThread->proxyID);
  LOG(LEVEL_INFO, "Client connection [ID:%u] closed!", clientThread->proxyID);

  deleteFromSList(&self->cthreads, clientThread);
  
  return true;
}

