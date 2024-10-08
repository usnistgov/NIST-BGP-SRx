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
 * Function to create a server-socket and to start/stop a server runloop.
 * Provides functionality to handle the SRx server socket.
 *
 * @version 0.6.1.3
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 *  0.6.1.3 - 2024/06/12 - oborchert
 *            * Fixed linker error in 'ROCKY 9' regarding the variable declaration
 *              int g_single_thread_client_fd which needs to be declared in the .c
 *              file and listed here as extern.
 *  0.5.0.0 - 2017/06/16 - oborchert
 *            * Version 0.4.1.0 is trashed and moved to 0.5.0.0
 *  0.5.0.0 - 2016/08/19 - oborchert
 *            * Moved socket connection error strings to this header file.
 *  0.3.0.0 - 2013/01/04 - oborchert
 *            * Added parameter goodByeReceived to ClientThread structure.
 *          - 2012/12/13 - oborchert
 *            * //TODO Make SVN compare
 *  0.2.0.0 - 2011/01/07 - oborchert
 *            * Changelog added with version 0.2.0 and date 2011/01/07
 *            * Version tag added
 *  0.1.0.0 - 2009/12/23 - pgleichm
 *            * Code Created
 * -----------------------------------------------------------------------------
 *
 *
 * //TODO: TO BE DELETED
 * The runloop acts depending on the ClientMode:
 *
 * <table>
 * <tr>
 *   <th>ClientMode</th>
 *   <th>Description</th>
 *   <th>runServerLoop \c callback type</th>
 *   <th>Handles packets</th>
 * </tr>
 * <tr>
 *   <td>MODE_SINGLE_CLIENT</td>
 *   <td>1 client, 1 connection</td>
 *   <td>ServerPacketReceived</td>
 *   <td>yes</td>
 * </tr>
 * <tr>
 *   <td>MODE_MULTIPLE_CLIENTS</td>
 *   <td>N clients, 1 connection</td>
 *   <td>ServerPacketReceived</td>
 *   <td>yes</td>
 * </tr>
 * <tr>
 *   <td>MODE_CUSTOM_CALLBACK</td>
 *   <td>Handling is up to user's callback</td>
 *   <td>ClientConnectionAccepted</td>
 *   <td>no</td>
 * </tr>
 * </table>
 *
 */
#ifndef __SERVER_SOCKET_H__
#define __SERVER_SOCKET_H__

#include "util/mutex.h"
#include "util/packet.h"
#include "util/slist.h"

/** Maximum number of clients waiting to be accepted for connection. */
#define MAX_PENDING_CONNECTIONS 5

////////////////////////////////////////////////////////////////////////////////
// ERROR STRINGS - Moved from code to here with version 0.5.0.0
////////////////////////////////////////////////////////////////////////////////

#define SOC_ERR_EADDRINUSE   "The specified address is already in use."
#define SOC_ERR_EADDRNOTAVAIL "The specified address is not available from " \
                             "the local machine."
#define SOC_ERR_EAFNOSUPPORT "The specified address is not a valid address " \
                             "for the address family of the specified socket."
#define SOC_ERR_EBADF        "The socket argument is not a valid file " \
                             "descriptor."
#define SOC_ERR_EINVAL       "The socket is already bound to an address, and " \
                             "the protocol does not support binding to a new " \
                             "address; or the socket has been shut down."
#define SOC_ERR_ENOTSOCK     "The socket argument does not refer to a socket."
#define SOC_ERR_EOPNOTSUPP   "The socket type of the specified socket does " \
                             "not support binding to an address."
#define SOC_ERR_EACCES       "A component of the path prefix denies search " \
                             "permission, or the requested name requires  " \
                             "writing in a directory with a mode that denies " \
                             "write permission."
#define SOC_ERR_EDESTADDRREQ "The address argument is a null pointer."
#define SOC_ERR_EISDIR       SOC_ERR_EDESTADDRREQ
#define SOC_ERR_EIO          "An I/O error occurred."
#define SOC_ERR_ELOOP        "A loop exists in symbolic links encountered " \
                             "during resolution of the pathname in address."
#define SOC_ERR_ENAMETOOLONG "A component of a pathname exceeded {NAME_MAX} " \
                             "characters, or an entire pathname exceeded " \
                             "{PATH_MAX} characters."
#define SOC_ERR_ENOENT       "A component of the pathname does not name an " \
                             "existing file or the pathname is an empty string."
#define SOC_ERR_ENOTDIR      "A component of the path prefix of the pathname " \
                             "in address is not a directory."
#define SOC_ERR_EROFS        "The name would reside on a read-only file system."
#define SOC_ERR_EISCONN      "The socket is already connected."
#define SOC_ERR_ENOBUFS      "Insufficient resources were available to " \
                             "complete the call."
#define SOC_ERR_UNKOWN       "Unknown Error."

/**
 * The Client-modes.
 * For more details see the detailed description.
 */
typedef enum
{
  MODE_SINGLE_CLIENT = 0, // 1 client  : 1 connection, ServerPacketReceived
  MODE_MULTIPLE_CLIENTS, // N clients : 1 connection, ServerPacketReceived
  MODE_CUSTOM_CALLBACK, // Custom, ClientConnectionAccepted

  NUM_CLIENT_MODES ///< Number of different modes (needs to be the last item)
} ClientMode;

/**
 * A client.
 *
 * @note Currently everything is hidden from the user.
 */
typedef void ServerClient;

/* Forward declaration */
struct _ServerSocket;

/**
 * A server-socket.
 *
 * @note Do not access any of the member variables.
 *
 * @note The typedef'd version is called ServerSocket. A direct definition is 
 *       not possible because a forward declaration is necessary.
 */
typedef struct _ServerSocket ServerSocket;

/**
 * Once a complete packet has been received by the server, this user-defined 
 * function is called.
 * To send the result, use \c sendPacketToClient - for example:
 *
 * @code
 * static my_receiptCallback(...) {
 *   uint32_t result;
 *   :
 *   sendPacketToClient(svrSock, client, &result, sizeof(uint32_t));
 * }
 * @endcode
 *
 * ClientMode: MODE_SINGLE_CLIENT, MODE_MULTIPLE_CLIENTS
 *
 * @param svrSock Server-socket instance
 * @param client Client that sent the packet
 * @param packet Data
 * @param length Number of Bytes of \c packet
 * @param user User-defined data
 */
typedef void (*ServerPacketReceived)(ServerSocket* svrSock,
                                     ServerClient* client,
                                     void* packet, PacketLength length,
                                     void* user);

/**
 * Each time a client connects to the server, this function is called. 
 * Note that the runloop takes care of creating the necessary threads.
 *
 * ClientMode: MODE_CUSTOM_CALLBACK
 *
 * @param svrSock Server-socket instance
 * @param sock Socket of the new client
 * @param user User-defined data
 */
typedef void (*ClientConnectionAccepted)(ServerSocket* svrSock, int sock,
                                         void* user);

/** 
 * Called upon the establishment or loss of a connection to a client. 
 * false as return-value denies the client, true accepts the client.
 *
 * @param svrSock Server-socket instance
 * @param client Client in MODE_SINGLE_CLIENT, otherwise \c NULL
 * @param fd New/lost file descriptor (= socket)
 * @param connected true = new client, false = client lost
 * @param user User-defined data, for srx-server the server connection handler
 * 
 * @return returns true if the client is accepted, otherwise false.
 */
typedef bool (*ClientStatusChanged)(ServerSocket* svrSock, ServerClient* client,
                                    int fd, bool connected, void* user);

/* The actual ServerSocket definition */
struct _ServerSocket
{
  // Arguments
  ClientMode mode;
  void (*modeCallback)();
  ClientStatusChanged statusCallback;
  void* user;

  // Internal variables
  int serverFD;
  int stopping;
  SList cthreads;
  bool verbose;
} ;

/**
 * A single client thread.
 */
typedef struct
{
  /** The thread that handles this client connection. */
  pthread_t thread;

  /** Indicates if the socket is active or not. */
  bool active;
  /** Indicates if this socket thread is ready to receive srx-proxy packets.
   * this happens after a handshake. */
  bool initialized;
  /** The file descriptor of the client socket. */
  int clientFD;
  /** Used as proxyID for SRx-Proxy connections to allow assigning updates to 
   *  the client. */
  uint32_t proxyID;
  
  /** Will be set true as soon as a goodbye PDU is received by this client. This
   * is important to determine if an ordered disconnect from the client is 
   * initiated. Once this flag is set true, no further packets should be send
   * out. All remaining packets should be dropped!
   */
  bool goodByeReceived;

  /** This ID is used SRx-intern. We do not anticipate more than a couple of 
   * attached routers / proxies, max 255 therefore a one byte id is more than
   * sufficient. This ID will be mapped to the updates. */
  uint8_t  routerID;
  
  Mutex writeMutex;

  /* the server socket itself. */
  ServerSocket* svrSock;
  /* The socket address. */
  struct sockaddr caddr;  
#ifdef USE_GRPC 
  bool type_grpc_client; /* between general client and  grpc client */
#endif
} ClientThread;

/**
 * Creates a server-socket and binds it to a specific port.
 *
 * @param self The resulting server-socket
 * @param port Port that the server should listen on
 * @param verbose \c true = enable verbose mode
 * @return \c true = successfully created, \c false = an error occured
 */
bool createServerSocket(ServerSocket* self, int port, bool verbose);

/**
 * Starts the runloop which processes all client connections, and depending 
 * on the mode even the receipt of the packets.
 *
 * @param self Existing server-socket instance
 * @param clMode The client-mode
 * @param modeCallback Callback depending on \c clMode
 * @param statusCallback Function to invoke in case a client dis/connects. 
 *      May be \c NULL.
 * @param user User-defined data - will be passed to \c modeCallback and 
 *      \c statusCallback
 *
 * @see stopServerLoop
 */
void runServerLoop(ServerSocket* self, ClientMode clMode,
                   void (*modeCallback)(),
                   ClientStatusChanged statusCallback,
                   void* user);

/**
 * Stops the runloop, and closes all client connections.
 *
 * @param self Server-socket instance
 * @see runServerLoop
 */
void stopServerLoop(ServerSocket* self);


/**
 * Sends a packet to a clients.
 *
 * @note For MODE_MULTIPLE_CLIENTS this function must be called from
 *       within ServerPacketReceived.
 *
 * @param self Server-socket instance
 * @param client Client
 * @param data Data (w/o length) that should be send
 * @param size Size in Bytes of \c data
 * @return \c true = sent, \c false = an error occurred (e.g. inactive client)
 */
bool sendPacketToClient(ServerSocket* self, ServerClient* client,
                        void* data, size_t size);

/**
 * Closes the connection associated with the given client.
 * 
 * @param self The server socket whose client has to be handled,
 * @param client The client connection object to be closed.
 * 
 * @return true if the socket could be closed.
 */
int closeClientConnection(ServerSocket* self, ServerClient* client);

// TODO: Check if it is still needed - Still used in server_socket.c/h 
// Maybe it can be moved into server_socket.c
// In ROCKY this throws a linker error. The solution is to declare it extern here and then
// make the proper declaration in server_socket.c
extern int g_single_thread_client_fd;

#ifdef USE_GRPC
void runServerLoop_gRPC(ServerSocket* self, ClientMode clMode,
                   void (*modeCallback)(),
                   ClientStatusChanged statusCallback,
                   void* user);
#endif // USE_GRPC
#endif // !__SERVER_SOCKET_H__

