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
 *            * Removed types.h
 * 0.3.0    - 2013/02/15 - oborchert
 *            * Added the number of updates linked to the ProxyClientMapping
 *          - 2013/02/12 - oborchert
 *            * Removed delMapping from header file. The code will still be 
 *              executed with the call of deaktivateMapping.
 *          - 2013/01/28 - oborchert
 *            * Finished mapping configuration.
 *          - 2013/01/22 - oborchert
 *            * Added internal receiver queue. (can be configured!)
 *          - 2013/01/05 - oborchert
 *            * Renamed ProxyClientMap into ProxyClientMaping
 *            * Added documentation to C file
 *          - 2013/01/04 - oborchert
 *            * Added isShutdown parameter to structure
 *            * Added system configuration to structure
 *          - 2012/12/31 - oborchert
 *            * Added Version control
 *            * Bug fix in prefix preparation for storing in update cache
 *          - 2012/12/17 - oborchert
 *            * Partially rewritten message flow.
 * 0.2.0    - 2011/11/01 - oborchert
 *            * Rewritten.
 * 0.1.0    - 2010/04/15 - pgleichm
 *            * Code Created
 * -----------------------------------------------------------------------------
 *
 */
#ifndef __SERVER_CONNECTION_HANDLER_H__
#define __SERVER_CONNECTION_HANDLER_H__

#include "server/configuration.h"
#include "server/command_queue.h"
#include "server/update_cache.h"
#include "util/server_socket.h"
#include "util/slist.h"

/** This Structure is used to identify proxies. IMPORTANT though to mention is 
 * that this map is ONLY used for initial mapping. Once the mapping is done the
 * value will be distributed into the rdata structures for speedup. This map
 * is not intended to be queried for each and every update notification
 * sending request. For this, the clientID will be stored in the managing 
 * connection thread as "routerID" The data transfer though should be performed
 * right after a handshake was successful. */
typedef struct {
  /** Contains the ID of the proxy to be attached, Zero "0" for unassigned. */
  uint32_t proxyID;
  /** Contains the Socket information */
  void* socket;
  /** Defines if the map entry is actively used at this point in time.*/
  bool isActive;
  /** Specifies if this entry is pre-defined using a configuration script. */
  bool preDefined;
  /** If other than zero "0" then it specifies the time when the connected
   * connection was reported lost (crashed).*/
  __time_t crashed;
  /** Number of updates assigned to this client. This allows a more efficient
   * cleanup. */
  uint32_t updateCount;  
} ProxyClientMapping;

#define MAX_PROXY_CLIENT_ELEMENTS MAX_PROXY_MAPPINGS

/**
 * A single Server Connection.
 */
typedef struct {
  // indicates if the system is in shutdown mode - used for detecting loss of
  // connection while shutdown. this prevents some error messages due to
  // loss of connectivity. (since 0.3.0)
  bool               inShutdown;
  // The server socket for SRx - proxy communication
  ServerSocket       svrSock;
 
  // Contains the commands to be processed
  CommandQueue*      cmdQueue;

  // Contains the proxy connections
  SList              clients;
  
  /** Contains the proxy Map - The proxy map will be an array of 256 elements.
   * This might not be the most memory efficient structure but fast. The 
   * clientID is the location in the array. The element of ID=0 MUST NOT be
   * used!!! */
  ProxyClientMapping proxyMap[MAX_PROXY_CLIENT_ELEMENTS];
  // The number of installed proxyID-clientID mappings, active and inactive!
  uint8_t            noMappings; 

  // Newly added to allow lookups within the update cache
  // Use this for read only !!!
  UpdateCache*       updateCache;
  
  // Contains the system configuration.
  Configuration*     sysConfig;
  
  // The internal receiver queue. NULL if not used. since 0.3.0
  void*              receiverQueue;
} ServerConnectionHandler;

/**
 * Initialized the connection handler and creates a server-socket and
 * binds it to the port specified in the system configuration.
 *
 * @param self The connection handler to be initialized. It is required that the
 *             connection handler is already instantiated (memory is allocated)
 * @param updCache Reference to the update cache. the cache MUST NOT be accessed
 *                 for writing, only reading.
 * @param sysConfig The system configuration.
 *
 * @return true if the handler could be initialized properly, otherwise false
 */
bool createServerConnectionHandler(ServerConnectionHandler* self, 
                                   UpdateCache* updCache, 
                                   Configuration* sysConfig);

/**
 * Frees allocated resources.
 *
 * @param self The connection handler itself
 */
void releaseServerConnectionHandler(ServerConnectionHandler* self);

/**
 * Provides the server loop that waits for all client requests processes them.
 *
 * @note Blocking-call!
 *
 * @param self The server connection handler.
 * @param cmdQueue Existing Command Queue
 * @see stopProcessingRequests
 */
void startProcessingRequests(ServerConnectionHandler* self, 
                             CommandQueue* cmdQueue);

/** 
 * Stops processing client requests.
 * Closes all client connections and the server-socket.
 *
 * @param self The server connection handler.
 */
void stopProcessingRequests(ServerConnectionHandler* self);

/**
 * Set the shutdown flag. 
 * 
 * @param self The connection handler instance
 * 
 * @since 0.3.0
 */
void markConnectionHandlerShutdown(ServerConnectionHandler* self);

/**
 * Sends a packet to all connected clients.
 *
 * @param self The server connection handler.
 * @param packet Data-stream
 * @param length Length of \c packet in Bytes
 * @return \c true = sent, \c false = failed
 */
bool broadcastPacket(ServerConnectionHandler* self,
                     void* packet, PacketLength length);

/**
 * Allows to pre-configure the proxy Map. This function performs all mappings 
 * or none.
 * 
 * @param self The server connection handler.
 * @param mappings The proxy mappings, an array of 256 elements.
 * 
 * @return true if the mappings could be performed, otherwise false and no 
 *              mapping was added at all.
 * 
 * @since 0.3
 */
bool configureProxyMap(ServerConnectionHandler* self, uint32_t* mappings);

/**
 * Search for the mapping of the provided proxy ID.
 * 
 * @param self The server connection handler.
 * @param proxyID The proxy whose mapping is requested.
 * 
 * @return The id of the proxyClient or zero "0".
 * 
 * @since 0.3.0
 */
uint8_t findClientID(ServerConnectionHandler* self, uint32_t proxyID);

/**
 * Create a new client ID and return it.
 * 
 * @param self The server connection handler.
 * 
 * @return The newly generated clientID or zero "0" if no more are available
 * 
 * @since 0.3.0
 */
uint8_t createClientID(ServerConnectionHandler* self);

/**
 * Attempt to add the provided Mapping. The mapping will fail if either of
 * the provided entries is actively mapped already. Adding a mapping does not
 * alter the attribute "predefined".
 * 
 * @param self The server connection handler.
 * @param proxyID array containing "mappings" number of proxy ID's
 * @param clientID array containing "mappings" number of client ID's
 * @param cSocket The client socket, can be NULL.
 * @param activate indicates if the mapping will be immediately activated. 
 *        This should not be done for predefining mappings. If activate is false
 *        the mapping will be considered pre-configured by default
 * 
 * @return true if the mapping could be performed.
 * 
 * @since 0.3
 */
bool addMapping(ServerConnectionHandler* self, uint32_t proxyID, 
                uint8_t clientID, void* cSocket, bool activate);

/**
 * Set the activation flag for the given client. This method returns true only
 * if a mapping for this client exist. This method only manipulates the internal
 * flag but does not alter the connectivity in any way.
 * 
 * @param self The server connection handler.
 * @param clientID The client id
 * @param value The new value of the active flag
 * 
 * @return true if a mapping exists.
 * 
 * @since 0.3.0
 */
bool setActivationFlag(ServerConnectionHandler* self, uint8_t clientID,
                        bool value);

/** 
 * Mark the this connection as closed. In case the connection closed without a 
 * crash and it was NOT pre-configured, it attempts to delete an existing 
 * mapping. This method requires an inactive mapping.  If the mapping is 
 * pre-defined, only the socket will be NULL'ed.
 * 
 * @param self The server connection handler.
 * @param clientID The client id
 * @param crashed indicator if the connection crashed
 * @param keepWindow Indicates how long the update should remain in the system 
 *                   before the garbage collector removes it.
 * 
 * @since 0.3.0
 */
void deactivateConnectionMapping(ServerConnectionHandler* self, 
                                 uint8_t clientID, bool crashed, 
                                 uint16_t keepWindow);
#endif // !__SERVER_CONNECTION_HANDLER_H__

