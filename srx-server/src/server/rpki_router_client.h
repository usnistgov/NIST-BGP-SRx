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
 * RPKI/Router protocol client-side implementation.
 *
 * Uses log.h for error reporting
 * 
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 * 0.3.0.7  - 2015/04/17 - oborchert
 *            * BZ599 - Changed typecase from (int) to (uintptr_t) to prevent 
 *              compiler warnings and other nasty side affects while compiling
 *              on 32 and 64 bit OS.
 * 0.3.0.0  - 2013/01/28 - oborchert
 *            * Update to be compliant to draft-ietf-sidr-rpki-rtr.26. This 
 *              update does not include the secure protocol section. The protocol
 *              will still use un-encrypted plain TCP
 *          - 2012/12/17 - oborchert
 *            * Adapted to the changes in the underlying client socket structure.
 *            * Fixed some spellers in documentation
 *            * Added documentation TODO
 * 0.2.0.0  - 2011/03/27 - oborchert
 *            * Changed implementation to follow draft-ietf-rpki-rtr-10
 * 0.1.0.0  - 2010/03/11 - pgleichm
 *            * Code Created
 * -----------------------------------------------------------------------------
 */
#ifndef __RPKI_ROUTER_CLIENT_H__
#define __RPKI_ROUTER_CLIENT_H__

#include <pthread.h>
#include "shared/rpki_router.h"
#include "util/client_socket.h"
#include "util/mutex.h"
#include "util/prefix.h"

/** Maximum allowable RPKI header. After that the rest will be dropped. */
#define RPKI_MAX_HEADER_LENGTH 102400
/** The maximum number of reconnect attempts within one connection request. */
#define MAX_RECONNECTION_ATTEMPTS 10

/**
 * Client parameter settings.
 */
typedef struct {
  // Handlers
  /**
   * This function is called for each prefix announcement / withdrawl received
   * from the RPKI validation cache.
   * 
   * @param valCacheID  This Id represents the cache. It is used to be able to 
   *                    later on identify the white-list / ROA entry in case the 
   *                    cache state changes.
   * @param sessionID   The cache sessionID entry for this data. It is be useful
   *                    for sessionID changes in case SRx is implementing a 
   *                    performance driven approach.
   * @param isAnn       Indicates if this in an announcement or not.
   * @param prefix      The prefix itself. Contains the information of v4/v6
   * @param maxLen      the maximum length this white-list / ROA entry covers.
   * @param oas         The origin AS for this entry.
   * @param user        Some user data. (might be deleted later on)             // THIS MIGHT BE DELETED LATER ON
   */
  void (*prefixCallback)(uint32_t valCacheID, uint16_t sessionID,
                         bool isAnn, IPPrefix* prefix, uint16_t maxLen,
                         uint32_t oas, void* user);


  /**
   * The cache/server sent a reset response. Usually, the client should reset 
   * his own cache.
   * 
   * @note There is no need to send a reset query - this was done already
   * The cache though can reestablish the connection similar to a cache session
   * id change.
   *
   * @param user User data
   */
  void (*resetCallback)(uint32_t valCacheID,  void* user);

  /**
   * This method is called in case of a cache session id change. This normally
   * requires a total cache reset and start from new. After this method a
   * RESET QUERY will be called and once all data are received the method
   * sessionIDEstablished will be called! (if provided!).
   *
   * Process flow:
   *
   * Change of the sessionID field:
   *
   * (1) sessionIDChanged
   * (2) - RESET QUERY and refill the cache
   *     - or abandon the cache completely
   * (3) sessionIDEstablished
   *
   *
   * @param valCacheID The id of the cache whose sessionID changed.
   * @param newSessionID The new cache sessionID.
   */
  void (*sessionIDChangedCallback)(uint32_t valCacheID, uint16_t newSessionID);

  /**
   * This method will be called after a cache sessionID change and reset query
   * was executed. This method also will be called if the decision was
   * made to abandon the cache after a cache session id change.
   *
   * @param valCacheID The id of the cache whose sessionID changed.
   * @param newSessionID The new cache sessionID.
   */
  void (*sessionIDEstablishedCallback)(uint32_t valCacheID, 
                                       uint16_t newSessionID);

  /**
   * An error report was received. 
   *
   * @note Optional - can be \c NULL
   *
   * @param errNo Error number all except 2 are fatal
   * @param msg Error message
   * @param user User data
   * @return \c true = keep the connection, \c false = close connection
   */ 
  bool (*errorCallback)(uint16_t errNo, const char* msg, void* user);

  /**
   * The connections was lost. The client will try to reconnect.
   *
   * @note Optional - can be \c NULL
   *
   * @param user User data
   * @return \c -1 = do not reconnect, otherwise wait sec and then try to
   *      reconnect to the server
   */
  int (*connectionCallback)(void* user);
  // Server connection

  /** Set this variable to the server host name - not IP. */
  const char* serverHost;
  /** Set this variable to the server port number. */
  int         serverPort;
} RPKIRouterClientParams;

/**
 * A single client.
 *
 * @note Do not modify any of the variables!
 */
typedef struct {
  /** This id MUST be unique within the application. */
  uint32_t                 routerClientID;

  /** The Parameters of this clinet */
  RPKIRouterClientParams*  params;
  /** */
  void*                    user;

  /** The socet information. */
  ClientSocket             clSock;
  /** Indicates if the sonnection is stopped. */
  bool                     stop;
  /** The worker thread for this connection. */
  pthread_t                thread;
  /** The rwite mutex of this connection. */
  Mutex                    writeMutex;
  /** The last used serial number for this connection (in network order!). */
  uint32_t                 serial; // < Stored in network order
  /** The type of the previous send PDU. */
  RPKIRouterPDUType        lastSent;
  /** The type of the last received PDU. */
  RPKIRouterPDUType        lastRecv;

  // The following attributes are needed for cache sessionID and possible 
  // changes within the sessionID number.
  /** The session_id given by the validation cache (in network order!). */
  uint32_t                 sessionID; // < Stored in network order
  /** Indicates change in sessionID number. Once set the cache has to remove
   * all entries coming from this cache where the sessionID numbers are 
   * different.*/
  bool                     sessionIDChanged;
  /** Is needed to prevent twice reset at the beginning. If startup is true
   * the cache session_id values will be "ignored" but set to the received 
   * value. See receivePDU for more info. */
  bool                     startup;
} RPKIRouterClient;

/**
 * Create a unique router client ID
 * 
 * @param self the router clinet the ID has to be generated for.
 * 
 * @return the ID;
 */
extern uint32_t createRouterClientID(RPKIRouterClient* self);

/**
 * Initializes a client and establishes a new connection to a server.
 * This also sends a reset query.
 *
 * @note \c All variables of \c param need to be set
 *
 * @param self Client variable that will be initialized.
 * @param params Pre-set parameters.
 * @param routerClientID an ID that will be assigned to this RPKIRouterClient.
 * @param user User data - will be passed to the callbacks
 * @return \c true = successful, \c false = something failed
 */
extern bool createRPKIRouterClient(RPKIRouterClient* client,
                                   RPKIRouterClientParams* params,
                                   void* user);

/**
 * Closes the connection, and releases all used resources.
 *
 * @param client Client instance
 */
extern void releaseRPKIRouterClient(RPKIRouterClient* client);

/**
 * Sends a reset query.
 *
 * @param client Client instance
 * @return \c true = PDU sent, \c false = sending failed
 */
extern bool sendResetQuery(RPKIRouterClient* client);

/**
 * Sends a serial query. This request all new and all expired prefixes.
 *
 * @param client Client instance
 * @return \c true = PDU sent, \c false = sending failed
 */
extern bool sendSerialQuery(RPKIRouterClient* client);

/**
 * Returns the type of the last sent PDU.
 *
 * @param client Client instance
 * @return Type
 */
extern RPKIRouterPDUType getLastSentPDUType(RPKIRouterClient* client);

/**
 * Returns the type of the last received PDU.
 *
 * @param client Client instance
 * @return Type
 */
extern RPKIRouterPDUType getLastReceivedPDUType(RPKIRouterClient* client);

int g_rpki_single_thread_client_fd;

extern void generalSignalProcess(void);

#endif // !__RPKI_ROUTER_CLIENT_H__
