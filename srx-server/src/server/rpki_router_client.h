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
 * @version 0.6.2.1
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.6.2.1 - 2024/09/10 - oborchert
 *           * Changed data types from u_int... to uint... which follows C99
 *           * Added timing parameters for protocol version 2 to 
 *             RPKIRouterClientParams
 *         - 2024/09/09 - oborchert
 *           * Removed deprecated handleAspaPdu function.
 *           * endOfDataCallback added 3 more parameters.
 *         - 2024/09/05 - oborchert
 *           * Renamed RPKIRouterClient.client into RPKIRouterClient.rpkiHandler
 *             to prevent confusion in coding.
 *         - 2024/08/27 - oborchert
 *           * Added aspaCallback back into the code and deprecated 
 *             cbHandleAspaPDU.
 *           * Modified aspaCallback to comply with 8210-bis14 requirements.
 * 0.6.1.3 - 2024/06/12 - oborchert
 *           * Moved int g_rpki_single_thread_client_fd into the .c file and 
 *             declared it as extern in the .h file.
 * 0.6.0.0  - 2021/03/30 - oborchert
 *            * Added missing version control. Also moved modifications labeled 
 *              as version 0.5.2.0 to 0.6.0.0 (0.5.2.0 was skipped)
 *          - 2021/02/26 - kyehwanl
 *            * Removed aspaCallback.
 *            * Added ASPA callback to RPKIRouterClientParam as cbHandleAspaPdu.
 *          - 2021/02/16 - oborchert
 *            * Added callback function aspaCallback for ASPA processing.
 * 0.5.1.0  - 2018/03/09 - oborchert 
 *            * BZ1263: Merged branch 0.5.0.x (version 0.5.0.4) into trunk 
 *              of 0.5.1.0.
 *          - 2017/10/13 - oborchert
 *            * Removed keyword extern from functions in header file.
 *            * Removed backslash c from comments
 * 0.5.0.4  - 2018/03/07 - oborchert
 *            * Fixed speller in documentation.
 *            * Removed 'extern' from functions. 
 *            * Removed functions getLastSentPDUType and getLastReceivedPDUType.
 *          - 2018/03/06 - oborchert
 *            * Removed debugCallback of 0.5.0.3 by separating it into two 
 *              individual functions 1:debugRecCallback and 2:debugSendCallback.
 * 0.5.0.3  - 2018/02/26 - oborchert
 *            * Added parameter allowDowngrade. (part of fix for BZ1261)
 *            * Added function pointer debugCallback
 *            * Added function doPrintRPKI_to_RTR_PDU
 *          - 2018/02/23 - oborchert
 *            * Modified RPKIRouterClientParams.version from int to u_int8_t
 * 0.5.0.0  - 2017/06/29 - oborchert
 *            * Added more documentation to function headers.
 *          - 2017/06/16 - kyehwanl
 *            * Added router key callback function pointer
 *          - 2017/06/16 - oborchert
 *            * Version 0.4.1.0 is trashed and moved to 0.5.0.0
 *          - 2016/08/30 - oborchert
 *            * Added parameter 'stopAfterEndOfData' to structure
 *              RPKIRouterClient.
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
   * This function is called for each prefix announcement / withdrawal received
   * from the RPKI validation cache.
   *
   * @param valCacheID  This Id represents the cache. It is used to be able to
   *                    later on identify the white-list / ROA entry in case the
   *                    cache state changes.
   * @param sessionID   The cache sessionID entry for this data. It is be useful
   *                    for sessionID changes in case SRx is implementing a
   *                    performance driven approach. This ID does not come from 
   *                    the prefix PDU, it is the stored value in the client.
   * @param isAnn       Indicates if this in an announcement or not.
   * @param prefix      The prefix itself. Contains the information of v4/v6
   * @param maxLen      the maximum length this white-list / ROA entry covers.
   * @param oas         The origin AS for this entry in host format.
   * @param rpkiHandler An instance of the RPKIHandler.
   */
  void (*prefixCallback)(uint32_t valCacheID, uint16_t sessionID,
                         bool isAnn, IPPrefix* prefix, uint16_t maxLen,
                         uint32_t oas, void* rpkiHandler);

  /**
   * This function is called for each prefix announcement / withdrawal received
   * from the RPKI validation cache.
   *
   * @param valCacheID  This Id represents the cache. It is used to be able to
   *                    later on identify the white-list / ROA entry in case the
   *                    cache state changes.
   * @param sessionID   The cache sessionID entry for this data. It is be useful
   *                    for sessionID changes in case SRx is implementing a
   *                    performance driven approach.
   * @param isAnn       Indicates if this in an announcement or not.
   * @param asn         The as number in host format
   * @param ski         the ski buffer
   * @param keyInfo     Pointer to the key in DER format.
   * @param rpkiHandler An instance of the RPKIHandler.
   */
  void (*routerKeyCallback)(uint32_t valCacheID, uint16_t sessionID,
                            bool isAnn, uint32_t asn, const char* ski,
                            const char* keyInfo, void* rpkiHandler);
  
  /**
   * This function is called for each prefix announcement / withdrawal received
   * from the RPKI validation cache. Values must be passed in host mode, no 
   * translation from network to host is needed.
   *
   * @param valCacheID  This Id represents the cache. It is used to be able to
   *                    later on identify the white-list / ROA entry in case the
   *                    cache state changes.
   * @param sessionID   The cache sessionID entry for this data. It is be useful
   *                    for sessionID changes in case SRx is implementing a
   *                    performance driven approach.
   * @param isAnn       Indicates if this in an announcement or not.
   * @param customerAS  The ASn of the customer.
   * @param providerCt  Number of Providers in the providerList
   * @param providerASList List of providerASs
   * @param rpkiHandler An instance of the RPKIHandler.
   */
  void (*aspaCallback)(uint32_t valCacheID, uint16_t sessionID, bool isAnn, 
                       uint32_t customerAS, uint16_t providerCt, 
                       uint32_t* providerASList, void* rpkiHandler);
  
  /**
   * This function is called each time end of data is received. This allows to
   * trigger all necessary processing after data was received. (i.e. dequeueing
   * the RPKI QUEUE). For version 2 the additional patrameters are stored in the
   * RPKI handler.
   *
   * @param valCacheID  This Id represents the cache. It is used to be able to
   *                    later on identify the white-list / ROA entry in case the
   *                    cache state changes.
   * @param sessionID   The cache sessionID entry for this data. It is be useful
   *                    for sessionID changes in case SRx is implementing a
   *                    performance driven approach.
   * @param rpkiHandler The RPKIHandler.
   */
  void (*endOfDataCallback)(uint32_t valCacheID, uint16_t sessionID,
                            void* rpkiHandler);

  /**
   * The cache/server sent a reset response. Usually, the client should reset
   * his own cache.
   *
   * @note There is no need to send a reset query - this was done already
   * The cache though can reestablish the connection similar to a cache session
   * id change.
   * 
   * @param valCacheID  This Id represents the cache. It is used to be able to
   *                    later on identify the white-list / ROA entry in case the
   *                    cache state changes.
   * @param rpkiHandler An instance of the RPKIHandler.
   */
  void (*resetCallback)(uint32_t valCacheID,  void* rpkiHandler);

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
   * @note Optional - can be NULL
   *
   * @param errNo Error number all except 2 are fatal
   * @param msg Error message
   * @param rpkiHandler An instance of the RPKIHandler.
   * @return \c true = keep the connection, \c false = close connection
   */
  bool (*errorCallback)(uint16_t errNo, const char* msg, 
                        void* rpkiHandler);
  
  /**
   * An erroneous PDU was received.
   * 
   * @note Optional - can be NULL
   * 
   * @param len Length of the erroneous PDU
   * @param erronPDU The erroneus PDU
   * @param rpkiHandler An instance of the RPKIHandler.
   * 
   * @return true = keep the connection, false = close the connection
   * 
   * @since 0.5.0.3
   */
  bool (*erronPDUCallback)(uint32_t len, uint8_t* erronPDU, 
                           void* rpkiHandler);

  /**
   * The connections was lost. The client will try to reconnect.
   *
   * @note Optional - can be NULL
   *
   * @param rpkiHandler An instance of the RPKIHandler.
   * @return -1 = do not reconnect, otherwise wait sec and then try to
   *      reconnect to the server
   */
  int (*connectionCallback)(void* rpkiHandler);
  // Server connection
  
  /**
   * Allows to perform a debug callback prior processing the received PDU.
   * 
   * @note Optional - can be NULL
   * 
   * @param *user User data (commonly the client implementation itself
   * @param *pdu The received PDU
   * 
   * @return false if the PDU has a syntax or logical error.
   * 
   * @since 0.5.0.4
   */
  bool (*debugRecCallback)(void* user, RPKICommonHeader* pdu);  

    /**
   * Allows to perform a debug callback prior processing the received PDU.
   * 
   * @note Optional - can be NULL
   * 
   * @param *user User data (commonly the client implementation itself
   * @param *pdu The received PDU
   * 
   * @return false if the PDU has a syntax or logical error.
   * 
   * @since 0.5.0.4
   */
  bool (*debugSendCallback)(void* user, RPKICommonHeader* pdu);  

  /** Set this variable to the server host name - not IP. */
  const char* serverHost;
  /** Set this variable to the server port number. */
  int         serverPort;
  /** rtr-to-cache version info */
  uint8_t     version;
  /** Allow downgrading to lower version number if signaled during session 
   * negotiation. 
   * @since 0.5.0.3 */
  bool        allowDowngrade;
  /** 
   * This parameter tells the router how long to wait before next attempting to
   * poll the cache and between subsequent attempts, using a Serial Query or
   * Reset Query PDU. The router SHOULD NOT poll the cache sooner than indicated
   * by this parameter. Note that receipt of a Serial Notify PDU overrides this
   * interval and suggests that the router issue an immediate query without 
   * waiting for the Refresh Interval to expire. Countdown for this timer starts
   * upon receipt of the containing End Of Data PDU.
   * (min: 1 sec), (max: 86400 sec -> 1 day), (def: 3600 sec -> 1 hour)
   * @since 0.6.2.1 */
  uint32_t refreshInterval;
  /**
   * This parameter tells the router how long to wait before retrying a failed 
   * Serial Query or Reset Query. The router SHOULD NOT retry sooner than 
   * indicated by this parameter. Note that a protocol version mismatch 
   * overrides this interval: if the router needs to downgrade to a lower 
   * protocol version number, it MAY send the first Serial Query or Reset Query
   * immediately. Countdown for this timer starts upon failure of the query and
   * restarts after each subsequent failure until a query succeeds.
   * (min: 1 sec), (max: 7200 sec -> 2 hours), (def: 600 sec -> 10 min)
   * @since 0.6.2.1 */
  uint32_t retryInterval;
  /**
   * This parameter tells the router how long it can continue to use the current
   * version of the data while unable to perform a successful subsequent query.
   * The router MUST NOT retain the data past the time indicated by this 
   * parameter. Countdown for this timer starts upon receipt of the containing
   * End Of Data PDU.
   * (min: 600 sec -> 10 min), (max: 172800 sec -> 2 days), 
   * (def: 7200 sec -> 2 hours)
   * @since 0.6.2.1 */
  uint32_t expireInterval;
} RPKIRouterClientParams;

/**
 * A single client.
 *
 * @note Do not modify any of the variables!
 */
typedef struct {
  /** This id MUST be unique within the application. It is the ID that 
   *  identifies the cache. */
  uint32_t                routerClientID;

  /** The Parameters of this client */
  RPKIRouterClientParams* params;
  /** Contains the RPKIHandler. */
  void*                   rpkiHandler;

  /** The socket information. */
  ClientSocket            clSock;
  /** Indicates if the connection is stopped. */
  bool                    stop;
  /** The worker thread for this connection. */
  pthread_t               thread;
  /** The write mutex of this connection. */
  Mutex                   writeMutex;
  /** The last used serial number for this connection (in network order!). */
  uint32_t                serial; // < Stored in network order
  /** The type of the previous send PDU. */
  RPKIRouterPDUType       lastSent;
  /** The type of the last received PDU. */
  RPKIRouterPDUType       lastRecv;

  // The following attributes are needed for cache sessionID and possible
  // changes within the sessionID number.
  /** The session_id given by the validation cache (in network order!). */
  uint32_t                sessionID; // < Stored in network order
  /** Indicates change in sessionID number. Once set the cache has to remove
   * all entries coming from this cache where the sessionID numbers are
   * different.*/
  bool                    sessionIDChanged;
  /** Is needed to prevent twice reset at the beginning. If startup is true
   * the cache session_id values will be "ignored" but set to the received
   * value. See receivePDU for more info. */
  bool                    startup;
  /** Is used to allow the receiver thread of ending after the END OF DATA is
   * received. This is used in the rpkirtr_client tool to allow single requests
   * without continuous polling.
   * @since 0.5.0.0 */
  bool                    stopAfterEndOfData;
  /** RTR-to-Cache protocol version info */
  int8_t                  version;
} RPKIRouterClient;

/**
 * Create a unique router client ID
 *
 * @param self the router client the ID has to be generated for.
 *
 * @return the ID;
 */
uint32_t createRouterClientID(RPKIRouterClient* self);

/**
 * Initializes a client and establishes a new connection to a server.
 * This also sends a reset query.
 *
 * @note All variables of  param need to be set
 *
 * @param self Client variable that will be initialized.
 * @param params Pre-set parameters.
 * @param routerClientID an ID that will be assigned to this RPKIRouterClient.
 * @param user The RPKI handler
 * @return \c true = successful, \c false = something failed
 */
bool createRPKIRouterClient(RPKIRouterClient* client,
                            RPKIRouterClientParams* params,
                            void* rpkiHandler);

/**
 * Closes the connection, and releases all used resources.
 *
 * @param client Client instance
 */
void releaseRPKIRouterClient(RPKIRouterClient* client);

/**
 * Sends a reset query.
 *
 * @param client The RPKI router client instance
 * @return true = PDU sent, false = sending failed
 */
bool sendResetQuery(RPKIRouterClient* client);

/**
 * Sends a serial query. This request all new and all expired prefixes.
 *
 * @param client The RPKI router client instance
 * @return true = PDU sent, false = sending failed
 */
bool sendSerialQuery(RPKIRouterClient* client);

/**
 * Send an error report to the server.
 * 
 * @param client The RPKI router client instance
 * @param errCode The error code to be used.
 * @param erronPDU The PDU containing the error.
 * @param lenErronPDU Length of the erroneous PDU.
 * @param errText The administrative text message that accompanies the error.
 * @param lenErrText The length of the text string.
 * 
 * @return true if the packet could be send successfully.
 * 
 * @since 0.5.0.3
 */
bool sendErrorReport(RPKIRouterClient* client, uint16_t errCode,
                     uint8_t* erronPDU, uint32_t lenErronPDU,
                     char* errText, uint32_t lenErrText);

// @TODO: fix this not so nice work around
// In ROCKY this throws a linker error. The solution is to declare it extern here and then
// make the proper declaration in rpki_routewr_client.c
extern int g_rpki_single_thread_client_fd;

void generalSignalProcess(void);

#endif // !__RPKI_ROUTER_CLIENT_H__
