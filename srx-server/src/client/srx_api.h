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
 * Secure Routing extension (SRx) client API - This API provides a fully 
 * functional proxy client to the SRx server.
 *
 * Version 0.4.0.0
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.4.0.0  - 2016/06/19 - oborchert
 *            * Modified the structure for the signaturesReady callback method
 * 0.3.0.10 - 2015/11/09 - oborchert 
 *            * Removed types.h
 * 0.3.0    - 2013/02/27 - oborchert
 *            * Changed the error management to a more broader communication 
 *              management. This resulted also in renaming some defines as well 
 *              as parameters in the proxy structure to be more meaningful.
 *          - 2013/02/04 - oborchert
 *            * Added stdarg.h into include to be able to compile under Centos 5
 *          - 2013/01/08 - oborchert
 *            * Added error control when server encounters buffer overflow.
 *            * Added experimental structure ProxySocketConfig;
 *          - 2012/12/17 - oborchert
 *            * Removed enumeration SRxOpMode
 *            * Added enumeration SRxProxyError
 *            * Changed signature of callback function (*ValidationReady), 
 *            * Modified parameter type of callback function (*SignaturesReady)
 *            * Added  callback function (*ErrorManagement)
 *            * Modified structure of SRxProxy
 *            * Changed signature of the following functions:
 *              createProxy; deleteUpdate; connectToSRx; vreifyUpdate; 
 *            * Added function:
 *              reconnectWithSRx; processPackets; getInternalSocketFD
 * 
 * 0.2.0    - 2011/01/07 - oborchert
 *            * Changelog added with version 0.2.0 and date 2011/01/07
 *            * Version tag added
 * 0.1.0    - 2010/03/10 - pgleichm
 *            * Code Created
 * -----------------------------------------------------------------------------
 */
#ifndef __SRX_API_H__
#define __SRX_API_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdio.h>
#include <sys/un.h>
#include "shared/srx_defs.h"
#include "util/prefix.h"
#include "util/slist.h"
  

/** This type specifies the different error codes the proxy provides. */
typedef enum
{
  /** Currently undefined error. The Subcode specifies the originating error */
  COM_ERR_PROXY_UNKNOWN=0,
  /** Error while assigning the proxy id - connecting to srx server. */
  COM_ERR_PROXY_DUPLICATE_PROXY_ID=1,
  /** The requested algorithm is unknown - path validation. */
  COM_ERR_PROXY_UNKNOWN_ALGORITHM=2,
  /** The specified update is unknown - delete/sign request. */
  COM_ERR_PROXY_UNKNOWN_UPDATE=3,
  /** This error code specifies a lost connection. */
  COM_ERR_PROXY_CONNECTION_LOST=4,
  /** This error specifies problems sending messages to the srx-server. This
   * Error provides the sockets as subcode the errno or -1 in case the error 
   * threshold was triggered. */
  COM_ERR_PROXY_COULD_NOT_SEND=5,
  /** This error specifies a SERVER error. This error contains the following
   * subcodes: SVRINTRNL=server internal,  SVRINVPKG=REceived invalid packet. */
  COM_ERR_PROXY_SERVER_ERROR=6,
  /** Proxy and SRx-server are not compatible. */
  COM_ERR_PROXY_COMPATIBILITY=7,          
  /** Currently undefined communication mode. The Subcode specifies the 
   * originating incident */
  COM_PROXY_UNKNOWN=128,
  /** Used to indicate disconnect was called and an established connection was 
   * disconnected. */
  COM_PROXY_DISCONNECT=129,
          
  /** No code - needed for initialization - No subcode */
  COM_PROXY_NONE=255,
} SRxProxyCommCode;

// Server internal error
#define SVRINTRNL  1
// Server reveived invalid packet
#define SVRINVPKG  2

// Should be used as sub code for errors that do NOT provide a subcode.
#define COM_PROXY_NO_SUBCODE 0

////////////////////////////////////////////////////////////////////////////////
// Callback notification functions for proxy user
////////////////////////////////////////////////////////////////////////////////

/**
 * Prototype for the logging. This callback allows to integrate the proxy 
 * logging into the hosts logging system. If not provided the internal logging 
 * system is used. The level follows the standard logging values but only the 
 * following levels are used:
 * LEVEL_ERROR = 3: 
 *        Non-urgent failures - these should be relayed to developers or admins;
 *        each item must be resolved within a given time
 * LEVEL_WARNING = 4:
 *        Warning messages - not an error, but indication that an error will 
 *        occur if action is not taken, e.g. file system 85% full - each item 
 *        must be resolved within a given time
 * LEVEL_NOTICE  = 5: 
 *        Events that are unusual but not error conditions - might be summarized
 *        in an email to developers or admins to spot potential problems - no 
 *        immediate action required
 * LEVEL_INFO    = 6:
 *        Normal operational messages - may be harvested for reporting, 
 *        measuring throughput, etc - no action required
 * LEVEL_DEBUG   = 7: 
 *        Info useful to developers for debugging the application, not useful 
 *        during operations
 * 
 * @param level The level - as described above.
 * @param fmt The formated string
 * @param arguments the list of arguments.
 */
typedef void (*ProxyLogger)(int level, const char* fmt, va_list arguments);

/**
 * Used to report the validation result for an update that can be identified
 * either by the update ID or the local ID (only if not "0" zero). This method
 * is used to communicate validation state changes to the user of the API.
 * The parameter localID is used to allow processing of updates by the API user
 * by self-assigning an id to the update (localID) until the srx-server provides
 * a system-wide unique update if. Therefore, the parameter localID is a
 * "pass-through" parameter that only has meaning to the user of the API. This
 * value was passed during the verifyUpdate call and will be given back in this
 * method only if this method is a direct response to the verification call with
 * localID set. Other state changes will not provide this id.
 *
 * @param updateID The updateID provided by the srx-server to communicate
 *                 the validation result.
 * @param localID  The local "update-id" used temporarily by the user of this
 *                 API when called a validation. (see more detailed above)
 * @param valType  Specifies which of the validation results contains actual
 *                 result values.
 * @param roaResult The result of the update validation only in regards to
 *                 prefix-origin validation.
 * @param bgpsecResult The result of the update validation only in regards to
 *                 path validation validation. (This does not include RPKI
 *                 validation)
 * @param usrPtr Pointer to SRxProxy.userPtr provided by router / user of the
 *               API.
 */
typedef bool (*ValidationReady)(SRxUpdateID          updateID,
                                uint32_t	           localID,
                                ValidationResultType valType,
                                uint8_t              roaResult,
                                uint8_t              bgpsecResult,
                                void* userPtr);

/**
 * Used to return the calculated signatures.
 *
 * @todo Parameters have yet to be defined
 *
 * @updId The update id the signature is calculated for
 * @param data the data containing the signature.
 * @param usrPtr Pointer to SRxProxy.userPtr provided by router / user of the
 *               API.
 */
typedef void (*SignaturesReady)(SRxUpdateID updId, BGPSecCallbackData* data,
                                void* userPtr);

/**
 * This callback function allows the SRx to send a synchronization request to
 * the proxy.
 * 
 * @param usrPtr Pointer to SRxProxy.userPtr provided by router / user of the
 *               API.
 */
typedef void (*SyncNotification)(void* userPtr);

/**
 * Used to communicate messages and errors between srx-server and the proxy.
 *
 * @param code    The communication code.
 * @param subCode A sub code. It is dependent on the communication code, if it 
 *                is used or not.
 *                See Communication code type description for more details.
 * @param usrPtr Pointer to SRxProxy.userPtr provided by router / user of the
 *               API.
 */
typedef void (*SrxCommManagement)(SRxProxyCommCode code, int subCode, 
                                void* userPtr);

////////////////////////////////////////////////////////////////////////////////
// Proxy type and functions
////////////////////////////////////////////////////////////////////////////////

/**
 * This structure is currently in experimental stage
 */
typedef struct {
  // enable / disable the Proxy Socket Configuration
  bool     enablePSC;
  // The maximum number of attempts to resend a packet before an error is 
  // reported.
  uint8_t  maxAttempts;
  // The time in milliseconds between attempts to send a packet
  uint16_t maxSleepMillis;
    
  // Counts the sending operations where the proxy needed more than one attempt
  // to send the data.
  uint32_t totalCountOfMultipleAttempts;
  
  //
  // An error is counted once sending failed completely
  //
  // The number of total errors encountered.
  uint16_t sendErrors;  
  // The total number of send errors until a system error will be send to the 
  // client/host who uses the API.
  uint16_t sendErrorThreshold; 
  // Number of successful send operations until the counter numberErrors will 
  // be reset automatically!
  uint16_t resetSendErrors;
  // Number of consecutive successful times send. Will be set to 0 once an error
  // is counted. -> this is the trigger for reset.
  uint16_t succsessSend;
} ProxySocketConfig;

/** The data structure of the proxy. DO NOT change the settings, this is done
 * within the proxy implementation.
 */
typedef struct {
  ValidationReady   resCallback;
  SignaturesReady   sigCallback;
  SyncNotification  syncNotification;
  
  SrxCommManagement commManagement;  
  SRxProxyCommCode  lastCode;    // Last communication code.
  int               lastSubCode; // subCode of communication codelast error.

  uint32_t          proxyID;

  void*             connHandler;  // MUST be of type ClientConnectionHandler

  uint32_t          proxyAS;
  SList             peerAS;          // Maybe change to a pointer
  
  // Something meaningful for the software that uses this API This pointer will
  // be used only for the callback
  void*            userPtr;

  bool externalSocketControl; // Allows the current socket connection to be
                              // controlled externally.
    
  // Experimental
  ProxySocketConfig socketConfig;
} SRxProxy;


/**
 * Creates a proxy instance and registers the callback methods for signature
 * generation and validation notification..
 *
 * @param vallidationReadyCallback The function the proxy calls to communicate
 *                   the validation result or changes in prior validation 
 *                   results to the proxy user. This can be for instance the
 *                   router or policy module, etc.
 * @param signatureReadyCallback The function, the SRx calls once the requested
 *                   signature is generated.
 * @param requestSynchronizationCallback This function is used to request a
 *                   synchronization. A call of this method should initiate a
 *                   complete validation request from the routers side to
 *                   guarantee that SRx has a complete view on the validated
 *                   data within the user.
 * @param communicationMgmtCallback This function is used to allow external
 *                   management of proxy management messages and errors by 
 *                   assigning a handler.
 * @param proxyID    The id of the proxy used during the handshake with SRx. If
 *                   SRx is requested to generate the ID this value MUST be "0"
 *                   zero.
 * @param proxyAS    The AS of the user that uses this proxy.
 *
 * @param userPtr    This parameter is used or not by the router or policy
 *                   module or other that accesses the proxy. It does not have
 *                   any meaning for SRx or the proxy itself but might be
 *                   meaningful for the software (router, policy module, etc)
 *                   that uses this API.
 *
 * @return the instance of the SRx proxy, or NULL in case of an error
 */
SRxProxy* createSRxProxy(ValidationReady   validationReadyCallback,
                         SignaturesReady   signatureReadyCallback,
                         SyncNotification  requestSynchronizationCallback,
                         SrxCommManagement communicationMgmtCallback,
                         uint32_t proxyID, uint32_t proxyAS, void* userPtr);
/**
 * Releases the instance. This also closes the connection if necessary.
 *
 * @param proxy The proxy instance
 */
void releaseSRxProxy(SRxProxy* proxy);

/** 
 * Add peers to the configuration of the proxy. In case the proxy is already 
 * connected, the peer change will be communicated to SRx.
 * 
 * @param proxy The proxy instance
 * @param noPeers The number of peers.
 * @param peerAS The array of peers.
 */
void addPeers(SRxProxy* proxy, uint32_t noPeers, uint32_t* peerAS);

/**
 * Remove peers from the proxy configuration. In case the proxy is already
 * connected, the peer change will be communicated to SRx.
 *
 * @param proxy The proxy instance
 * @param noPeers The number of peers.
 * @param peerAS The array of peers.
 */
void removePeers(SRxProxy* proxy, uint32_t noPeers, uint32_t* peerAS);

/**
 * Remove peers from the proxy configuration. In case the proxy is already
 * connected, the peer change will be communicated to SRx.
 *
 * @param proxy The proxy instance
 * @param keep_window The number of seconds requested to keep the data on the
 *        server side.
 * @param updateID The ID of the update to deleted.
 */
void deleteUpdate(SRxProxy* proxy, uint16_t keep_window, SRxUpdateID updateID);

/** 
 * Tries to establish a connection to an SRx server. The given proxy instance
 * is expected to be completely configured. Any previously established
 * connection will be ended.
 *
 * In case the connection handshake fails the connection is closed and the
 * connection handler is released.
 *
 * @param proxy The proxy instance
 * @param host Server host name
 * @param port Server port address
 * @param handshakeTimeout The time in seconds before a handshake is timed out.
 * @param externamSocketControl Allows the socket control (closing the socket)
 *                              to be done external.
 *
 * @return true if connected, otherwise false if the connection failed.
 */
bool connectToSRx(SRxProxy* proxy, const char* host, int port,
                  int handshakeTimeout, bool externalSocketControl);

/**
 * Disconnects the proxy from the SRx Server instance on both, application and
 * transport layer.
 *
 * @param proxy The proxy instance
 * @param keepWindow Sends a request to keep the proxy data with SRx for given
 *                   amount of seconds.
 *
 * @return true if the instance is disconnected, false in case of on invalid 
 *         instance
 */
bool disconnectFromSRx(SRxProxy* proxy, uint16_t keepWindow);

/**
 * Returns if the proxy is connected or not.
 * 
 * @param proxy The proxy itself.
 * 
 * @return true if the proxy is connected, false otherwise.
 */
bool isConnected(SRxProxy* proxy);

/**
 * Attempt to reconnect with the srx-server
 *
 * @param proxy The proxy itself
 *
 * @return true if the reconnect was successful, otherwise false
 *
 * @since 0.3
 */
bool reconnectWithSRx(SRxProxy* proxy);

/**
 * Verifies the given update data. All parameters except the result parameter
 * are IN parameters, result is an OUT parameter that will be filled within this
 * function. The memory MUST be allocated outside of this function.
 *
 * @param proxy The proxy instance
 * @param localID Specifies the local ID associated to this Update. This is NOT
 *                the updateID and if an update id is known, this value should
 *                be "0" zero. If the value is other than "0" zero the
 *                SRx-server WILL send a notification back, regardless if the
 *                given default result is a correct validation result or not.
 * @param usePrefixOriginVal specify if srx-server should perform a prefix
 *                origin validation.
 * @param usePpathVal specify if srx-server should perform a path validation.
 * @param defaultResult The parameter contains the default information to be 
 *                used in case the validation result is not readily available.
 * @param prefix The prefix of the request. (both v4/v6 possible)
 * @param as32 Origin AS (32-bit)
 * @param bgpsec the bgpsec information.
 *
 * @return The pointer to the provided validation result or NULL if validation
 *         encountered an error. Most likely the error is that the proxy is not
 *         connected.
 */
void verifyUpdate(SRxProxy* proxy, uint32_t localID,
                  bool usePrefixOriginVal, bool usePathVal,
                  SRxDefaultResult* defaultResult,
                  IPPrefix* prefix, uint32_t as32,
                  BGPSecData* bgpsec);

/**
 * This method generates a signature request. The signature will be returned
 * using the signature notification callback.
 *
 * @param proxy Pointer to the proxy instance
 * @param updId The update id the signature is requested for
 * @param onlyOwnSignature Return only the latest signature block generated for
 *                         this BGP router, otherwise the own signatures will be
 *                         concatenated to the previous given BGPSEC data block.
 * @param algorithm        The algorithm to use.
 * @param prependCounter   Number of times the own AS will be prepended into the
 *                         path. This allows traffic engineering.
 * @param peerAS           The peer AS the update will be send to.
 *
 * @return true if sending the signature request was successful.
 */
bool signUpdate(SRxProxy* proxy, SRxUpdateID updateId, bool onlyOwnSignature,
                uint16_t algorithm, uint32_t prependCounter, uint32_t peerAS);

/**
 * This function is called to read packets received from srx-server and process
 * them accordingly. This function allows the caller to have the packet handling
 * been done within the scope of the caller process. This is a possible blocking
 * method. It will go into a loop of receiving messages until the connection is
 * closed, lost, or all data is read.
 *
 * @param proxy The proxy instance
 *
 * @return true if the receiver loop was ended clean, false in case an error
 *              occurred.
 * @since 0.3
 */
bool processPackets(SRxProxy* proxy);

/**
 * Return the internal socket descriptor. This method allows to manage the
 * socket from within the user of the API. For detailed information see the
 * users technical manual. This method only returns the internal socket
 * descriptor if the connection was established by specifying the usage of
 * external socket control. Otherwise the return value will be -1
 *
 * @param proxy The SRx-Proxy instance
 * @param main If true. it returns the main socket file descriptor. If false
 *        it returns the original file descriptor. In general both are the same
 *        except if a socket close command set the file descriptor to -1. This
 *        allows to retrieve the original file descriptor/
 *
 * @return The file descriptor of the connected socket or -1
 *
 * @since 0.3
 */
int getInternalSocketFD(SRxProxy* proxy, bool main);

/**
 * Reset the error attributes of this proxy. Post condition of this function
 * is proxy->lastError=ERR_PROXY_NONE and 
 * proxy->lastErrorSubCodee=PROXY_ERROR_NO_SUBCODE
 * 
 * @param proxy The proxy.
 * 
 * @since 0.3
 */
void resetProxyError(SRxProxy* proxy);

////////////////////////////////////////////////////////////////////////////////
// Debugging Framework
////////////////////////////////////////////////////////////////////////////////

/**
 * Set the API Proxy logger.
 * 
 * @param logger The logger method. NULL for deactivation.
 * 
 * @since 0.3.0 
 */
void setProxyLogger(ProxyLogger logger);

/** 
 * Set the logging mode in case no external logger is provided.
 * The following modes are supported:
 * 
 * DISABLE     = 0:
 *        All logging will be suppressed.
 * LEVEL_ERROR = 3: 
 *        Non-urgent failures - these should be relayed to developers or admins;
 *        each item must be resolved within a given time
 * LEVEL_WARNING = 4:
 *        Warning messages - not an error, but indication that an error will 
 *        occur if action is not taken, e.g. file system 85% full - each item 
 *        must be resolved within a given time
 * LEVEL_NOTICE  = 5: 
 *        Events that are unusual but not error conditions - might be summarized
 *        in an email to developers or admins to spot potential problems - no 
 *        immediate action required
 * LEVEL_INFO    = 6:
 *        Normal operational messages - may be harvested for reporting, 
 *        measuring throughput, etc - no action required
 * LEVEL_DEBUG   = 7: 
 * 
 * @param logMode the logging mode level as described above.
 * 
 * @return true if the logging mode could be selected, otherwise false.
 * 
 * @since 0.3.0
 */
bool setLogMode(int logMode);


/** 
 * Determines if the given code is an error code or not.
 * 
 * @param mainCode The code to be checked for an error.
 * 
 * @return true if the given code is an error. 
 * 
 * @since 0.3.0
 */
bool isErrorCode(SRxProxyCommCode code);
#ifdef __cplusplus
}
#endif

#endif // !__SRX_API_H__

