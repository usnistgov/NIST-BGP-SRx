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
 * This file contains the functions to send srx-proxy packets.
 * 
 * @version 0.3.0
 *
 * Changelog:
 * 
 * -----------------------------------------------------------------------------
 *   0.3.0 - 2013/01/02 - oborchert
 *   * Added changelog.
 *   * Added sending queue to prevent buffer overflows in the receiver socket 
 *   0.1.0 - 2011/11/01 - oborchert
 *   * File Created.
 */

#ifndef __SRX_PACKET_UTIL_H__
#define	__SRX_PACKET_UTIL_H__

#include <stdint.h>
#include <stdbool.h>
#include "util/server_socket.h"

/**
 * Create the sender queue including the thread that manages the queue.
 * 
 * @return true if the queue cold be created otherwise false. 
 * 
 * @since 0.3.0
 */
bool createSendQueue();

/**
 * Start the send queue. In case the queue is already started this method does 
 * not further start it.
 * 
 * @return true if the Queue is running.
 * 
 * @since 0.3.0
 */
bool startSendQueue();

/**
 * Stop the queue but does not destroy the thread itself.
 * 
 * @since 0.3.0
 */
void stopSendQueue();

/**
 * Stops the queue is not already stopped and frees all memory associated with 
 * it.
 * 
 * @since 0.3.0
 */
void releaseSendQueue();

/**
 * Send a hello response to the client. This method does not use the send queue
 *
 * @param proxyID The id of the proxy
 * @param srcSock The server socket
 * @param client The client who received the original message
 *
 * @return true if the packet could be send, otherwise false.
 */
bool sendHelloResponse(ServerSocket* srcSock, ServerClient* client,
                       uint32_t proxyID);

/**
 * Send a goodbye packet to the proxy. The proxy does not use the keepWindow,
 * therefore it will be 0
 *
 * @param srcSock The server socket
 * @param client The client who received the original message
 * @param useQueue indicates if the sending queue should be used or not
 *
 * @return true if the packet could be send, otherwise false.
 */
bool sendGoodbye(ServerSocket* srcSock, ServerClient* client, bool useQueue);

/**
 * Send a verification notification.
 *
 * @param svrSock The server socket
 * @param client The client of the communication.
 * @param updateID The id of the update.
 * @param resultType The type of results.
 * @param requestToken The token id of a request. Must be disabled 
 *                     (DONOTUSE_REQUEST_TOKEN) if the receipt flag is not set!
 * @param roaResult The ROA validation result.
 * @param bgpsecResult The BGPSEC validation result.
 * @param useQueue use the sending queue or not.
 *
 * @return true if the packet could be send, otherwise false.
 */
bool sendVerifyNotification(ServerSocket* svrSock, ServerClient* client,
                            SRxUpdateID updateID, uint8_t resultType,
                            uint32_t requestToken,
                            uint8_t roaResult, uint8_t bgpsecResult, 
                            bool useQueue);

/**
 * Send a signature notification.
 *
 * @param svrSock The server socket
 * @param client The client of the communication.
 * @param updateID The id of the update.
 * @param bgpsecLength The length of the signature
 * @param bgpsecBlob The BGPSEC data blob
 * @param useQueue Use the sending queue or not
 *
 * @return true if the packet could be send, otherwise false.
 */
bool sendSignatureNotification(ServerSocket* svrSock, ServerClient* client,
                            SRxUpdateID updateID, uint32_t bgpsecLength,
                            uint8_t* bgpsecBlob, bool useQueue);

/**
 * Send a synchronization request to the proxy.
 *
 * @param svrSock The server socket
 * @param client The client of the communication.
 * @param useQueue Use the sending queue
 *
 * @return true if the packet could be send, otherwise false.
 */
bool sendSynchRequest(ServerSocket* svrSock, ServerClient* client, 
                      bool useQueue);

/**
 * Send an error report to the proxy.
 * 
 * @param errorCode The code of the error
 * @param svrSock The server socket
 * @param client The client of the communication.
 * @param useQueue Use the sending queue.
 * 
 * @return true if the packet could be send, otherwise false.
 */
bool sendError(uint16_t errorCode, ServerSocket* svrSock, ServerClient* client,
               bool useQueue);

#endif	/* __SRX_PACKET_UTIL_H__ */

