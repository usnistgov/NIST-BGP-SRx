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
 * This software might use libraries that are under GNU public license or
 * other licenses. Please refer to the licenses of all libraries required 
 * by this software.
 * *
 * Exchange of multiple data packets over a single connection.
 *
 * \note The server (server_socket.h) must run in MODE_MULTIPLE_CLIENTS mode 
 *
 * log.h is used for the handling of error messages.
 * 
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 *            * Added Changelog
 * 0.1.0.0  - 2010/01/12
 *            * File Created.
 * 
 */
// @TODO: Check if this can be deleted

#ifndef __MULTI_CLIENT_SOCKET_H__
#define __MULTI_CLIENT_SOCKET_H__

#include <pthread.h>
#include <stdint.h>
#include "util/client_socket.h"
#include "util/mutex.h"
#include "util/slist.h"

/** 
 * A single Multi Client Socket
 *
 * \note Do not access any of the member variables directly!
 */
typedef struct {
  ClientSocket  clSock;
  pthread_t     monitor;
  SList         queue;
  uint32_t      maxId;
  Mutex         idMutex;
} MultiClientSocket;

/**
 * Creates a client-socket, capable of distinguishing between different 
 * data packet, and tries to connect to a server.
 *
 * @param self Variable that should be used to store the socket
 * @param host Server hostname (not IP-address)
 * @param port Server port
 * @return \c true = established a connection, \c false = an error occurred
 */
extern bool createMultiClientSocket(MultiClientSocket* self,
                                    const char* host, int port);

/**
 * Closes a client-socket.
 *
 * @param self Socket instance
 */
extern void releaseMultiClientSocket(MultiClientSocket* self);

/**
 * Exchanges a message with the server.
 * 
 * \param self Socket instance
 * \param data Data to send
 * \param dataSize Size (in Bytes) to send
 * \param buffer (out) Buffer for the server's response
 * \param bufferSize Size of \c buffer
 * \return Size of the server's response, or \c -1 in case of an error
 */ 
extern size_t exchangeData(MultiClientSocket* self, 
                           void* data, size_t dataSize,
                           void* buffer, size_t bufferSize);

#endif // !__MULTI_CLIENT_SOCKET_H__

