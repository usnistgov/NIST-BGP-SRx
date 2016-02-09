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
 * Functions to create a client-socket, to receive from and to send data
 * to a server.
 *
 * log.h is used for the handling of error messages.
 * 
 * This software might use libraries that are under GNU public license or
 * other licenses. Please refer to the licenses of all libraries required 
 * by this software.
 *
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 *            * Added Changelog
 * 0.1.0.0  - 2009/12/28
 *            * Created code.
 */

#ifndef __CLIENT_SOCKET_H__
#define __CLIENT_SOCKET_H__

#include <netinet/in.h>
#include "util/packet.h"

typedef enum {
  /** This is an undefined socket. == NULL*/
  UNDEFINED_CLIENT_SOCKET,
  /** This is a client socket within the SRx API */
  SRX_PROXY_CLIENT_SOCKET,
  /** This is a client socket within srx-server to the rpki validation cache */
  RPKI_RTR_CLIENT_SOCKET
} ClientSocketType;

/**
 * A Client Socket.
 */
typedef struct {
  /** The socket Address */
  struct sockaddr_in  svrAddr;
  /** Specifies the type of this socket. This is important because srx api
   * sockets can be non blocking and maintained elsewhere, whereas srx-server
   * sockets towards the validation cache are handled within this instance. */
  ClientSocketType    type;
  /** Due to the new coding changes that allows external socket handling, this
   * value should contain the socket's file descriptor just in case the clientFD
   * is set to -1 what will happen when an error occurs. The socket will not
   * be automatically closed anymore while reading from it.
   */
  int                 oldFD;
  /** The file descriptor of the client socket. */
  int                 clientFD;
  /** indicates if a reconnect is requested in case the  connection is lost. */  
  bool                reconnect; // Might be deleted, don't like it!
  bool                canBeClosed; // if this is false, the socket must not be
                                   // closed!! This is to allow external
                                   // socket control.
} ClientSocket;

/**
 * This Socket instance is used by the SRX-Proxy API to connect to the SRx
 * server and by the SRx server to connect to the RPKI Validation cache.
 *
 * Creates a client socket instance and connects the underlying socket to the
 * server specified by the given parameters. The return value of this method
 * depends on the parameter "failNoServer".
 * By default the client socket is allowed to reconnect. The value will
 * be set to false only if failNoServer is true and the connection could not
 * be established.
 *
 * @param self The Client socket.
 * @param host The host to attach to.
 * @param port The port to attach to.
 * @param failNoServer if the function is allowed to fail in case the connection
 *                     could not be established.
 * @param type The type of this socket - This allows to determine where the
 *                     socket is used, proxy-server or server-rtr cache
 * @param allowToClose indicates if the socket is allowed to be closed.
 *
 * @return false only if failNoServer && no connection could be established.
 */
bool createClientSocket(ClientSocket* self, const char* host, int port,
                        bool failNoServer, ClientSocketType type,
                        bool allowToClose);

/**
 * Closes a client-socket.
 *
 * @param self Client-socket instance
 * 
 * @see closeClientSocket
 */
void closeClientSocket(ClientSocket* self);

/**
 * Tries to establish a connection to the server again.
 *
 * @note A \c delay of > 0 makes this a blocking call
 *
 * @param self Client-socket instance
 * @param delay Wait \c delay seconds before trying again
 * @param max_attempts The maximum attempts this function performs to establish
 *              a connection before it returns false
 * 
 * @return \c true = connection established, \c failed to connect
 */
bool reconnectToServer(ClientSocket* self, int delay, int max_attempts);

/**
 * Stops any further attempts to connect to the server.
 *
 * @param self Client-socket instance
 */
void stopReconnectingToServer(ClientSocket* self);

/**
 * Returns a pointer to the file-descriptor of a client-socket.
 *
 * @param self Client-socket instance
 *
 * @return int* - file descriptor
 */
int* getClientFDPtr(ClientSocket* self);

/**
 * Returns \c true if the client is connected to the server.
 *
 * @param self Client-socket instance
 * 
 * @return \c true = connected, \c false = not connected
 */
bool isConnectedToServer(ClientSocket* self);

/**
 * Sends data to the server.
 *
 * @note An integer is put in front of the data to indicate the data length
 * 
 * @param self Client-socket instance
 * @param data Data to send
 * @param length Size (in Bytes) of the data
 * @return \c true = successfully sent, \c false = an error occurred
 * @see receiveData
 */
bool sendData(ClientSocket* self, void* data, PacketLength length);

/**
 * Waits and receives data from the server.
 *
 * @note The first 32-bit integer is expected to be the data length
 * @note Blocking-call
 *
 * @param self Client-socket instance
 * @param buffer Buffer where to store the received data
 * @param length Length of the buffer
 * @return Number of received Bytes, or \c -1 in case of an error
 * @see sendData
 * @see sendDataIndirect
 * @see skipBytes
 */
size_t receiveData(ClientSocket* self, void* buffer, size_t length);

/**
 * Reads and discards a certain number of Bytes.
 *
 * @note Blocking-call
 *
 * @param self Client-socket instance
 * @param num Number of Bytes to skip
 * @return \c true = successfully skipped the Bytes, \c = failed to skip
 * @see receiveData
 */
bool skipBytes(ClientSocket* self, size_t num);

#endif // !__CLIENT_SOCKET_H__

