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
 *   0.3.0 - 2012/12/17 - oborchert
 *   * Added changelog.
 *   * Changed Structure of client socket to allow different handling depending
 *     where this structure is used (proxy / srx-server)
 *   0.2.0 - 2011/11/xx - oborchert
 *   * bug fixes and other changes.
 *   0.1.0 - 2009/12/28 - pgleichm
 *   * Code Created
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <errno.h>
#include "util/client_socket.h"
#include "util/log.h"
#include "util/packet.h"
#include "util/socket.h"

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
                        bool allowToClose)
{
  struct hostent* svr;
  int conRetVal;

  self->oldFD = -1;
  self->type = UNDEFINED_CLIENT_SOCKET; // for now
  self->canBeClosed = true; // for now

  // Resolve the host name
  svr = gethostbyname(host);
  if (svr == NULL)
  {
    RAISE_ERROR("Unknown host '%s'", host);
    return false;
  }

  // Create a TCP socket
  self->clientFD = socket(AF_INET, SOCK_STREAM, 0);
  if (self->clientFD < 0)
  {
    RAISE_ERROR("Failed to create the client socket");
    return false;
  }

  // Connect TCP
  bzero(&self->svrAddr, sizeof (struct sockaddr_in));
  self->svrAddr.sin_family = AF_INET;
  self->svrAddr.sin_port = htons(port);
  memcpy(&(self->svrAddr.sin_addr.s_addr), svr->h_addr, svr->h_length);
  self->reconnect = true;

  conRetVal = connect(self->clientFD, (const struct sockaddr*)&self->svrAddr,
               sizeof (self->svrAddr));
  if (conRetVal != 0)
  {
    close(self->clientFD);

    LOG(LEVEL_INFO, "Failed to open TCP connection to the server at %s:%u",
                    host, port);
    if (failNoServer)
    {
      self->reconnect = false;
      return false;
    }
    else
    {
      self->clientFD = -1;
    }
  }

  self->oldFD = self->clientFD;
  self->type = type;
  self->canBeClosed = allowToClose;

  // if we got here then at least the socket exists.
  return true;
}

/**
 * Closes the client socket and turns off the reconnect feature. This method
 * closes the socket on transport layer if possible, otherwise it only sets
 * the descriptor to -1 but keeps the oldFD where it was.
 *
 * @param self The client socket
 */
void closeClientSocket(ClientSocket* self)
{
  if (self != NULL)
  {
    int fileDescriptor = self->clientFD > -1 ? self->clientFD : self->oldFD;

    stopReconnectingToServer(self);
    if (fileDescriptor > -1)
    {
      // At least keep old behavior and close it if it is an rpki client socket.
      if (self->canBeClosed)
      {
        self->oldFD = -1;
        self->clientFD = -1;
        close(fileDescriptor);
      }
      else
      {
        // Make sure the socket is not usable internally!
        self->clientFD = -1;
      }
    }
  }
}

/**
 * This method reestablishes the current client connection to the server.
 * During this phase the parameter "reconnect" is set to true until the 
 * connection is reestablished. This method closes the given socket only if
 * the attribute self->canBeClosed is true. Connections that are created here
 * and fail during creation will be closed regardless of the setting 
 * self->canBeClosed and both file descriptors will be set to -1 in such cases.
 * 
 * @param self The client socket.
 * @param delay the delay between reconnection attempts.
 * @param max_attempts The maximum attempts this function performs to establish
 *              a connection before it returns false
 * 
 * @return true if the client is reconnected.
 */
bool reconnectToServer(ClientSocket* self, int delay, int max_attempts)
{
  bool succ = false;
  // the next two ones are Just for debug
  int att=0;
  int max_att = max_attempts;
  int connectRetVal = 0;

  // Delete the file descriptor (otherwise CLOSE_WAIT)
  if (self->canBeClosed)
  {
    int fileDescriptor = self->clientFD > -1 ? self->clientFD : self->oldFD;
    if (fileDescriptor > -1)
    {
      close(fileDescriptor);
    }
  }

  // Re-initialize the file descriptors.
  self->clientFD = -1;
  self->oldFD = -1;

  // Try to reconnect
  while (self->reconnect && max_attempts > 0)
  {
    LOG(LEVEL_DEBUG, "Reconnect to Server: attempt %d of %d -- delayed time:%d",
                     ++att, max_att, delay);
    max_attempts--;

    // Create a new one socket if necessary
    if (self->clientFD == -1)
    {
      self->clientFD = socket(AF_INET, SOCK_STREAM, 0);
      self->oldFD = self->clientFD;
      if (self->clientFD < 0)
      {
        RAISE_ERROR("Failed to create a new client socket");
        succ = false;
        break;
      }
    }

    // Try to connect on TCP layer
    connectRetVal = connect(self->clientFD, 
                            (const struct sockaddr*)&self->svrAddr,
                            sizeof (self->svrAddr));
    succ =  connectRetVal == 0;
    if (succ)
    {
      // No more attempts necessary
      break;
    }

    // Close the socket - it became invalid
    switch (errno)
    {
      case ECONNREFUSED:
      case EINVAL:
                close(self->clientFD);
                self->clientFD = -1;
                self->oldFD = -1;
      default:
        break;
    }

    if (delay > 0)
    {
      sleep(delay);
    }
  }

  return succ;
}

/**
 * Turn off the reconnection feature.
 *
 * @param self The socket itself
 */
void stopReconnectingToServer(ClientSocket* self)
{
  self->reconnect = false;
}

/**
 * Returns the file descriptor.
 *
 * @param self The Client Socket.
 *
 * @return The file descriptor.
 */
inline int* getClientFDPtr(ClientSocket* self)
{
  return &self->clientFD;
}

/**
 * Returns false if the file descriptor is -1 (equals to not connected)
 *
 * @return true if the file descriptor is valid, false if -1
 */
inline bool isConnectedToServer(ClientSocket* self)
{
  return (self->clientFD != -1);
}

/**
 *
 * USE sendNum instead
 *
 * Send the data stream using the provided socket.
 *
 * @param self The socket to be used to send the data.
 * @param data The data itself.
 * @param length The number of bytes to be send
 *
 * @return true if the data could be send, otherwise false.
 */
bool sendData(ClientSocket* self, void* data, PacketLength length)
{
  int* nullPopinter = NULL;
  if (length <= 1)
  {
    *nullPopinter = 8;
  }
  return sendNum(&self->clientFD, data, (size_t)length);
//  return (sendNum(&self->clientFD, &length, sizeof(PacketLength))
//          && sendNum(&self->clientFD, data, (size_t)length));
}

/**
 * Read the given number of bytes and "drop them on the floor" (maximum 1024)
 *
 * @param client The client socket to read from
 * @param num The number of bytes to be skipped.
 *
 * @return true if num bytes where available, otherwise false.
 */
bool skipBytes(ClientSocket* client, size_t num)
{
#define NULL_SIZE 1024
  char buf[NULL_SIZE];
  size_t nb;

  while (num > 0)
  {
    nb = (num > NULL_SIZE) ? NULL_SIZE : num;
    if (!recvNum(&client->clientFD, buf, nb))
    {
      return false;
    }
    num -= nb;
  }
  return true;
}

/**
 * Receive data and write it into the given buffer.
 * 
 * @param self The socket to read from.
 * @param buffer The buffer where the data will be written into.
 * @param length the maximum length of the buffer
 * 
 * @return -1 if the connection got lost.
 */
size_t receiveData(ClientSocket* self, void* buffer, size_t length)
{
  PacketLength plen;

  if (!recvNum(&self->clientFD, &plen, sizeof(uint32_t)))
  {
    // No connection anymore
    return -1;
  }

  // Enough buffer space
  if (length >= plen)
  {
    return recvNum(&self->clientFD, buffer, plen) ? plen : -1;
  }

  // Fill the buffer and skip the rest
  if (recvNum(&self->clientFD, buffer, length)
      && skipBytes(self, plen - length))
  {
    return length;
  }

  return -1;
}

