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
 *   0.3.0 - 2013/02/27 - oborchert
 *           * Changed handling of errors by storing errno and not always 
 *             calling it. In certain circumstances of thread handling the errno
 *             value can re overwritten in between calls.
 *         - 2013/01/09 - oborchert
 *           * Added getter for last error code produced. 0 for no error.
 *           * Removed the extern keyword - not needed.
 *         - 2012/12/17 - oborchert
 *           * Minor changes, mainly formating and spellers in documentation
 *           * Added change log.
 *           * Changed mode of sending data
 *   0.2.0 - SKIPPED
 *   0.1.0 - 2009/12/29 - pgleichm
 *           * Code Created
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include "shared/srx_packets.h"
#include "util/socket.h"
#include "util/log.h"

#include <fcntl.h>
#include <pthread.h>

#define HDR "([0x%08X] Socket {%u}): "

/** Contains the last produced error code while sending. */
static int _sockSendError = 0;
/** Contains the last produced error code while receiving. */
static int _sockRecvError = 0;

typedef enum {
  SOCK_OP_SEND = 1,
  SOCK_OP_RCV = 0
} SockOperation;

// Forward declaration
void _setLastError(int errorCode, SockOperation operation);

/**
 * This method receives bytes and writes them into the given buffer.
 *
 * @param fd The file descriptor of the socket.
 * @param buffer The buffer to be send.
 * @param num The number of bytes to be send.
 *
 * @return true if data could be received and written in the buffer,
 * otherwise false.
 */
bool recvNum(int* fd, void* buffer, size_t num)
{
  ssize_t     rbytes;
  _setLastError(0, SOCK_OP_RCV);
  
  if (*fd == -1)
  {
    _setLastError(EBADF, SOCK_OP_RCV);
    return false;
  }

  // Loop until all data is received.
  while (num > 0)
  {
    LOG(LEVEL_COMM, HDR "Wait to read (%u) bytes from Socket (status:%u).",
                     pthread_self(), *fd, num, errno);
    //rbytes = recv(*fd, buffer, num, MSG_WAITALL);
    _setLastError(0, false);
    rbytes = recv(*fd, buffer, num, MSG_NOSIGNAL | MSG_WAITALL);
    LOG(LEVEL_COMM, HDR "Read %u of %u bytes from Socket (status: %u).",
                     pthread_self(), *fd, rbytes, num, errno);
    // An error occurred
    if (rbytes == -1)
    {      
      int ioError = errno;
      _setLastError(ioError, false);
      if (ioError != EAGAIN)
      {
        // Print an error message only if not intentional
        if ((ioError != EBADF) && (ioError != ECONNRESET))
        {
          RAISE_SYS_ERROR("Socket error 0x%X (%u) while receiving data!",
                          ioError, ioError);
        }
        else
        {
          LOG(LEVEL_DEBUG, HDR "Socket error 0x%X (%u) while receiving data - "
                           "Close socket!", pthread_self(), ioError, ioError);
          //close(*fd);
        }
        *fd = -1;
        return false;
      }
    }

    // Connection lost
    if (rbytes == 0)
    {
      LOG(LEVEL_INFO, "Connection reset by peer.");
      //close(*fd); // No CLOSE_WAIT
      *fd = -1;
      return false;
    }


    buffer += rbytes;
    num -= rbytes;
  };

  return true;
}

/**
 * Send the data stored in the buffer. this method closes the socket in case of
 * an error.
 *
 * @param fd the file descriptor of the socket to write into.
 * @param buffer The buffer to be written.
 * @param num the number of bytes to be written.
 *
 * @return true if the data could be send, otherwise false.
 */
bool sendNum(int* fd, void* buffer, size_t num)
{
  ssize_t sbytes;
  bool retVal = true;

  // Reset the error code
  _setLastError(0, SOCK_OP_SEND);
  
  if (*fd == -1)
  {
    LOG(LEVEL_DEBUG, FILE_LINE_INFO " File descriptor is invalid!");
    _setLastError(EBADF, SOCK_OP_SEND);
    return false;
  }

  while (num > 0)
  {
    sbytes = send(*fd, buffer, num, MSG_NOSIGNAL | MSG_WAITALL);
    //sbytes = send(*fd, buffer, num, MSG_NOSIGNAL | MSG_WAITFORONE);

    // Any Error occurred
    if (sbytes <= 0)
    {
      _setLastError(errno, SOCK_OP_SEND);
      // Removed this sys error to allow the caller for completely deal with it.
      // If an error occurs, the error will be stored and can be retrieved using 
      // the method getLastSendError. In addition this method will return false
      // to indicate that something went wrong.      
      //RAISE_SYS_ERROR("Socket error 0x%X (%u) while sending data!",
      //                    errno, errno);

      /* Partial write. */
      if (errno == EWOULDBLOCK || errno == EAGAIN)
      {
        // TODO: later, re-try algorithm should be introduced here
        continue;
        //retVal = false;
        //break;
      }
      else if ((errno != EBADF) && (errno != ECONNRESET))
      {
        ;//close(*fd);
      }

      *fd = -1;
      retVal = false;
      return retVal;
    }

    buffer += sbytes;
    num -= sbytes;
  }

  return retVal;
}

/**
 * Generate the address string of the socket.
 *
 * @param sa The socket address plus port number
 * @param dest The destination string pointer
 * @param size the size of the destination.
 *
 * @return pointer to the destination.
 */
const char* sockAddrToStr(const struct sockaddr* sa, char* dest, size_t size)
{
  const char* ret;
  in_port_t port;
  size_t len;

  if (sa == NULL)
  {
    return strncpy(dest, "(null)", size);
  }

  // IPv4
  if (sa->sa_family == AF_INET)
  {
    ret = inet_ntop(AF_INET, &((struct sockaddr_in*)sa)->sin_addr,
                    dest, size);
    port = ((struct sockaddr_in*)sa)->sin_port;

    // IPv6
  }
  else if (sa->sa_family == AF_INET6)
  {
    ret = inet_ntop(AF_INET6, &((struct sockaddr_in6*)sa)->sin6_addr,
                    dest, size);
    port = ((struct sockaddr_in6*)sa)->sin6_port;

    // Unknown address family
  }
  else
  {
    return strncpy(dest, "(Unknown type)", size);
  }

  if (ret == NULL)
  {
    strncpy(dest, "(Invalid IP)", size);
  }

  // Append the port
  len = strlen(dest);
  snprintf(dest + len, size - len, ":%d", ntohs(port));
  return dest;
}

/**
 * Returns the address of the given socket as string.
 *
 * @param fd The file descriptor.
 * @param isPeer
 * @param dest
 * @param size
 *
 * @return the address of the given socket as string.
 */
const char* socketToStr(int fd, bool isPeer, char* dest, size_t size)
{
  struct sockaddr sa;
  socklen_t slen = sizeof (struct sockaddr);

  if (   (isPeer && getpeername(fd, &sa, &slen) == -1)
      || (!isPeer && getsockname(fd, &sa, &slen) == -1))
  {
    return strncpy(dest, "(Invalid socket)", size);
  }
  return sockAddrToStr(&sa, dest, size);
}

/**
 * Set the internal const variable of the error code. This function handles 
 * both, sending and receiving.
 * 
 * @param errorCode The error code in case an error occured.
 * @param operation Specifies if the error occured during sending or receiving 
 *                  data.
 * 
 * @since 0.3.0
 */
void _setLastError(int errorCode, SockOperation operation)
{
  switch (operation)
  {
    case SOCK_OP_SEND:
      _sockSendError = errorCode;
      break;
    case SOCK_OP_RCV:
      _sockRecvError = errorCode;
      break;
    default:
      RAISE_SYS_ERROR("Invalid SockOperation type! %u", operation);      
  }
}

/**
 * Return the last produced error code while sending. Zero "0" if no error 
 * occured.
 * 
 * @return the error that occured during the last send operation or zero "0"
 * 
 * @since 0.3.0
 */
int getLastSendError()
{
  return _sockSendError;
}

/**
 * Return the last produced error code while receiving. Zero "0" if no error 
 * occured.
 * 
 * @return the error that occured during the last receive operation or zero "0"
 * 
 * @since 0.3.0
 */
int getLastRecvError()
{
  return _sockRecvError;
}

