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
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 * 0.3.0    - 2013/01/09 - oborchert
 *            * Added getter for last error code produced. 0 for no error.
 *            * Removed the extern keyword - not needed.
 *          - 2012/12/17 - oborchert
 *            * Minor changes, mainly formating and spellers in documentation
 *            * Added change log.
 *            * Changed mode of sending data
 * 0.2.0    - SKIPPED
 * 0.1.0    - 2009/12/29 - pgleichm
 *            * Code Created
 */
#ifndef __SOCKET_H__
#define __SOCKET_H__

#include <sys/socket.h>
#include "util/prefix.h"

/** 
 * Max. length of the textual representation of a socket.
 *
 * @see sockAddrToStr
 * @see socketToStr
 */
#define MAX_SOCKET_STRING_LEN (MAX_IP_V6_STR_LEN + 6)

/**
 * Reads \c num Bytes from a socket.
 * In case of an error, \c fd is closed and set to \c -1.
 *
 * @note Blocking call
 *
 * @param fd File-descriptor pointer
 * @param buffer (out) Destination for the read data
 * @param num Number of Bytes to read
 * @return \c true = successful, \c = failed
 * @see sendNum
 */
bool recvNum(int* fd, void* buffer, size_t num);

/** 
 * Writes \c num Bytes to a socket.
 * In case of an error, \c fd is closed and set to \c -1.
 *
 * @param fd File-descriptor pointer
 * @param buffer Data to write
 * @param num Size of buffer
 * @return \c true = successful, \c = failed
 */
bool sendNum(int* fd, void* buffer, size_t num);

/**
 * Returns a textual representation of a \c sockaddr.
 *
 * @param sa Socket address
 * @param dest Destination buffer
 * @param size Size of \c dest
 * @return String 
 */
const char* sockAddrToStr(const struct sockaddr* sa, 
                                 char* dest, size_t size);

/**
 * Returns a textual representation of a socket.
 *
 * @param fd Socket (file descriptor)
 * @param isPeer Is a conncted peer (= client)
 * @param dest Destination buffer
 * @param size Size of \c dest
 * @return String 
 */
const char* socketToStr(int fd, bool isPeer, char* dest, size_t size);

/**
 * Return the last produced error code while sending. Zero "0" if no error 
 * occured.
 * 
 * @return the error that occured during the last send operation or zero "0"
 * 
 * @since 0.3.0
 */
int getLastSendError();

/**
 * Return the last produced error code while receiving. Zero "0" if no error 
 * occured.
 * 
 * @return the error that occured during the last receive operation or zero "0"
 * 
 * @since 0.3.0
 */
int getLastRecvError();

#endif // !__SOCKET_H__

