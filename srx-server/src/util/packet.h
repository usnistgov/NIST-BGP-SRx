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
 *            * Added Changelog
 * 0.1.0.0  - 2009/12/08 - pgleichm
 *            * Code creaded.
 */
#ifndef __PACKET_H__
#define __PACKET_H__

#include "shared/srx_packets.h"

/** Specifies the length of a packet. */
typedef uint32_t PacketLength;

/** This enumeration helps to determine who uses the packet handler, the SRx 
 * server or the SRx proxy. */
typedef enum {
  PHT_PROXY  = 0,
  PHT_SERVER = 1
} PacketHandlerType;

/**
 * This method is called to handle the packet received. The size of the pdu is
 * specified in the second uin32_t value of the header. It is assured that the
 * amount of bytes in dataHeader contains a valid SRX-PROXY PDU. (The length is
 * specified in the well known length field position.
 *
 * @param dataHeader  The data packet header.
 * @param cHandler    The instance of the SRx or proxy that processes this
 *                    packet or NULL if used on server side.
 */
typedef void (*SRxPacketHandler)(SRXPROXY_BasicHeader* dataHeader,
                                 void* cHandler);

/**
 * This function runs in a loop to receive packets. This function is used as 
 * receiver loop on both sides, SRx server as well as SRx client. IN case the 
 * SRx server uses. this method the parameter connHandler MUST be NULL.
 *
 * @note Blocking call!
 *
 * @param fdPtr        The file descriptor of the socket
 * @param dispatcher   The dispatcher method that receives all packets and
 *                     distributes them.
 * @param pHandler     Instance of the packet handler. On SRx server side this 
 *                     will be ClientThread, on the proxy side this will be 
 *                     SRxProxy.
 * @param pHandlerType The type of handler, srx-proxy or srx-server.
 *
 * @return true if the method ended clean.
 */
bool receivePackets(int* fdPtr, SRxPacketHandler dispatcher, void* pHandler, 
                    PacketHandlerType pHandlerType);

#endif // !__PACKET_H__

