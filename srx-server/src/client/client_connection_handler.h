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
 * Version 0.3.0.10
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 * 0.3.0    - 2013/02/27 - oborchert
 *            * Added Change log
 * 0.2.0    - 2011/11/01 - oborchert
 *            * rewritten
 * 0.1.0    - 2010/04/07 - pgleichm
 *            * Code Created
 * -----------------------------------------------------------------------------
 */
#ifndef __CLIENT_CONNECTION_HANDLER__
#define __CLIENT_CONNECTION_HANDLER__

#include <pthread.h>
#include <semaphore.h>
#include "client/srx_api.h"
#include "util/client_socket.h"
#include "util/packet.h"
#include "util/rwlock.h"
#include "util/slist.h"
#include "shared/srx_packets.h"

/**
 * This method is called to handle the packet received. The size of the pdu is
 * specified in the second int32 value of the header. It is assured that the
 * amount of bytes in dataHeader contains a valid SRX-PROXY PDU. (The length is
 * specified in the well known length field position.
 *
 * @param pduType     PDU type of the packet
 * @param dataHeader  The data packet header.
 * @param srxProxy    The instance of the proxy that processes this packet.
 */
//typedef void (*SRxPacketHandler)(SRxProxyPDUType pduType, void* dataHeader,
//                                 void* srxProxy);

/**
 * A single Client Connection Handler.
 */
typedef struct {
  // Arguments
  bool             initialized;   // Indicates if this instance is initialized.
  bool             established;   // Indicates if a connection is established.
  
  SRxPacketHandler packetHandler; // The packet handler that deals with packets
                                  // received.

  // Internal
  ClientSocket     clSock;        // Connection to the server
  pthread_t        recvThread;    // Receiving thread
  bool             stop;          // Do not try to reconnect, receive
  SList            sendQueue;     // Buffers send requests if offline
  RWLock           queueLock;     // Protects the \c sendQueue
  bool		   bRecvSet;

  // Used to allow handling of send and receive from two separate threads.
  sem_t		   sem_transx;
  sem_t		   sem_register;
  sem_t		   sem_crit_sec;
  pthread_cond_t*  cond;
  pthread_mutex_t* rcvMonitor;      // The proxy can wait on this mutex for
                                    // receipts to be received.
  uint32_t         svdRequestToken; // The request token is is set each time 
                                    // the value of the syncValData 
                                    // attribute is changed. This is done using 
                                    // method setSyncValData(...). The initial
                                    // value MUST be 1

  uint32_t         handshake_timeout; // The time in seconds allowed to wait
                                    // until a handshake timeout occurs.

  // Pointer to the srx proxy
  uint32_t         keepWindow;    // a default keep window value.
  SRxProxy*        srxProxy;      // A pointer to the SRX proxy instance.
                                  // Will be set using the method
                                  // initializeClientConnectionHandler.
} ClientConnectionHandler;

/**
 * Create the clientConnectionHandler by allocating the memory and setting 
 * certain values to a pre-initialized state. The memory of the 
 * ClientConnectionHandler MUST be freed by the caller of this method!!!
 *
 * @param proxy The SRX Proxy this connection handler belongs to -
 *        MUST NOT BE NULL
 * 
 * @return an instance of ClientConnectionHandler of NULL.
 */
ClientConnectionHandler* createClientConnectionHandler(SRxProxy* proxy);

/**
 * Initialized the client connection handler used by the SRx Proxy to connect
 * to the SRx server. The instance must be created elsewhere. This method
 * requires the attribute initialized to be set to false. Best is to have the
 * Handler created using the here provided create method.
 * Once set to true the instance must never be initialized again. The attribute
 * initialized will be set to true once this method exits with true.
 * This method also created the client socket but does NOT attempt to connect
 * the transport layer. This is done using the connectToSRx method.
 *
 * @param self             Instance that should be be initialized.
 * @param host             Server host name.
 * @param port             Server port address.
 * @param packetHandler    Received packets are passed to this function.
 * @param handshakeTimeout The time in seconds a handshake MUST be completed.
 *
 * @return true = connection established and handshake performed,
 *         false = failed to connect.
 *
 * @see releaseClientConnectionHandler
 */
bool initializeClientConnectionHandler(ClientConnectionHandler* self,
                                       const char* host, int port,
                                       SRxPacketHandler packetHandler,
                                       uint32_t handshakeTimeout);

/** 
 * Closes the connection to the server.
 *
 * @param self Instance that should be used
 */
void releaseClientConnectionHandler(ClientConnectionHandler* self);

/**
 * This method waits until data is received. It is expected that the lock is 
 * already set.
 *
 * @param self The connection handler to wait on.
 *
 * @return true if the wait could be executed, otherwise false.
 */
inline bool connHandlerWait(ClientConnectionHandler* self);

/**
 * This method waits until data is received. It is expected that the lock is
 * already set.
 *
 * @param self The Client connection handler.
 *
 * @return true if the notify could be send, otherwise false.
 */
inline bool connHandlerNotify(ClientConnectionHandler* self);

/**
 * This method locks the mutex for wait and notification
 *
 * @param self The Client connection handler.
 *
 * @return true if the lock could be taken.
 */
inline bool connHandlerLock(ClientConnectionHandler* self);

/**
 * This method unlocks the mutex for wait and notification
 *
 * @param self The Client connection handler.
 *
 * @return true if the lock could be removed.
 */
inline bool connHandlerUnlock(ClientConnectionHandler* self);

/**
 * Sends a packet to the server.
 *
 * @param self Instance that should be used
 * @param header The proxySRX PDU to be send.
 * @param length Data size in bytes. This method does not read the header length
 *               field, it goes with the length provided. This can allow to
 *               send a stream of multiple pdu's at once.
 * @return true = data sent successfully, false = sending failed
 *         (e.g. no connection)
 */
bool sendPacketToServer(ClientConnectionHandler* self, SRXPROXY_PDU* header,
                        uint32_t length);


/*
 * Create the connection of application layer between srx and proxy
 *
 * @param clSock The socket to be used to talk to the server
 * @param noPeers The number of peers this proxy contains
 * @param peerAS the peer numbers
 * @return true if the handshake was successful.
 */
bool handshakeWithServer(ClientConnectionHandler* self, SRXPROXY_HELLO* pdu);

/**
 * Send the goodbye message to the server. This message is done by directly
 * calling the sendData method without using the sendPacketToServer method.
 * Most likely after a goodbye the socket will be closed right away and all
 * buffers are emptied!
 *
 * The attribute "established" will be set to false due to the fact that this
 * message the application layer connection closes. (only if the function
 * returns true)
 *
 * @param self The pointer to the client connection handler.
 * @param keepWindow the keep window value.
 *
 * @return true if the message could be send, otherwise false.
 */
bool sendGoodbye(ClientConnectionHandler* self, uint16_t keepWindow);

/**
 * This method allows to re-establish a connection between proxy and srx-server
 * this method will close an existing connection to the srx server on the
 * application layer sending a GoodBye message and if the socket is not
 * maintained externally it closes the socket. In case the socket is managed
 * outside the socket will not be closed but a new one will be installed.
 * The reconnect will result in a handshake. The new socket will have the
 * same features as the old one. A ClientConnectionHandler can only be restarted
 * if it was not stopped.
 *
 * @param self The ClientConnection handler.
 *
 * @return true if the reconnect was successful, otherwise false.
 */
bool reconnectSRX(ClientConnectionHandler* self);
#endif // !__CLIENT_CONNECTION_HANDLER__

