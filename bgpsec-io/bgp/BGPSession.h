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
 * This header provides the function headers for the BGPSocket loop.
 * 
 * @version 0.2.0.0
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.0.0 - 2016/05/10 - oborchert
 *            * Fixed compiler warnings BZ950
 *            * Renamed function _shutDownTCPSession into shutdownTCPSession an
 *              included it in the header file.
 *          - 2016/05/06 - oborchert
 *            * Renamed the methods _checkMessageHeader and _processOpenMessage
 *              into checkMessageHeader and processOpenMessage and added them to
 *              the header file.
 *  0.1.1.0 - 2016/03/21 - oborchert
 *            * Modified debug output in session configuration.
 *  0.1.0.0 - 2015/08/17 - oborchert
 *            * Created File.
 */
#ifndef BGPSESSION_H
#define	BGPSESSION_H

#include <stdbool.h>
#include <time.h>
#include <semaphore.h>
#include <netinet/in.h>

#include "bgp/BGPHeader.h"
#include "bgp/BGPFinalStateMachine.h"

/** mainly used for update messages */
#define SESS_MIN_MESSAGE_BUFFER 10240

/** Buffer mostly used for Open, KeepAlive, Notification */
#define SESS_MIN_SEND_BUFF 1024

/** The default sleep time in the receiver loop */
#define SESS_DEV_RCV_SLEEP 1
/** The default sleep time in the session loop */
#define SESS_DEV_SLEEP 4

/** Specify timeout for receive messages during message negotiation. */
#define SESS_TIMEOUT_RCV_OPEN 10
/** Specify default timeout while waiting for messages. */
#define SESS_DEF_RCV_TIMEOUT  0

/** This callback method is used to process receiving messages. The message
 * itself contains a BGP message specified in RFC4271. This function MUST
 * consider the FSM state of the session and possibly change the state to
 * signal the FSM a state change.
 * 
 * @param session The session that contains the packet.
 */
typedef void (*process_packet)(void* session);

typedef struct
{
  /** the session file descriptor. */
  int sessionFD;
  /** The receiver buffer of this session. */
  char* recvBuff;
  /** Allocated size of the receive buffer. */
  int buffSize;
  
  /** indicates if the session is active or not - This is used to control the 
   * thread that manages the session. once run is false all threads will stop 
   * their loop - DONT mix up with the BGP FSM */
  bool run;
  /** Indicates if the TCP session is established or not. */
  bool tcpConnected;

  /** BGP session configuration. */
  BGP_SessionConf bgpConf;
  
  /** Last time any BGP packet was send after session was established. */
  time_t lastSent;
  /** Last time a BGP update was send. */
  time_t lastSentUpdate;
  /** Last time any BGP packet was received after session was established. */
  time_t lastReceived;

  /** The BGP Final State Machine for this session. s*/
  BGPFinalStateMachine fsm;
  
  /** This callback method is used to preciess receiving messages. The message
   * itself contains a BGP message specified in RFC4271*/
  process_packet processPkt;
  
  /** The semaphor for the hold timer. This allows to be woken up prior the time
   * expiration. No need for sleep anymore. */
  sem_t* sessHoldTimerSem;
} BGPSession;

/**
 * Allocates the memory for the session and configures soem of its values.
 * the configured values are he minimal necessary values to be able to establish
 * a BGP session.
 *  
 * @param buffSize The internal buffer size.
 * @param config   The session configuration 
 * @param process  The method to process received packages.
 * 
 * @return the allocated memory of the session. 
 */
BGPSession* createBGPSession(int buffSize, BGP_SessionConf* config,
                             process_packet process);

/**
 * Free the given session and its internal buffer. In case the session is still
 * active this method will shutdown the session as well.

 * 
 * @param session the session to be freed.
 */
void freeBGPSession (BGPSession* session);


/** 
 * Run the BGP session - Should be part of BGPSession.c
 * 
 * @param session the BGP session to be managed.
 */
void* runBGP(void* bgp);

/** 
 * Read the next BGP message and writes it into the sessions buffer. This method
 * will only read as long as FSM is in ESTABLISHED or OpenSent mode.
 * 
 * @param session the session to read from.
 * @param timeout timeout in seconds. No timeout if 0;
 * 
 * @return 0 = EOF / timeout, &lt; 0 error, &gt; 0 number bytes read.
 */
int readNextBGPMessage(BGPSession* session, int timeout);

/**
 * The FSM MUST be in FSM_STATE_OpenSent to be able to send the open message.
 * 
 * @param session the session information
 * 
 * @return true if the OpenMessage could be sent.
 */
bool sendOpenMessage(BGPSession* session);

/**
 * Send a keepalive to the peer. The FSM must be in ESTABLISHED
 * 
 * @param session the session where to send to
 * 
 * @return true if the mesage could be sent otherwise false.
 */
bool sendKeepAlive(BGPSession* session);

/**
 * Send a notification to the peer. This function will update the 
 * session.lastSent value.
 * 
 * @param session The session to send the notification to.
 * @param error_code The error code of the notification.
 * @param subcode the subcode of the error.
 * @param dataLength The length of the attached data (can be zero)
 * @param data the data to attach.
 * 
 * @param type the type of the notification.
 * 
 * @return true if successful, otherwise false.
 */
bool sendNotification(BGPSession* session, int error_code, int subcode, 
                      u_int16_t dataLength, u_int8_t* data);

/**
 * Send the given BGP update. This function will modify the session.lastSent
 * and session.lastUpdateSend values.
 * 
 * @param session The session where to send the update to.
 * 
 * @param update The update to be send.
 * 
 * @return true if the update could be send.
 */
bool sendUpdate(BGPSession* session, BGP_UpdateMessage_1* update);


/**
 * Establish a TCP Session to the peer with the given peer IP. 
 * 
 * @param session the necessary session information.
 * 
 * @return true if a TCP session could be established.
 */
bool establishTCPSession(BGPSession* session);

/**
 * Check the message header for correctness. If not correct and a notification 
 * needs to be send, it will do so.
 * 
 * @param session The bgp session.
 */
bool checkMessageHeader(BGPSession* session);

/**
 * Process the open message while FSM is in FSM_STATE_OpenSent. This function 
 * checks with the FSM and modifies its state if necessary. It also sends out a
 * notification if needed and closes the TCP connection if required. In case
 * the recvBuff contains a notification message it will shut down the session.
 * (session->run = false)
 * 
 * @param session The session that contains the open message.
 */
void processOpenMessage(BGPSession* session);

/**
 * Close the socket. (NO NOTIFICATION IS SENT)
 * 
 * @param session the session that has to be shut down.
 * @param reportError indicates if an error during closing the session should
 *                    be reported or not.
 */
void shutDownTCPSession(BGPSession* session, bool reportError);
#endif	/* BGPSESSION_H */

