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
 * This software implements a BGP final state machine, currently only for the
 * session initiator, not for the session receiver. 
 *  
 * @version 0.2.0.0
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.0.0 - 2016/06/13 - oborchert
 *            * Added more information in case of a failed TCP connection.
 *          - 2016/05/17 - oborchert
 *            * Renamed parameter in _rcvBGP which is more self explanatory
 *          - 2016/05/13 - oborchert
 *            * Enhanced the poll loop printout.
 *          - 2016/05/12 - oborchert
 *            * Fixed some string formatting
 *            * Changed FSM state immediately after receiving Notification
 *          - 2016/05/10 - oborchert
 *            * Fixed compiler warnings BZ950
 *            * Renamed function _shutDownTCPSession into shutdownTCPSession an
 *              included it in the header file.
 *            * Modified the detection of broken sockets in _isSocketAlive that 
 *              does work in CentOS7 as well.
 *          - 2016/05/06 - oborchert
 *            * Fixed BZ947: Modified the behavior when receiving a notification
 *              from peer during establishment of a BGP session.
 *            * Renamed the methods _checkMessageHeader and _processOpenMessage
 *              into checkMessageHeader and processOpenMessage and added them to
 *              the header file.
 *            * Fixed issue with already blocked socket. BZ:924
 *  0.1.1.0 - 2016/04/21 - oborchert
 *            * Extended the session configuration.
 *          - 2016/03/21 - oborchert
 *            * Fixed some error formating (printout)
 *          - 2016/03/21 - oborchert
 *            * Modified debug output in session configuration.
 *  0.1.0.0 - 2015/08/17 - oborchert
 *            * Created File.
 */
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 
#include <time.h>
#include <openssl/err.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <poll.h>
#include "bgp/BGPSession.h"
#include "bgp/BGPHeader.h"
#include "bgp/printer/BGPHeaderPrinter.h"
#include "bgp/printer/BGPUpdatePrinter.h"

#define POLL_TIMEOUT_MS 100

static void _processPacket(void* session);

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
                             process_packet process)
{
  BGPSession*      session    = NULL;
  BGP_SessionConf* sessConfig = NULL;
  AlgoParam*       sessAlgo   = NULL;
  AlgoParam*       configAlgo = NULL;
  
  int idx;
  
  if (config->peer_addr.sin_port > 0)
  {
    session = malloc(sizeof(BGPSession));
    memset(session, 0, sizeof(BGPSession));

    sessConfig = &session->bgpConf;
    
    sessConfig->asn            = config->asn;
    sessConfig->bgpIdentifier  = config->bgpIdentifier;
    sessConfig->holdTime       = config->holdTime;
    sessConfig->disconnectTime = config->disconnectTime;
    sessConfig->useMPNLRI      = config->useMPNLRI;
    for (idx = 0; idx < PRNT_MSG_COUNT; idx++)
    {
      sessConfig->printOnReceive[idx] = config->printOnReceive[idx];
      sessConfig->printOnSend[idx]    = config->printOnSend[idx];
    }
    sessConfig->printPollLoop  = config->printPollLoop;
                
    session->lastSent  = 0;
    
    session->sessionFD = -1;
    session->recvBuff  = malloc(buffSize);
    memset(session->recvBuff, 0, buffSize);
    session->buffSize  = buffSize;

    sessConfig->peerAS   = config->peerAS;
    memcpy(&session->bgpConf.peer_addr, &config->peer_addr, 
           sizeof(struct sockaddr_in));
    
    session->processPkt   = process  != NULL ? process  : _processPacket;
    
    session->fsm.session = session;
    session->fsm.state   = FSM_STATE_IDLE;
    int keepAliveTime = config->holdTime > 3 ? (int)(config->holdTime / 3) 
                                             : FSM_KEEPALIVE_TIME;
    session->fsm.keepAliveTime       = keepAliveTime;
    session->fsm.connectRetryTime    = FSM_RECONNECT_TIME;
    session->fsm.connectRetryCounter = 0;
    
    sessAlgo   = &sessConfig->algoParam;
    configAlgo = &config->algoParam;

    // Do the loop.    
    while (configAlgo != NULL && sessAlgo != NULL)
    {
      sessAlgo->addPubKeys     = configAlgo->addPubKeys;
      sessAlgo->algoID         = configAlgo->algoID;
      sessAlgo->asList         = configAlgo->asList;
      // the danger in the memory copy below is that it also copies the position
      // if a key pointer. This pointer MUST not be free'd from within the 
      // session - it will be maintained from the within the configuration 
      // parameter which must exist until this session is removed.      
      memcpy(&sessAlgo->fake_key, &configAlgo->fake_key, sizeof(BGPSecKey));
      
      sessAlgo->fake_sigLen    = configAlgo->fake_sigLen;
      memcpy(&sessAlgo->fake_signature, &configAlgo->fake_signature, 
             configAlgo->fake_sigLen);
      sessAlgo->pubKeysStored  = 0;
      sessAlgo->ns_mode        = configAlgo->ns_mode;
      configAlgo = configAlgo->next;
      if (configAlgo != NULL)
      {
        sessAlgo = malloc(sizeof(AlgoParam));
        memset(sessAlgo, 0, sizeof(AlgoParam));
      }
    }
  }
  
  return session;
}

/**
 * Close the socket. (NO NOTIFICATION IS SENT)
 * 
 * @param session the session that has to be shut down.
 * @param reportError indicates if an error during closing the session should
 *                    be reported or not.
 */
void shutDownTCPSession(BGPSession* session, bool reportError)
{
  int retVal = close(session->sessionFD);
  if (retVal != 0 && reportError)
  {
    printf("ERROR: Shutdown not successful code [%i]\n", retVal);
  }
  session->tcpConnected = false;
  session->sessionFD = -1;
}

/**
 * Free the given session and its internal buffer. In case the session is still
 * active this method will shutdown the session as well.
 * 
 * @param session the session to be freed.
 */
void freeBGPSession (BGPSession* session)
{
  // @TODO: Consider the FSM - maybe refuse to free as long as FSM is NOT IDLE
  if (session)
  {
    if (session->tcpConnected)
    {
      shutDownTCPSession(session, true);
    }
    free(session->recvBuff);
    session->recvBuff = NULL;
    AlgoParam* sessParam = session->bgpConf.algoParam.next;
    AlgoParam* next = NULL;
    while (sessParam != NULL)
    {
      next = sessParam->next;
      free(sessParam);
      sessParam = next;
    }
    free(session);
  }
}

/**
 * Check if the socked is open or closed. (This method has a timeout of 100ms.)
 * This method is extended with the information for what. If the peer closed
 * it there might still be data in it what might be of interest.
 * 
 * @param session  The BGPSession information.
 * @param timeout  The polling timeout in milli seconds.
 * @param readOnly In case of a peer reset, it might be the socket still has 
 *                 data that can be read. There if revents contains POLLIN it 
 *                 returns true if readOnly is selected.
 * 
 * @return true if it can be used, otherwise false. 
 */
static bool _isSocketAlive(BGPSession* session, int timeout, bool readOnly)
{
  bool retVal = true;
  
  short int errmask  = POLLERR | POLLHUP | POLLNVAL;
#ifdef __USE_GNU
  errmask = errmask | POLLRDHUP;
#endif
            
  struct pollfd pfd;
  pfd.fd      = session->sessionFD;
  pfd.events  = POLLIN | POLLPRI | POLLOUT | POLLRDNORM;
#if defined __USE_XOPEN || defined __USE_XOPEN2K8
  pfd.events  = pfd.events | POLLRDNORM	| POLLRDBAND | POLLWRNORM	| POLLWRBAND;
#endif
#ifdef __USE_GNU
  pfd.events  = pfd.events | POLLMSG;
#endif
  
  pfd.revents = 0;
  int pollVal = poll(&pfd, 1, timeout);
  if (pollVal <= 0)
  {
    // Lets do it differently!
    if (!readOnly)
    {
      retVal = (pfd.revents & errmask) == 0;
    }
    else
    {
      retVal = (pfd.revents & POLLIN) != 0;      
    }
// The lower portion does not work correctly in centos 7
//    char buff[32];
//    int rec = recv(pfd.fd, buff, sizeof(buff), MSG_PEEK | MSG_DONTWAIT); 
//    if (rec == 0)
//    {
//      // zero => connection has been closed
//      retVal = false;
//    }
  }

  if (session->bgpConf.printPollLoop)
  {
    printf("Session[AS %d] Socket Poll [timeout=%i, FD=%i, events=0x%02X, "
           "revents=0x%02X]\n", session->bgpConf.asn, timeout,
            pfd.fd, pfd.events, pfd.revents);
  }
  
  return retVal;
}

/**
 * This is the sessions receiver thread. It will be created within runBGP.
 * 
 * @param bgpSession the session itself.
 * 
 * @return NULL
 */
static void* _rcvBGP(void* bgpSession)
{
  BGPSession* session = (BGPSession*)bgpSession;
  int bytesReady = 0;
  int bytesRead  = 0;

  while (session->fsm.state == FSM_STATE_ESTABLISHED) 
  {
    if (!_isSocketAlive(session, POLL_TIMEOUT_MS, true))
    {
      printf("ERROR: Socket to AS %u broke!\n", session->bgpConf.peerAS);
      fsmSwitchState(&session->fsm, FSM_STATE_IDLE);
      continue;
    }
    bytesReady = 0;
    ioctl(session->sessionFD, FIONREAD, &bytesReady);
    if (bytesReady > 0)
    {
      bytesRead = readNextBGPMessage(session, SESS_DEF_RCV_TIMEOUT);
      if (bytesRead > 0)
      {
        _processPacket(session);
      }
    }
    else
    {
      if (session->bgpConf.printPollLoop)
      {
        printf("Wait for receive!\n");
      }
      sleep(SESS_DEV_RCV_SLEEP);
    }
  }
  
  return NULL;
}

/** 
 * Run the BGP session. This method expects the BGP session to be in 
 * IDLE mode and establish the session. It keeps the session running as long
 * as configured.
 * 
 * @param session the BGP session to be managed.
 */
void* runBGP(void* bgp)
{ 
  BGPSession* session = (BGPSession*)bgp;
  
  if (fsmEstablishBGP(&session->fsm))
  {
    // Create a receiver thread that handles the receiving side.            
    pthread_t bgp_rcv_thread;
    
    if (pthread_create(&bgp_rcv_thread, NULL, _rcvBGP, session))
    {
      printf ("Error creating BGP-receiver thread!\n");
    } 
    else
    {
      session->sessHoldTimerSem = malloc(sizeof(sem_t));
      if (sem_init(session->sessHoldTimerSem, 0, 0) == -1)
      {
        printf("WARNING: Could not generate the HoldTimer semaphor!\n");
        // This will cause shutdowns to take up to holdtime/3 seconds to 
        // complete.
        free(session->sessHoldTimerSem);
        session->sessHoldTimerSem = NULL;
      }
      
      printf ("BGP-receiver thread created!\n");
      // Now here we can send Updates like crazy !!!!
      if (session->fsm.state == FSM_STATE_ESTABLISHED)
      {
        // hold time loop is the session loop. It sends keep alives as long as 
        // no  updates are send to keep the session running.
        fsmRunHoldTimeLoop(&session->fsm);
        // We end here if either the FSM changed or the hold timer is set to 
        // zero which means no keep alives to be send. In the later case the FSM
        // will still be ESTABLISHED. if we end here with hold time > 0 then
        // cease the session and stop, Otherwise keep the session open until the
        // disconnect time is reached or the peer closes the session.
        while (session->fsm.state == FSM_STATE_ESTABLISHED)
        {
          printf("runBGP - loop\n");
          if (session->bgpConf.holdTime > 0)
          { // The hold time loop was stopped. session is still established,
            // send notification
            sendNotification(session, BGP_ERR6_CEASE, 
                             BGP_ERR6_SUB_PEER_DE_CONFIGURED, 0, NULL);
          }
          else
          {
            // No hold time => no loop, check if disconnect is specified
            if (session->bgpConf.disconnectTime > 0)
            {
              // disconnect after last update message was send.
              time_t now = time(0);
              if (now < (session->lastSentUpdate 
                         + session->bgpConf.disconnectTime))
              {
                sendNotification(session, BGP_ERR6_CEASE, 
                                 BGP_ERR6_SUB_PEER_DE_CONFIGURED, 0, NULL);        
              }
            }
          }
          // hold_time is 0 => no keep alive - peer will eventually close session 
          //   if no more update is send by this session.
          // Updates will be send from elsewhere - this keeps the session only up 
          //   and running 
          sleep(SESS_DEV_SLEEP);
        }
      }
      
      if (session->sessHoldTimerSem != NULL)
      {
        // Just in case, wake up a still sleeping hold timer.
        sem_post(session->sessHoldTimerSem);
        free(session->sessHoldTimerSem);
        session->sessHoldTimerSem = NULL;
      }
      // Now wait until all threads come back - then shutdown.
      void* pVal = NULL;
      pthread_join(bgp_rcv_thread, &pVal);
    }
    
    if (session->fsm.state != FSM_STATE_IDLE)
    {
      sendNotification(session, BGP_ERR5_FSM, BGP_ERR_SUB_UNDEFINED, 0, NULL);
    }
          
    // Now shutdown the session.
    shutDownTCPSession(session, true);      
  }
  else
  {
    printf("NOTIFICATION: Could not establish the session %u <=> %u!\n",
           session->bgpConf.asn, session->bgpConf.peerAS);
    if (session->tcpConnected)
    {
      // Can happen if it run into a BGP timeout while waiting for Open Response
      shutDownTCPSession(session, true);
    }
  }
  
  // Here stop the session.
  session->run = false;
  return NULL;
}

/**
 * Establish a TCP Session to the peer with the given peer IP. 
 * 
 * @param session the necessary session information.
 * 
 * @return true if a TCP session could be established.
 */
bool establishTCPSession(BGPSession* session)
{
  
  if (session->tcpConnected)
  {
    printf ("Session is already established.\n");
    return false;
  }

  if (!fsmSwitchState(&session->fsm, FSM_STATE_CONNECT))
  {
    printf ("ERROR: Cannot switch to FSM state %u\n", session->fsm.state);
    return false;
  }
  
  if((session->sessionFD = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
  {
    printf("ERROR: Could not create socket \n");
    fsmCanSwitchTo(&session->fsm, FSM_STATE_IDLE);
    return false;
  }
  int conVal = connect(session->sessionFD, 
                       (struct sockaddr *)&(session->bgpConf.peer_addr), 
                       sizeof(session->bgpConf.peer_addr));
  if( conVal < 0)
  {    
    // @TODO: Add V6 Support
    char addrStr[INET_ADDRSTRLEN];
    memset(addrStr, 0, INET_ADDRSTRLEN);
    if (session->bgpConf.peer_addr.sin_family == AF_INET)
    {
      u_int32_t addr  = session->bgpConf.peer_addr.sin_addr.s_addr;
      snprintf(addrStr, INET_ADDRSTRLEN, "%u.%u.%u.%u", 
               (addr & 0xFF),
               ((addr >> 8) & 0xFF),
               ((addr >> 16) & 0xFF),
               ((addr >> 24) & 0xFF)
               );
    }
    else
    {
      snprintf(addrStr, INET_ADDRSTRLEN, "%s", "Add V6 Support");
    }
    int ierrno = errno;
    switch (ierrno)
    {
      case 110:
        printf("ERROR[110]: Connection to peer '%s' timed out!\n", addrStr);
        break;
      case 111:
        printf("ERROR[111]: Connection refused by peer '%s' !\n", addrStr);
        break;
      default:
        printf("ERROR[%i]: Connection to peer '%s' failed (Error: %i (0x%X))\n", 
                ierrno, addrStr, ierrno, ierrno);
    }
    return false;
  }
    
  // Check if the socket is alive
  session->tcpConnected = _isSocketAlive(session, POLL_TIMEOUT_MS, false);
  if (!session->tcpConnected)
  {
    shutDownTCPSession(session, false);
  }
  
  return session->tcpConnected;
}

/**
 * Returns true as long as FSM is in ESTABLISHED or OpenSent state.
 * 
 * @param fsm The final state machine
 * 
 * @return true or false. 
 */
static bool _canReceiveBGPMessage(BGPFinalStateMachine fsm)
{
  return    fsm.state == FSM_STATE_ESTABLISHED 
         || fsm.state == FSM_STATE_OpenSent;
}

/** 
 * Read the next BGP message and writes it into the sessions buffer. This method
 * will only read as long as FSM is in ESTABLISHED or OpenSent mode.
 * 
 * @param session the session to read from.
 * @param timeout timeout in seconds. No timeout if 0;
 * 
 * @return 0 = EOF / timeout, &lt; 0 error, &gt; 0 number bytes read.
 */
int readNextBGPMessage(BGPSession* session, int timeout)
{
  if (session == NULL)
  {
    return -1;
  }
  int totalBytesRead = 0; // contains the accumulative number of bytes read.
  int readBytes = 0; // contains the number of bytes for each read call
  int bytesAvailable = 0; // for polling the socket.
  int maxLen = session->buffSize;
  int hdrSize = sizeof(BGP_MessageHeader);
  u_int16_t length = 0;
  BGP_MessageHeader* hdr = (BGP_MessageHeader*)session->recvBuff;
  // Use a pointer because pread does not work with socket streams. the buffer
  // pointer allows to be moved forward without loosing the real buffer start.
  char* buff = session->recvBuff;
  
  if (timeout == 0)
  {
    timeout = 0x7FFFFFFF; // pretty much forever
  }
  
  if (_canReceiveBGPMessage(session->fsm))
  {
    while (bytesAvailable == 0 && timeout > 0)
    {
      // Poll if data is available on the socket.
      ioctl(session->sessionFD, FIONREAD, &bytesAvailable);
      if (bytesAvailable == 0 && timeout != 0)
      {
        timeout--;
        sleep(SESS_DEV_RCV_SLEEP);
      }
    }
    if (bytesAvailable > 0 && _canReceiveBGPMessage(session->fsm))
    {
      readBytes = read(session->sessionFD, buff, hdrSize);
      totalBytesRead = readBytes;
      if (readBytes != hdrSize)
      {
        hdr->length = 0;
        memset(session->recvBuff, '0', maxLen);
        return readBytes;
      }
      buff += readBytes;

      // now check if the message fits into the buffer - for this don't adjust the
      // length yet, do it later.
      length = ntohs(hdr->length);
      if (length > maxLen)
      {
        // increase the header buffer.
        if (length < BGP_MAX_HDR_SIZE)
        {
          void* new = NULL;
          new = realloc(session->recvBuff, length+1);
          if (new != NULL)
          {
            session->recvBuff = new;
            session->buffSize = length+1;
          }
        }
        else
        {
          printf("BGP header to large %u - Max allowed size id %i\n", 
                 hdr->length, BGP_MAX_HDR_SIZE);
          hdr->length = 0;
          memset(session->recvBuff, '0', maxLen);
          return -1;
        }
      }
      // now adjust the length and subtract the number of already read bytes.
      length -= readBytes;

      bool error = false;
      while (length > 0)
      {
        readBytes = read(session->sessionFD, buff, length);
        if (readBytes > 0)
        {
          buff   += readBytes;
          length -= readBytes;
          totalBytesRead += readBytes;
        }
        else
        {
          // store the error in totalBytesRead
          totalBytesRead = readBytes;
          error = true;
          break;
        }
      }
      if (error)
      {
        // @TODO: Send Notification - maybe count error and don't immediately 
        //        close connection - look into it further.
        printf ("ERROR - close socket - Move to IDLE!");
        session->tcpConnected = false;
        shutDownTCPSession(session, true);
      }
    }
  }
  if (session->fsm.state != FSM_STATE_IDLE && totalBytesRead > 0)
  {
    session->lastReceived = time(0);
  }
  
  return totalBytesRead;
}

/**
 * Check the message header for correctness. If not correct and a notification 
 * needs to be send, it will do so.
 * 
 * @param session The bgp session.
 */
bool checkMessageHeader(BGPSession* session)
{
  BGP_MessageHeader* hdr = (BGP_MessageHeader*)session->recvBuff;
  
  int idx;
  for (idx = 0; idx < BGP_MARKER_SIZE; idx++)
  {
    if (hdr->marker[idx] != 0xff)
    {
      u_int16_t length = ntohs(hdr->length);
      sendNotification(session, BGP_ERR1_MESSAGE_HEADER, BGP_ERR_SUB_UNDEFINED,
                       length, (u_int8_t*)session->recvBuff);
      return false;
    }
  }
  
  return true;
}

/**
 * Process the open message while FSM is in FSM_STATE_OpenSent. This function 
 * checks with the FSM and modifies its state if necessary. It also sends out a
 * notification if needed and closes the TCP connection if required. In case
 * the recvBuff contains a notification message it will shut down the session.
 * (session->run = false)
 * 
 * @param session The session that contains the open message.
 */
void processOpenMessage(BGPSession* session)
{
  BGP_OpenMessage* hdr = (BGP_OpenMessage*)session->recvBuff;
  BGP_NotificationMessage* nhdr = NULL;
  if (hdr->messageHeader.type != BGP_T_OPEN)
  {
    char* type = NULL;
    bool  isERROR = true;
    switch (hdr->messageHeader.type)
    {
      case BGP_T_UPDATE: 
        type = "UPDATE\0"; break;
      case BGP_T_NOTIFICATION: 
        nhdr = (BGP_NotificationMessage*)hdr;
        if (nhdr->error_code != BGP_ERR6_CEASE)
        {
          printf("WARNING: Received NOTIFICATION with other error code than"
                 "cease (%d)!\n", BGP_ERR6_CEASE);
          printBGP_Message((BGP_MessageHeader*)hdr, "Notification Message", 
                            false);
        }
        
        if (!fsmCanSwitchTo(&session->fsm, FSM_STATE_IDLE))
        {
          printf("ERROR: Received NOTIFICATION but FSM cannot switch to IDLE!\n");          
        }
        else
        {
          fsmSwitchState(&session->fsm, FSM_STATE_IDLE);
        }
        // end session here BZ:947!
        session->run = false;
        isERROR = false; // The peer refused the connection.          
        break;
      case BGP_T_KEEPALIVE: 
        type = "KEEPALIVE\0"; break;
      default: 
        type = "UNKNOWN\0";
    }

    if (isERROR)
    {
      printf("ERROR: Open message expected but %s message received! "
              "Abort message processing for open!\n", type);    
      printBGP_Message((BGP_MessageHeader*)hdr, "Received Unexpected Message", 
                       false);
    }
    else
    {
      printf("NOTIFICATION: Peer refused BGP session - Verify no other session" 
             " is active!! -\n");      
    }
    
    // change session and close connection.
    
    return;
  }
  
  if (session->fsm.state != FSM_STATE_OpenSent)
  {
    printf ("ERROR: FSM not in OpenSent - close session and go to IDLE!\n");
    sendNotification(session, BGP_ERR5_FSM, BGP_ERR_SUB_UNDEFINED, 0, NULL);
    return;
  }

  u_int16_t length = ntohs(hdr->messageHeader.length);
  // check the message length
  if (length < BGP_MIN_OPEN_LENGTH)
  {
    printf ("ERROR: Open Messages MUST be at least %u bytes of length!\n", 
            BGP_MIN_OPEN_LENGTH);
    sendNotification(session, BGP_ERR1_MESSAGE_HEADER, BGP_ERR1_SUB_BAD_LENGTH,
                     length, (u_int8_t*)hdr);
    return;
  }
    
  // Check the BGP version  
  if (hdr->version != BGP_VERSION)
  {
    printf ("ERROR: Wrong BGP Version - close session and go to IDLE!\n");
    sendNotification(session, BGP_ERR2_OPEN_MESSAGE, BGP_ERR2_SUB_VERSION, 
                     0, NULL);
    return;
  }

  // Check and adjust the BGP hold time
  u_int16_t peerHoldTime = ntohs(hdr->hold_time);
  if (peerHoldTime < session->bgpConf.holdTime)
  {
    // Re-adjust my hold time
    session->bgpConf.holdTime = peerHoldTime;
  }

  // Get the peer Configuration and capabilities
  BGP_Cap_Conf peerCap;
  memset(&peerCap, 0, sizeof(BGP_Cap_Conf));
  
  u_int32_t peerASN   = ntohs(hdr->my_as);
  u_int8_t  paramLen  = hdr->opt_param_len;
  u_int8_t  bgpsecVer = 0;
  u_int8_t  dir       = 255;
  BGP_Cap_MPNLRI*   mpnlri   = NULL;
  BGP_Cap_AS4*      as4      = NULL;
  BGP_Cap_BGPSEC*   bgpsec   = NULL; 

  char* buff = session->recvBuff + sizeof(BGP_OpenMessage);
  char* hlpPtr = NULL;
  int consumed = 0;
  int pLen = 0; // the length of the individual parameter
  // Go through the all optional parameters
  while (consumed < paramLen)
  {
    BGP_OpenMessage_OptParam* param = (BGP_OpenMessage_OptParam*)buff;
    pLen = param->param_len + sizeof(BGP_OpenMessage_OptParam);
    consumed += pLen;      
    hlpPtr = buff + sizeof(BGP_OpenMessage_OptParam);
    
    if (param->param_type == BGP_T_CAP)
    {
      BGP_Capabilities* cap = (BGP_Capabilities*)hlpPtr;
      // Process the capability
      switch (cap->cap_code)
      {
        case BGP_CAP_T_MPNLRI:
          mpnlri = (BGP_Cap_MPNLRI*)buff;
          switch (ntohs(mpnlri->afi))
          {
            case AFI_V4: 
              peerCap.mpnlri_v4 = true;
              break;
            case AFI_V6:
              peerCap.mpnlri_v6 = true;
              break;
            default:
              printf("WARNING: Unknown MPNLRI AFI Capability %u - Ignore\n", 
                      ntohs(mpnlri->afi));
          }
          break;
        case BGP_CAP_T_AS4:
          as4 = (BGP_Cap_AS4*)buff;
          peerASN = ntohl(as4->myAS);
          peerCap.asn_4byte = true;
          break;
        case BGP_CAP_T_BGPSEC:
          bgpsec    = (BGP_Cap_BGPSEC*)buff;
          bgpsecVer = bgpsec->firstOctet >> 4;
          dir       = (bgpsec->firstOctet >> 3) & 0x01;
          if (bgpsecVer != BGPSEC_VERSION)
          {
            printf ("ERROR: Wrong BGPSEC version %u!\n", bgpsecVer);
            sendNotification(session, BGP_ERR2_OPEN_MESSAGE, 
                             BGP_ERR3_SUB_UNSUPPORTED_BGPSEC_VER, 0, NULL);
            return;
          }
          switch (ntohs(bgpsec->afi))
          {
            case AFI_V4:
              if (dir == BGPSEC_DIR_SND)
              {
                peerCap.bgpsec_snd_v4 = true;
              }
              else
              {
                peerCap.bgpsec_rcv_v4 = true;
              }
              break;
            case AFI_V6:
              if (dir == BGPSEC_DIR_SND)
              {
                peerCap.bgpsec_snd_v6 = true;
              }
              else
              {
                peerCap.bgpsec_rcv_v6 = true;
              }
              break;
            default:
              printf("WARNING: Unknown BGPSEC AFI Capability %u - Ignore", 
                      ntohs(mpnlri->afi));
          }
          break;
        case BGP_CAP_T_RREFRESH:
        case BGP_CAP_T_RREFRESH_PRIV:
          peerCap.route_refresh = true;
          break;
        default:
          printf ("WARNING: Unknown BGP Capability %u - Ignore!\n", 
                  param->param_type);
      }
      buff += pLen;
    }
    else
    {
      // Unsupported optional Parameter
      sendNotification(session, BGP_ERR2_OPEN_MESSAGE, 
                       BGP_ERR2_SUB_UNSUPP_OPT_PARAM, 0, NULL);
      return;
    }
  }
  
  // Now check the peer AS
  if (peerASN != session->bgpConf.peerAS)
  {
    printf ("ERROR: Peer reports AS %u but expected is AS %u!\n",
            peerASN, session->bgpConf.peerAS);
    sendNotification(session, BGP_ERR2_OPEN_MESSAGE, BGP_ERR2_SUB_BAD_PEERAS,
                     0, NULL);
    return;
  }
    
  // Now check the required Capabilities
  
  // If "we" do 4-byte ASN the peer MUST do so too.
  if (session->bgpConf.capConf.asn_4byte && !peerCap.asn_4byte)
  {
    printf ("ERROR: Peer does not support 4-byte ASN\n");
    sendNotification(session, BGP_ERR2_OPEN_MESSAGE, BGP_ERR_SUB_UNDEFINED,
                     0, NULL);
    return;    
  }

  // If "we" send V4 BGPSEC the peer MUST be able to receive it  
  if (session->bgpConf.capConf.bgpsec_snd_v4 && !peerCap.bgpsec_rcv_v4)
  {
    printf ("ERROR: Peer does not support BGPSEC for IPv4\n");
    sendNotification(session, BGP_ERR2_OPEN_MESSAGE, BGP_ERR_SUB_UNDEFINED,
                     0, NULL);
    return;    
  }
  
  // If "we" send V6 BGPSEC the peer MUST be able to receive it  
  if (session->bgpConf.capConf.bgpsec_snd_v6 && !peerCap.bgpsec_rcv_v6)
  {
    printf ("ERROR: Peer does not support BGPSEC for IPv6\n");
    sendNotification(session, BGP_ERR2_OPEN_MESSAGE, BGP_ERR_SUB_UNDEFINED,
                     0, NULL);
    return;    
  }
  
  // If "we" support V4 MPNLRI the peer MUST do so too
  if (session->bgpConf.capConf.mpnlri_v4 && !peerCap.mpnlri_v4)
  {
    printf ("ERROR: Peer does not support MPNLRI for IPv4\n");
    sendNotification(session, BGP_ERR2_OPEN_MESSAGE, BGP_ERR_SUB_UNDEFINED,
                     0, NULL);
    return;    
  }
  
  // If "we" support V6 MPNLRI the peer MUST do so too
  if (session->bgpConf.capConf.mpnlri_v6 && !peerCap.mpnlri_v6)
  {
    printf ("ERROR: Peer does not support MPNLRI for IPv6\n");
    sendNotification(session, BGP_ERR2_OPEN_MESSAGE, BGP_ERR_SUB_UNDEFINED,
                     0, NULL);
    return;    
  }  
  
  // OK, we reached here, change FSM
  if (!fsmSwitchState(&session->fsm, FSM_STATE_OpenConfirm))
  {
    printf("ERROR: Could not update FSM!\n");
    sendNotification(session, BGP_ERR5_FSM, BGP_ERR_SUB_UNDEFINED, 0, NULL);
    return;
  }
  
  // clean the buffer again
  memset(session->recvBuff, 0, ntohs(hdr->messageHeader.length));
}

/**
 * Process the provided message.
 * 
 * @param session the bgpsession that received the packet. 
 */
static void _processPacket(void* self)
{
  BGPSession* session = (BGPSession*)self;
  BGP_MessageHeader* hdr = (BGP_MessageHeader*)session->recvBuff;
  u_int16_t length = ntohs(hdr->length);
  if (length < sizeof(BGP_MessageHeader)) // 19
  {
    printf("ERROR: Received message with invalid message header!\n");
    sendNotification(session, BGP_ERR1_MESSAGE_HEADER, BGP_ERR1_SUB_BAD_LENGTH,
                     0, NULL);
    return;
  }
  int idx = 0;
  while (idx < BGP_MARKER_SIZE)
  {
    if (hdr->marker[idx++] != 0xFF)
    {
      // @TODO: Check RFC again and see the correct subcode
      sendNotification(session, BGP_ERR1_MESSAGE_HEADER, BGP_ERR1_SUB_NOT_SYNC,
                       0, NULL);
      return;
    }
  }
          
  if (checkMessageHeader(session))
  {  
    switch (hdr->type)
    {
      case BGP_T_OPEN:
        printf("ERROR: Received unexpected Open message!\n");
        if (session->bgpConf.printOnReceive[PRNT_MSG_OPEN])
        {
          printBGP_Message((BGP_MessageHeader*)hdr, 
                           "Received Open Message", false);
        }
        sendNotification(session, BGP_ERR5_FSM, BGP_ERR_SUB_UNDEFINED, 
                         ntohs(hdr->length), (u_int8_t*)session->recvBuff);
        break;
      case BGP_T_KEEPALIVE:
        if (session->bgpConf.printOnReceive[PRNT_MSG_KEEPALIVE])
        {
          printBGP_Message((BGP_MessageHeader*)hdr, 
                           "Received KeepAlive Message", false);
        }
        if (length != sizeof(BGP_KeepAliveMessage))
        {
          sendNotification(session, BGP_ERR1_MESSAGE_HEADER, 
                           BGP_ERR1_SUB_BAD_LENGTH, ntohs(hdr->length), 
                           (u_int8_t*)session->recvBuff);        
        }
        session->lastReceived = time(0);
        break;
      case BGP_T_NOTIFICATION:        
        session->fsm.state = FSM_STATE_IDLE;
        if (session->bgpConf.printOnReceive[PRNT_MSG_NOTIFICATION])
        {
          printBGP_Message((BGP_MessageHeader*)hdr, 
                           "Received Notification Message", false);
        }
        if (session->sessHoldTimerSem != NULL)
        {
          // Notify the hold timer
          sem_post(session->sessHoldTimerSem);
        }
        //shutDownTCPSession(session);
        break;
      case BGP_T_UPDATE:
        session->lastReceived = time(0);
        if (session->bgpConf.printOnReceive[PRNT_MSG_UPDATE])
        {
          printBGP_Message((BGP_MessageHeader*)hdr, 
                           "Received Update Message", false);
        }
        break;
      default:
        printf("ERROR: Received unknown message[%u]!\n", hdr->type);
        sendNotification(session, BGP_ERR1_MESSAGE_HEADER, BGP_ERR1_SUB_BAD_TYPE, 
                         ntohs(hdr->length), (u_int8_t*)session->recvBuff);
        break;
    }
  }
}

/**
 * Finally writes the data, this function will take care of buffering in the
 * future. This method also will set the lastSent time.
 * 
 * @param session the session where to send the data
 * @param data the data to be send
 * @param size the size where to send the data from.
 * 
 * @return the number of bytes send. 
 */
static int _writeData(BGPSession* session, u_int8_t* data, int size)
{
  int written = write(session->sessionFD, data, size);
  session->lastSent = time(0);
  return written;
}


/**
 * The FSM MUST be in FSM_STATE_OpenSent to be able to send the open message.
 * 
 * @param session the session information
 * 
 * @return true if the OpenMessage could be sent.
 */
bool sendOpenMessage(BGPSession* session)
{
  if (!_isSocketAlive(session, POLL_TIMEOUT_MS, false))
  {
    // The file descriptor is broken, don't attempt to send.
    if (fsmCanSwitchTo(&session->fsm, FSM_STATE_IDLE))
    {
      fsmSwitchState(&session->fsm, FSM_STATE_IDLE);
    }
    printf ("ERROR: Cannot send Open, socket is broken!\n");
    return false;
  }
  
  if (session->fsm.state != FSM_STATE_OpenSent)
  {
    printf ("FSM is not in OpenSent state!\n");
    return false;
  }
  unsigned char sendBuff[SESS_MIN_SEND_BUFF];
  memset(sendBuff, 0, SESS_MIN_SEND_BUFF);
  int size = createOpenMessage(sendBuff, sizeof(sendBuff), &(session->bgpConf));
  if (size < 0)
  {
    // @TODO: resize the sending buffer
    printf ("%i bytes missing!", size * (-1));
    return false;
  }
  int written = 0;
  if (size > 0 && size <= sizeof(sendBuff))
  {
    written = _writeData(session, sendBuff, size);
    if (session->bgpConf.printOnSend[PRNT_MSG_OPEN])
    {
      printBGP_Message((BGP_MessageHeader*)sendBuff, 
                       "Send Open Message", false);
    }
  }
  
  return written == size;
}

/**
 * Send a keepalive to the peer. The FSM must be in ESTABLISHED
 * 
 * @param session the session where to send to
 * 
 * @return true if the mesage could be sent otherwise false.
 */
bool sendKeepAlive(BGPSession* session)
{
  if (!_isSocketAlive(session, POLL_TIMEOUT_MS, false))
  {
    // The file descriptor is broken, don't attempt to send.
    if (fsmCanSwitchTo(&session->fsm, FSM_STATE_IDLE))
    {
      fsmSwitchState(&session->fsm, FSM_STATE_IDLE);
    }
    printf ("ERROR: Cannot send KeepAlive, socket is broken!\n");
    return false;
  }
  
  if (session->fsm.state != FSM_STATE_ESTABLISHED)
  {
    printf ("FSM is not in ESTABLISHED state!\n");
    return false;
  }

  unsigned char sendBuff[SESS_MIN_SEND_BUFF];
  memset(sendBuff, 0, SESS_MIN_SEND_BUFF);
  int size = createKeepAliveMessge(sendBuff, sizeof(sendBuff));
  if (size < 0)
  {
    // @TODO: resize the sending buffer
    printf ("%i bytes missing!", size * (-1));
    return false;
  }
  int written = 0;
  if (size > 0 && size <= sizeof(sendBuff))
  {
    written = _writeData(session, sendBuff, size);
    if (session->bgpConf.printOnSend[PRNT_MSG_KEEPALIVE])
    {
      printBGP_Message((BGP_MessageHeader*)sendBuff, 
                       "Send KeepAlive Message", false);
    }
  }
  
  return (written == size);
}

/**
 * Send a notification to the peer, closes the connection and moved the
 * FSM to IDLE
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
                      u_int16_t dataLength, u_int8_t* data)
{
  if (!_isSocketAlive(session, POLL_TIMEOUT_MS, false))
  {
    // The file descriptor is broken, don't attempt to send.
    if (fsmCanSwitchTo(&session->fsm, FSM_STATE_IDLE))
    {
      fsmSwitchState(&session->fsm, FSM_STATE_IDLE);
    }
    printf ("ERROR: Cannot send Notification, socket is broken!\n");
    return false;
  }
  
  unsigned char sendBuff[SESS_MIN_SEND_BUFF];
  memset(sendBuff, 0, SESS_MIN_SEND_BUFF);
  int size = createNotificationMessage(sendBuff, sizeof(sendBuff), error_code,
                                       subcode, dataLength, data);
  if (size < 0)
  {
    // @TODO: resize the sending buffer
    printf ("%i bytes missing!", size * (-1));
    return false;
  }
  int written = 0;
  if (size > 0 && size <= sizeof(sendBuff))
  {
    written = _writeData(session, sendBuff, size);
    if (session->bgpConf.printOnSend[PRNT_MSG_NOTIFICATION])
    {
      printBGP_Message((BGP_MessageHeader*)sendBuff, 
                       "Send Notification Message", false);
    }
  }
  
  bool retVal = written == size;
  if (retVal)
  {
    //session->shutdownSess(session);
    if (!fsmSwitchState(&session->fsm, FSM_STATE_IDLE))
    {
      printf("ERROR: Cannot move FSM to IDLE state!");
      retVal = session->fsm.state == FSM_STATE_IDLE;
      // @TODO: Throw an error, this is definitely a BUG
    }
  } 
  return retVal;
}

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
bool sendUpdate(BGPSession* session, BGP_UpdateMessage_1* update)
{
  if (session->fsm.state != FSM_STATE_ESTABLISHED)
  {
    printf ("NOTICE: Cannot send Update, FSM is not in ESTABLISHED state!\n");
    return false;
  }
  
  if (!_isSocketAlive(session, POLL_TIMEOUT_MS, false))
  {
    // To determine if this is an error condition or if the session is in limbo
    // check the socket again.
    if (_isSocketAlive(session, POLL_TIMEOUT_MS, true)) // check for data
    {
      printf ("WARNING: Cannot send Update, socket is in read only!\n");    
    }
    else
    {
      printf ("ERROR: Cannot send Update, socket is broken - move to IDLE!\n");
      if (fsmCanSwitchTo(&session->fsm, FSM_STATE_IDLE))
      {
        fsmSwitchState(&session->fsm, FSM_STATE_IDLE);
      }
      else
      {
        printf ("ERROR: Cannot switch to IDLE!\n");        
      }
    }
    return false;
  }
    
  bool retVal = false;
  int written = 0;
  u_int16_t size = ntohs(update->messageHeader.length);
  written = _writeData(session, (u_int8_t*)update, size);
  if (session->bgpConf.printOnSend[PRNT_MSG_UPDATE])
  {
    printUpdateData((BGP_UpdateMessage_1*)update);
  }
  
  retVal = (written == size);
  
  if (retVal)
  {
    session->lastSentUpdate = session->lastSent;
  }
  
  return retVal;
}

