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
 * @version 0.2.0.7
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.0.7 - 2017/04/28 - oborchert
 *            * BZ1153: Updated error that GEN-C generated updates could not be 
 *              used by peer, missing next hop information.
 *            * Modified create Session by removing configuration setup that 
 *              belongs into the configuration.
 *          - 2017/03/23 - oborchert
 *            * Added CREATE_TESTVECTOR
 *          - 2017/03/20 - oborchert
 *            * BZ1043: Added flow control to socket handling.
 *          - 2017/03/10 - oborchert
 *            * Fixed incorrect unsupported capability processing.
 *          - 2017/03/09 - oborchert
 *            * BZ1134: Moved printing of received bgp messages into 
 *              readNextBGPMessage to have it more centralized and to capture
 *              all received messages.
 *            * BZ1133: Renamed function checkMessageHeader into 
 *              _checkMessageHeader and declared visibility to static. 
 *              It is only called from within readNextBGPMessage.
 *          - 2017/02/14 - oborchert (branch 2017/02/07)
 *            * Added IPv6 processing
 *  0.2.0.6 - 2017/02/15 - oborchert
 *            * Added switch to force sending extended messages regardless if
 *              capability is negotiated. This is a TEST setting only.
 *          - 2017/02/14 - oborchert
 *            * BZ1111: Added switch for liberal extended message processing.
 *            * BZ1110: Added check for message size on receive.
 *  0.2.0.5 - 2017/02/01 - oborchert
 *            * Moved the capabilities configuration in the session creation.
 *            * Added more details explanation if an update could not be send 
 *              due to message size. BZ1100
 *          - 2017/01/31 - oborchert
 *            * Added capabilities configuration.
 *          - 2017/01/21 - oborchert
 *            * Added extended message size capability
 *            * Modified Capability check during open receive.
 *          - 2017/01/03 - oborchert
 *            * Added transfer of new algo parameter from configuration into 
 *              session.
 *          - 2016/10/24 - oborchert
 *            * Previous change introduced an incompatibility with quagga which
 *              is fixed now.
 *          - 2016/10/21 - oborchert
 *            * Fixed formating of error / warning output.
 *            * Fixed parsing of capabilities to allow multiple capabilities 
 *              being bundled within a single optional parameter. BZ1026
 *          - 2016/10/19 - oborchert
 *            * Removed 4-byte ASN capability requirement from peer.
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
#include "printer/BGPPrinterUtil.h"

#define POLL_TIMEOUT_MS 100

#define SOCKET_ERR      -1
#define SOCKET_TIMEOUT   0
#define SOCKET_ALIVE     1

static void _processPacket(void* session);
static bool _checkMessageHeader(BGPSession* session);

/**
 * Allocates the memory for the session and configures soem of its values.
 * the configured values are he minimal necessary values to be able to establish
 * a BGP session.
 * 
 * @param buffSize The internal buffer size.
 * @param config   The session configuration 
 * @param process  The method to process received packages.
 * 
 * @return the allocated memory of the session or NULL if the session could not
 *         be generated
 */
BGPSession* createBGPSession(int buffSize, BGP_SessionConf* config,
                             process_packet process)
{
  BGPSession*      session    = NULL;
  BGP_SessionConf* sessConfig = NULL;
  AlgoParam*       sessAlgo   = NULL;
  AlgoParam*       configAlgo = NULL;
  
  if (config->peer_addr.sin_port > 0)
  {
    session = malloc(sizeof(BGPSession));
    memset(session, 0, sizeof(BGPSession));

    sessConfig = &session->bgpConf;
    
    sessConfig->asn                   = config->asn;
    sessConfig->bgpIdentifier         = config->bgpIdentifier;
    sessConfig->holdTime              = config->holdTime;
    sessConfig->disconnectTime        = config->disconnectTime;
    sessConfig->useMPNLRI             = config->useMPNLRI;
    sessConfig->capConf.extMsgSupp    = config->capConf.extMsgSupp;
    sessConfig->capConf.extMsgLiberal = config->capConf.extMsgLiberal;
    sessConfig->capConf.extMsgForce   = config->capConf.extMsgForce;
    int idx;
    for (idx = 0; idx < PRNT_MSG_COUNT; idx++)
    {
      sessConfig->printOnReceive[idx] = config->printOnReceive[idx];
      sessConfig->printOnSend[idx]    = config->printOnSend[idx];
    }
    
    memcpy(&sessConfig->nextHopV4, &config->nextHopV4, sizeof(struct sockaddr_in));    
    memcpy(&sessConfig->nextHopV6, &config->nextHopV6, sizeof(struct sockaddr_in6));
    
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
    sessAlgo->sigGenMode     = configAlgo->sigGenMode;
    configAlgo = configAlgo->next;
    if (configAlgo != NULL)
    {
      sessAlgo = malloc(sizeof(AlgoParam));
      memset(sessAlgo, 0, sizeof(AlgoParam));
    }
    
    // Now set the capabilities for this session
    // Configure BGP capabilities - set all true except route refresh
    memset (&(session->bgpConf.capConf), 1, sizeof(BGP_Cap_Conf));
    sessConfig->capConf.asn_4byte     = config->capConf.asn_4byte;
    sessConfig->capConf.bgpsec_rcv_v4 = config->capConf.bgpsec_rcv_v4;
    sessConfig->capConf.bgpsec_rcv_v6 = config->capConf.bgpsec_rcv_v6;
    sessConfig->capConf.bgpsec_snd_v4 = config->capConf.bgpsec_snd_v4;
    sessConfig->capConf.bgpsec_snd_v6 = config->capConf.bgpsec_snd_v6;
    sessConfig->capConf.extMsgSupp    = config->capConf.extMsgSupp;
    sessConfig->capConf.extMsgLiberal = config->capConf.extMsgLiberal;
    sessConfig->capConf.extMsgForce   = config->capConf.extMsgForce;
    sessConfig->capConf.mpnlri_v4     = config->capConf.mpnlri_v4;
    sessConfig->capConf.mpnlri_v6     = config->capConf.mpnlri_v6;
    sessConfig->capConf.route_refresh = config->capConf.route_refresh;  
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
  printf("INFO: Shutdown TCP session\n");
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
 * @return SOCKET_ALIVE if it is alive, SOCKET_ERROR on an error, 
 *         and SOCKET_TIMEOUT on a timeout
 */
static int _isSocketAlive(BGPSession* session, int timeout, bool readOnly)
{
  bool retVal = SOCKET_ALIVE;
  
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
    { // REQUEST FOR SENDING TOO
      // Return error or timeout.
      retVal = (pollVal == 0) ? SOCKET_TIMEOUT : SOCKET_ERR;
      //retVal = (pfd.revents & errmask) == 0;
    }
    else
    { // REQUEST FOR READ ONLY
      // If still data is waiting on the in buffer anounce socekt to be ready.
      retVal = ((pfd.revents & POLLIN) != 0) ? SOCKET_ALIVE : SOCKET_ERR;
    }
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
  int socketState = SOCKET_ALIVE;
  int attempt = 1;

  while (session->fsm.state == FSM_STATE_ESTABLISHED) 
  {
    switch (_isSocketAlive(session, POLL_TIMEOUT_MS, true))
    {
      case SOCKET_ERR:
        printf("ERROR: Socket to AS %u broke!\n", session->bgpConf.peerAS);
        fsmSwitchState(&session->fsm, FSM_STATE_IDLE);
        break;
        
      case SOCKET_TIMEOUT:
        printf("WARNING: Socket to AS %u timed out (%u. attempt)!\n", 
               session->bgpConf.peerAS, attempt);
        if (attempt++ <= SESS_FLOW_CONTROL_REPEAT)
        {
          sleep(SESS_FLOW_CONTROL_SLEEP);
          break;
        }
        fsmSwitchState(&session->fsm, FSM_STATE_IDLE);
        break;
        
      case SOCKET_ALIVE:
        attempt = 1; // reset the attempt pointer.
        bytesReady = 0;
        ioctl(session->sessionFD, FIONREAD, &bytesReady);
        if (bytesReady > 0)
        {
          bytesRead = readNextBGPMessage(session, SESS_DEF_RCV_TIMEOUT);
          switch (bytesRead)
          {
            case 0:
              // EOF, nothing came in.
              break;
            case -1:
              // Error
              // Session is not established or closed.
              break;
            case -2:
              // Larger 64K Notification already send and session is closed
              break;
            default:
              // Check if message is of acceptable length
              if (bytesRead < BGP_MAX_MESSAGE_SIZE) // 4K boundary
              {
                // This is most likely the case
                _processPacket(session);
              }
              else
              {
                if (session->bgpConf.capConf.extMsgLiberal 
                    || (session->bgpConf.capConf.extMsgSupp 
                        && session->bgpConf.peerCap.extMsgSupp))
                {
                  _processPacket(session);              
                }
                else
                {
                  // Send notification of invalid message size
                  sendNotification(session, BGP_ERR1_MESSAGE_HEADER, 
                                   BGP_ERR1_SUB_BAD_LENGTH, 0, NULL, 
                                   SESS_FLOW_CONTROL_REPEAT);
                }
              }
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
        break;
        
      default:
        printf("ERROR: Socket to AS %u in undefined state!\n", 
               session->bgpConf.peerAS);
        fsmSwitchState(&session->fsm, FSM_STATE_IDLE);
        break;
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
                             BGP_ERR6_SUB_PEER_DE_CONFIGURED, 0, NULL, 
                             SESS_FLOW_CONTROL_REPEAT);
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
                                 BGP_ERR6_SUB_PEER_DE_CONFIGURED, 0, NULL, 
                                 SESS_FLOW_CONTROL_REPEAT);        
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
      sendNotification(session, BGP_ERR5_FSM, BGP_ERR_SUB_UNDEFINED, 0, NULL,
                       SESS_FLOW_CONTROL_REPEAT);
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
    
  // Check if the socket is alive (don't accept error or timeout here)
  session->tcpConnected = (_isSocketAlive(session, POLL_TIMEOUT_MS, false) 
                           == SOCKET_ALIVE);
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
 * will only read as long as FSM is in ESTABLISHED or OpenSent mode. This 
 * message ONLY returns an error if the socket was broken.
 * This message performs two checks on each received BGP message, 
 * (1) it does not read messages larger than 64 K (ext message maximum)
 * (2) after the message is read it performs a basic check on the message 
 *     header only by calling checkMessageHeader prior loading the remaining 
 *     message.
 * @param session the session to read from.
 * @param timeout timeout in seconds. No timeout if 0;
 * 
 * @return 0 = EOF / timeout, &gt; 0 number bytes read, -1 Error (no session), 
 *         -2 Message to large
 * 
 * @see checkMessageHEader
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
        // This might actually result in a FSM event code.
        hdr->length = 0;
        memset(session->recvBuff, '0', maxLen);
        return readBytes;
      }
      buff += readBytes;

      // Check the message header
      if (!_checkMessageHeader(session))
      {
        // Message header error
        return -2;
      }
      
      // now check if the message fits into the buffer - for this don't adjust the
      // length yet, do it later.
      length = ntohs(hdr->length);
      // maxLen here is the total size of the read buffer.
      if (length > maxLen)
      {
        void* new = NULL;
        new = realloc(session->recvBuff, length+1);
        if (new != NULL)
        {
          session->recvBuff = new;
          session->buffSize = length+1;
        }
      }
      // now adjust the length and subtract the number of already read bytes.
      length -= readBytes;

      // continue reading until the complete message is read.
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
          // error reading
          // @TODO: Send Notification - maybe count error and don't immediately 
          //        close connection - look into it further.
          printf ("ERROR[%i] - close socket - Move to IDLE!", readBytes);
          session->tcpConnected = false;
          shutDownTCPSession(session, true);
          return -1;
        }
      }
      
      // Now determine if we print on receipt
      bool prnHdr = false;
      switch (hdr->type)
      {
        case BGP_T_KEEPALIVE:
          prnHdr = session->bgpConf.printOnReceive[PRNT_MSG_KEEPALIVE]; break;
        case BGP_T_UPDATE:
          prnHdr = session->bgpConf.printOnReceive[PRNT_MSG_UPDATE]; break;
        case BGP_T_OPEN:
          prnHdr = session->bgpConf.printOnReceive[PRNT_MSG_OPEN]; break;
        case BGP_T_NOTIFICATION:
          prnHdr = session->bgpConf.printOnReceive[PRNT_MSG_NOTIFICATION]; break;
        default:
          prnHdr = session->bgpConf.printOnReceive[PRNT_MSG_UNKNOWN]; break;
      }
      if (prnHdr)
      {
        printf ("Received ");
        printBGP_Message(hdr);
      }
    }    
    // Moved inside the if section - count the message only if the FSM is
    // ready to receive messages
    if (session->fsm.state != FSM_STATE_IDLE && totalBytesRead > 0)
    {
      session->lastReceived = time(0);
    }
  }
  else
  {
    printf ("WARNING - FSM not ready to receive messages!\n");   
  }
  
  return totalBytesRead;
}

/**
 * Check the BGP message header for correctness. If not correct and a 
 * notification message needs to be send, it will do so.
 * 
 * This function will perform the extended message processing on the receiver
 * side.
 * 
 * @param session The bgp session.
 * 
 * @return true if the message header is correct, otherwise false. If false a 
 *              notification with the appropriate error was send.
 */
static bool _checkMessageHeader(BGPSession* session)
{
  BGP_MessageHeader* hdr = (BGP_MessageHeader*)session->recvBuff;
  u_int16_t length = ntohs(hdr->length);
 
  int idx;
  for (idx = 0; idx < BGP_MARKER_SIZE; idx++)
  {
    if (hdr->marker[idx] != 0xff)
    {
      sendNotification(session, BGP_ERR1_MESSAGE_HEADER, BGP_ERR_SUB_UNDEFINED,
                       length, (u_int8_t*)session->recvBuff,
                       SESS_FLOW_CONTROL_REPEAT);
      return false;
    }
  }
  
  // Moved processing here to facilitate the length processing
  bool allowExtendedMsg = false;
  switch (hdr->type)
  {
    case BGP_T_UPDATE:
      allowExtendedMsg = session->bgpConf.capConf.extMsgSupp 
                         || session->bgpConf.capConf.extMsgLiberal;
      break;
    case BGP_T_OPEN:
    case BGP_T_KEEPALIVE:
    case BGP_T_NOTIFICATION:
      break;
    default:
      sendNotification(session, BGP_ERR1_MESSAGE_HEADER, BGP_ERR1_SUB_BAD_TYPE,
                       length, (u_int8_t*)session->recvBuff, 
                       SESS_FLOW_CONTROL_REPEAT);
      return false;
      break;
  }

  if (length > BGP_MAX_MESSAGE_SIZE)
  {
    // We received an extended message
    if ( (!allowExtendedMsg) || (length > BGP_EXTMAX_MESSAGE_SIZE))
    {
      sendNotification(session, BGP_ERR1_MESSAGE_HEADER, BGP_ERR1_SUB_BAD_LENGTH,
                       length, (u_int8_t*)session->recvBuff, 
                       SESS_FLOW_CONTROL_REPEAT);
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
          // Only print if not already printed
          if (!session->bgpConf.printOnReceive[PRNT_MSG_NOTIFICATION])
          {
            printBGP_Message((BGP_MessageHeader*)hdr);
          }
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
      printf("ERROR: Open message expected but '%s' [%i] message received! "
              "Abort message processing for open!\n", 
              type, hdr->messageHeader.type);    
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
    sendNotification(session, BGP_ERR5_FSM, BGP_ERR_SUB_UNDEFINED, 0, NULL, 
                     SESS_FLOW_CONTROL_REPEAT);
    return;
  }

  u_int16_t length = ntohs(hdr->messageHeader.length);
  // check the message length
  if (length < BGP_MIN_OPEN_LENGTH)
  {
    printf ("ERROR: Open Messages MUST be at least %u bytes of length!\n", 
            BGP_MIN_OPEN_LENGTH);
    sendNotification(session, BGP_ERR1_MESSAGE_HEADER, BGP_ERR1_SUB_BAD_LENGTH,
                     length, (u_int8_t*)hdr, SESS_FLOW_CONTROL_REPEAT);
    return;
  }
    
  // Check the BGP version  
  if (hdr->version != BGP_VERSION)
  {
    printf ("ERROR: Wrong BGP Version - close session and go to IDLE!\n");
    sendNotification(session, BGP_ERR2_OPEN_MESSAGE, BGP_ERR2_SUB_VERSION, 
                     0, NULL, SESS_FLOW_CONTROL_REPEAT);
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
  BGP_Cap_Conf* peerCap = &session->bgpConf.peerCap;
  // Reset the peer capabilities
  memset(peerCap, 0, sizeof(BGP_Cap_Conf));
  
  u_int32_t peerASN   = ntohs(hdr->my_as);
  u_int8_t  bgpsecVer = 0;
  u_int8_t  dir       = 255;
  BGP_Cap_MPNLRI*   mpnlri   = NULL;
  BGP_Cap_AS4*      as4      = NULL;
  BGP_Cap_BGPSEC*   bgpsec   = NULL; 

  char* buff  = session->recvBuff + sizeof(BGP_OpenMessage);
  int capSize = 0;
  // The number bytes consumed of the Optional Parameter
  int bytesRead = 0;
  
  // Now loop through all optional parameters.
  while (bytesRead < hdr->opt_param_len)
  {
    // Now get the parameter
    BGP_OpenMessage_OptParam* param = (BGP_OpenMessage_OptParam*)buff;
    bytesRead += sizeof(BGP_OpenMessage_OptParam); // processed parameter header
    // Move buffer to Parameter Value
    buff      += sizeof(BGP_OpenMessage_OptParam);
    
    // Number of parameter value bytes processed
    int paramProcessed = 0;
    BGP_Capabilities* cap = NULL;            
    while (paramProcessed < param->param_len)
    {
      // Now look into the type - For now we only accept capability parameters.
      switch (param->param_type)
      {
        case  BGP_T_CAP:
          // Loop through multiple capabilities all written in the payload of
          // this parameter. (BIRD is doing this kind of capability packing.)
          cap             = (BGP_Capabilities*)buff;
          capSize         = sizeof(BGP_Capabilities) + cap->cap_length;
          paramProcessed += capSize;
          bytesRead      += capSize;
          // Move the buffer over over this capability.
          buff           += capSize;        
          // Process the capability
          switch (cap->cap_code)
          {
            case BGP_CAP_T_MPNLRI:
              mpnlri = (BGP_Cap_MPNLRI*)cap;
              switch (ntohs(mpnlri->afi))
              {
                case AFI_V4: 
                  peerCap->mpnlri_v4 = true;
                  break;
                case AFI_V6:
                  peerCap->mpnlri_v6 = true;
                  break;
                default:
                  printf("WARNING: Unknown MPNLRI AFI Capability %u - Ignore\n", 
                          ntohs(mpnlri->afi));
              }
              break;
            case BGP_CAP_T_AS4:
              as4 = (BGP_Cap_AS4*)cap;
              peerASN = ntohl(as4->myAS);
              peerCap->asn_4byte = true;
              break;
            case BGP_CAP_T_BGPSEC:
              bgpsec    = (BGP_Cap_BGPSEC*)cap;
              bgpsecVer = bgpsec->firstOctet >> 4;
              dir       = (bgpsec->firstOctet >> 3) & 0x01;
              if (bgpsecVer != BGPSEC_VERSION)
              {
                printf ("ERROR: Wrong BGPSEC version %u!\n", bgpsecVer);
                sendNotification(session, BGP_ERR2_OPEN_MESSAGE, 
                                  BGP_ERR2_SUB_UNSUPPORTED_BGPSEC_VER, 0, NULL,
                                  SESS_FLOW_CONTROL_REPEAT);
                return;
              }
              switch (ntohs(bgpsec->afi))
              {
                case AFI_V4:
                  if (dir == BGPSEC_DIR_SND)
                  {
                    peerCap->bgpsec_snd_v4 = true;
                  }
                  else
                  {
                    peerCap->bgpsec_rcv_v4 = true;
                  }
                  break;
                case AFI_V6:
                  if (dir == BGPSEC_DIR_SND)
                  {
                    peerCap->bgpsec_snd_v6 = true;
                  }
                  else
                  {
                    peerCap->bgpsec_rcv_v6 = true;
                  }
                  break;
                default:
                  printf("WARNING: Unknown BGPSEC AFI Capability %u - Ignore\n", 
                          ntohs(mpnlri->afi));
              }
              break;
            case BGP_CAP_T_RREFRESH:
            case BGP_CAP_T_RREFRESH_PRIV:
              peerCap->route_refresh = true;
              break;
            case BGP_CAP_T_EXT_MSG_SUPPORT:
              peerCap->extMsgSupp = true;
              break;
            case BGP_CAP_T_GRACE_RESTART:
            case BGP_CAP_T_OUT_FLTR:
            case BGP_CAP_T_MULTI_ROUTES:
            case BGP_CAP_T_EXT_NEXTHOPENC:
            case BGP_CAP_T_DEPRECATED:
            case BGP_CAP_T_SUPP_DYNCAP:
            case BGP_CAP_T_MULTI_SESS:
            case BGP_CAP_T_ADD_PATH:
            case BGP_CAP_T_ENHANCED_RR:
            case BGP_CAP_T_LLGR:
            case BGP_CAP_T_FQDN:
            default:
              printf ("WARNING: Unsupported BGP Capability %u - Ignore!\n", 
                      cap->cap_code);
          }
          break;
          
        default:
          // For parameters other than CAPABILITIES
          // Unsupported optional Parameter
          printf ("WARNING: Unsupported parameter[%u]!\n", param->param_type);
          sendNotification(session, BGP_ERR2_OPEN_MESSAGE, 
                           BGP_ERR2_SUB_UNSUPP_OPT_PARAM, 0, NULL,
                           SESS_FLOW_CONTROL_REPEAT);
          return;        
          break;
      }
    }
  }
  
  // Now check the peer AS
  if (peerASN != session->bgpConf.peerAS)
  {
    printf ("ERROR: Peer reports AS %u but expected is AS %u!\n",
            peerASN, session->bgpConf.peerAS);
    sendNotification(session, BGP_ERR2_OPEN_MESSAGE, BGP_ERR2_SUB_BAD_PEERAS,
                     0, NULL, SESS_FLOW_CONTROL_REPEAT);
    return;
  }
    
  // Now check the peer Capabilities
  // Removed this check, peers that do not have the ASN4 capability will use
  // the 4 byte ASN simply as AS 23456 BZ 1026/1027
  // If "we" do 4-byte ASN the peer MUST do so too.
  //if (session->bgpConf.capConf.asn_4byte && !peerCap->asn_4byte)
  //{
  //  printf ("ERROR: Peer does not support 4-byte ASN\n");
  //  sendNotification(session, BGP_ERR2_OPEN_MESSAGE, BGP_ERR_SUB_UNDEFINED,
  //                   0, NULL);
  //  return;    
  //}
  
  // This specifies the required capabilities
  bool mp_reach_nlri_ipv4_available = true;
  bool mp_reach_nlri_ipv6_available = true;
  
  // 1st. Check MPNLRI capability for peer where required
  // Verify that the peer can to mpnlri V4 if it can receive or send bgpsec V4
  if (   (peerCap->bgpsec_rcv_v4 || peerCap->bgpsec_snd_v4)
      && !peerCap->mpnlri_v4)
  {
    mp_reach_nlri_ipv4_available = false;
    printf ("ERROR: Peer does not support MPNLRI for IPv4\n");
  }

  if (   (peerCap->bgpsec_rcv_v6 || peerCap->bgpsec_snd_v6)
      && !peerCap->mpnlri_v6)
  {
    mp_reach_nlri_ipv6_available = false;
    printf ("ERROR: Peer does not support MPNLRI for IPv6\n");
  }
    
  // OK, we reached here, change FSM
  if (!fsmSwitchState(&session->fsm, FSM_STATE_OpenConfirm))
  {
    printf("ERROR: Could not update FSM!\n");
    sendNotification(session, BGP_ERR5_FSM, BGP_ERR_SUB_UNDEFINED, 0, NULL, 
                     SESS_FLOW_CONTROL_REPEAT);
    return;
  }
  
  if (!(mp_reach_nlri_ipv4_available & mp_reach_nlri_ipv6_available))
  {
    // one or both of the required MP_REACH_NLRI is missing.
    int multiplier = 0;
    if (!mp_reach_nlri_ipv4_available) multiplier++;
    if (!mp_reach_nlri_ipv6_available) multiplier++;
    int size = sizeof(BGP_Cap_MPNLRI) * multiplier;
    u_int8_t* data = malloc(size);
    memset (data, 0, size);
    
    BGP_Cap_MPNLRI* mpData = (BGP_Cap_MPNLRI*)data;
    if (!mp_reach_nlri_ipv4_available)
    {
      mpData->capHdr.cap_code   = BGP_CAP_T_MPNLRI;
      mpData->capHdr.cap_length = 4;
      mpData->afi = htons(AFI_V4);
      mpData->reserved = 0;
      mpData->safi = SAFI_UNICAST;
      mpData = (BGP_Cap_MPNLRI*)(data + sizeof(BGP_Cap_MPNLRI));
    }
    if (!mp_reach_nlri_ipv6_available)
    {
      mpData->capHdr.cap_code   = BGP_CAP_T_MPNLRI;
      mpData->capHdr.cap_length = 4;
      mpData->afi = htons(AFI_V6);
      mpData->reserved = 0;
      mpData->safi = SAFI_UNICAST;
      mpData += 1;
    }
    sendNotification(session, BGP_ERR2_OPEN_MESSAGE, 
                     BGP_ERR2_SUB_UNSUPPORTED_CAPABILITY, size, data, 
                     SESS_FLOW_CONTROL_REPEAT);
    free (data);
    data = NULL;
    mpData = NULL;
  }
    
  // clean the buffer again
  memset(session->recvBuff, 0, ntohs(hdr->messageHeader.length));
}

/**
 * Process the provided bgp message.
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
                     0, NULL, SESS_FLOW_CONTROL_REPEAT);
    return;
  }
  int idx = 0;
  while (idx < BGP_MARKER_SIZE)
  {
    if (hdr->marker[idx++] != 0xFF)
    {
      // @TODO: Check RFC again and see the correct subcode
      sendNotification(session, BGP_ERR1_MESSAGE_HEADER, BGP_ERR1_SUB_NOT_SYNC,
                       0, NULL, SESS_FLOW_CONTROL_REPEAT);
      return;
    }
  }
          
  switch (hdr->type)
  {
    case BGP_T_OPEN:
      printf("ERROR: Received unexpected Open message!\n");
      sendNotification(session, BGP_ERR5_FSM, BGP_ERR_SUB_UNDEFINED, 
                       ntohs(hdr->length), (u_int8_t*)session->recvBuff,
                       SESS_FLOW_CONTROL_REPEAT);
      break;
    case BGP_T_KEEPALIVE:
      if (length != sizeof(BGP_KeepAliveMessage))
      {
        sendNotification(session, BGP_ERR1_MESSAGE_HEADER, 
                         BGP_ERR1_SUB_BAD_LENGTH, ntohs(hdr->length), 
                         (u_int8_t*)session->recvBuff, 
                         SESS_FLOW_CONTROL_REPEAT);        
      }
      session->lastReceived = time(0);
      break;
    case BGP_T_NOTIFICATION:        
      session->fsm.state = FSM_STATE_IDLE;
      if (session->sessHoldTimerSem != NULL)
      {
        // Notify the hold timer
        sem_post(session->sessHoldTimerSem);
      }
      //shutDownTCPSession(session);
      break;
    case BGP_T_UPDATE:
      session->lastReceived = time(0);
      break;
    default:
      printf("ERROR: Received unknown message type [%u]!\n", hdr->type);
      sendNotification(session, BGP_ERR1_MESSAGE_HEADER, BGP_ERR1_SUB_BAD_TYPE, 
                       ntohs(hdr->length), (u_int8_t*)session->recvBuff, 
                       SESS_FLOW_CONTROL_REPEAT);
      break;
  }
}

/** 
 * Check and possibly adjust the retry counter to accepted values.
 * 
 * @param session Allows to have a session configuration for the retry counter
 * @param retryCounter Pointer to the retry counter.
 */
static void _checkRetryCounter(BGPSession* session, int* retryCounter)
{
  if (*retryCounter < 0)
  {
    *retryCounter = 0;
  } else if (*retryCounter > SESS_FLOW_CONTROL_REPEAT)
  {
    *retryCounter = SESS_FLOW_CONTROL_REPEAT;
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
  bool retVal  = false;
  int  written = 0;
  
  switch (_isSocketAlive(session, POLL_TIMEOUT_MS, false))          
  {
    case SOCKET_ERR:
      // The file descriptor is broken, don't attempt to send.
      if (fsmCanSwitchTo(&session->fsm, FSM_STATE_IDLE))
      {
        fsmSwitchState(&session->fsm, FSM_STATE_IDLE);
      }
      printf ("ERROR: Cannot send Open, socket is broken!\n");
      break;
      
    case SOCKET_TIMEOUT:      
      printf ("WARNING: Socket timed out!\n");
      break;
      
    case SOCKET_ALIVE:
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
      if (size > 0 && size <= sizeof(sendBuff))
      {
        written = _writeData(session, sendBuff, size);
        if (session->bgpConf.printOnSend[PRNT_MSG_OPEN])
        {
          printf ("Send ");
          printBGP_Message((BGP_MessageHeader*)sendBuff);
        }
      }
      retVal = written == size;
      break;
      
    default:
      printf ("ERROR: Undefined socket state!\n");
      break;
  }
  
  return retVal;
}

/**
 * Send a keepalive to the peer. The FSM must be in ESTABLISHED.
 * This function allows retying to send in case the socket experienced a 
 * timeout. This can happen is the peer cannot keep up with the speed of the 
 * sending.
 * 
 * @param session the session where to send to
 * @param retryCounter The number of times the sending should be retried prior 
 *                     return returning false.
 * 
 * @return true if the message could be sent otherwise false.
 */
bool sendKeepAlive(BGPSession* session, int retryCounter)
{
  bool retVal = false;
  
  _checkRetryCounter(session, &retryCounter);
  
  switch (_isSocketAlive(session, POLL_TIMEOUT_MS, false))
  {
    case SOCKET_ERR:
      // The file descriptor is broken, don't attempt to send.
      if (fsmCanSwitchTo(&session->fsm, FSM_STATE_IDLE))
      {
        fsmSwitchState(&session->fsm, FSM_STATE_IDLE);
      }
      printf ("ERROR: Cannot send KEEPALIVE message, socket is broken!\n");
      break;
      
    case SOCKET_TIMEOUT:      
      printf ("WARNING: Cannot send KEEPALIVE message, socket timed out!\n");
      if (retryCounter-- > 0)
      {
        printf ("INFO: Retry sending KEEPALIVE message in %u seconds.\n", 
                SESS_FLOW_CONTROL_SLEEP);
        sleep (SESS_FLOW_CONTROL_SLEEP);
        retVal = sendKeepAlive(session, retryCounter);
      }
      break;
      
    case SOCKET_ALIVE:
      if (session->fsm.state != FSM_STATE_ESTABLISHED)
      {
        printf ("FSM is not in ESTABLISHED state!\n");
        break;
      }

      unsigned char sendBuff[SESS_MIN_SEND_BUFF];
      memset(sendBuff, 0, SESS_MIN_SEND_BUFF);
      int size = createKeepAliveMessge(sendBuff, sizeof(sendBuff));
      if (size < 0)
      {
        // @TODO: resize the sending buffer
        printf ("%i bytes missing!", size * (-1));
        break;
      }
      int written = 0;
      if (size > 0 && size <= sizeof(sendBuff))
      {
        written = _writeData(session, sendBuff, size);
        if (session->bgpConf.printOnSend[PRNT_MSG_KEEPALIVE])
        {
          printf ("Send ");
          printBGP_Message((BGP_MessageHeader*)sendBuff);
        }
      }
      retVal = (written == size);
      break;
    default:
      printf ("WARNING: Undefined socket state!\n");
      break;
  }
  
  return retVal;
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
 * @param retryCounter The number of retries in case the socket timed out.
 * 
 * @return true if successful, otherwise false.
 */
bool sendNotification(BGPSession* session, int error_code, int subcode, 
                      u_int16_t dataLength, u_int8_t* data, int retryCounter)
{
  bool retVal = false;
  unsigned char sendBuff[SESS_MIN_SEND_BUFF];
  
  _checkRetryCounter(session, &retryCounter);
  
  switch (_isSocketAlive(session, POLL_TIMEOUT_MS, false))
  {
    case SOCKET_ERR:
      // The file descriptor is broken, don't attempt to send.
      if (fsmCanSwitchTo(&session->fsm, FSM_STATE_IDLE))
      {
        fsmSwitchState(&session->fsm, FSM_STATE_IDLE);
      }
      printf ("ERROR: Cannot send NOTIFICATION message, socket is broken!\n");
      break;
      
    case SOCKET_TIMEOUT:
      printf ("WARNING: Cannot send NOTIFICATION message, socket timed out!\n");
      if (retryCounter-- > 0)
      {
        printf ("INFO: Retry sending NOTIFICATION message in %u seconds.\n", 
                SESS_FLOW_CONTROL_SLEEP);
        sleep (SESS_FLOW_CONTROL_SLEEP);
        retVal = sendNotification(session, error_code, subcode, dataLength, 
                                  data, retryCounter);
      }
      break;
      
    case SOCKET_ALIVE:
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
          printf ("Send ");
          printBGP_Message((BGP_MessageHeader*)sendBuff);
        }
      }

      retVal = written == size;
      if (retVal)
      {
        //session->shutdownSess(session);
        if (!fsmSwitchState(&session->fsm, FSM_STATE_IDLE))
        {
          printf("ERROR: Cannot move FSM to IDLE state!\n");
          retVal = session->fsm.state == FSM_STATE_IDLE;
          // @TODO: Throw an error, this is definitely a BUG
        }
      }
      break;
      
    default:
      printf("ERROR: Undefined socket state!\n");
      break;
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
 * @param retryCounter Allows to retry sending in case the socket experienced a 
 *                     timeout.
 * 
 * @return true if the update could be send.
 */
bool sendUpdate(BGPSession* session, BGP_UpdateMessage_1* update, 
                int retryCounter)
{
  bool retVal = false;
  int written = 0;
  u_int16_t size = ntohs(update->messageHeader.length);
  
  _checkRetryCounter(session, &retryCounter);
  
  if (session->fsm.state != FSM_STATE_ESTABLISHED)
  {
    printf ("NOTICE: Cannot send UPDATE message, FSM is not in ESTABLISHED state!\n");
    return retVal;
  }
 
  switch (_isSocketAlive(session, POLL_TIMEOUT_MS, false))
  {
    case SOCKET_ERR:
      printf ("ERROR: Cannot send UPDATE message, socket is broken - move to IDLE!\n");
      if (fsmCanSwitchTo(&session->fsm, FSM_STATE_IDLE))
      {
        fsmSwitchState(&session->fsm, FSM_STATE_IDLE);
      }
      else
      {
        printf ("ERROR: Cannot switch to IDLE!\n");        
      }
      break;
      
    case SOCKET_TIMEOUT:
      printf ("WARNING: Cannot send UPDATE message, socket timed out!\n");
      if (retryCounter-- > 0)
      {
        printf ("INFO: Retry sending UPDATE message in %u seconds.\n", 
                SESS_FLOW_CONTROL_SLEEP);
        sleep (SESS_FLOW_CONTROL_SLEEP);
        retVal = sendUpdate(session, update, retryCounter);
      }
      break;
      
    case SOCKET_ALIVE:
      // Check if we can send the message!
      if (size > BGP_MAX_MESSAGE_SIZE)
      {
        // We can only send the message if extended message was negotiated!
        // Or if forced - Only to allow testing the peer
        bool doSend = (    session->bgpConf.peerCap.extMsgSupp 
                        && session->bgpConf.capConf.extMsgSupp)
                      || session->bgpConf.capConf.extMsgForce;
        if (!doSend)
        {
          printf ("WARNING: Cannot send message due to message size > %d\n", 
                  BGP_MAX_MESSAGE_SIZE);
          if (!session->bgpConf.capConf.extMsgSupp)
          {
            printf ("         * To send this messages, enable the extended message"
                    " size capability!\n");
          }
          if (!session->bgpConf.peerCap.extMsgSupp)
          {
            printf ("         * Peer did not announce the extended message"
                    " size capability!\n");
          }
          break;
        }
        
        if (size > BGP_EXTMAX_MESSAGE_SIZE)
        {
          printf ("ERROR: Cannot send message due to message size > %d\n", 
                  BGP_EXTMAX_MESSAGE_SIZE);
          break;      
        }
      }

      written = _writeData(session, (u_int8_t*)update, size);
#ifdef CREATE_TESTVECTOR
      // This mode is to print a detailed version of the update, incl. byte dump      
      printf ("\nUpdate from AS(%u) to AS(%u):\n", 
              session->bgpConf.asn, session->bgpConf.peerAS);
      printf ("===================================\n");
      printf ("Binary Form of BGP/BGPsec Update (TCP-DUMP):\n\n");
      
      printHex((u_int8_t*)update, size, "");
      printf ("\n");
      printf ("The human readable output is produced using bgpsec-io, a bgpsec");
      printf ("\ntraffic generator that uses a wireshark like printout.\n\n");
      bool prnOnUpdate = session->bgpConf.printOnSend[PRNT_MSG_UPDATE];
      // Enable update printer in this mode.
      session->bgpConf.printOnSend[PRNT_MSG_UPDATE] = true;
#endif            
      if (session->bgpConf.printOnSend[PRNT_MSG_UPDATE])
      {
        printf ("Send ");
        printBGP_Message((BGP_MessageHeader*)update);
        //printUpdateData((BGP_UpdateMessage_1*)update);
      }
      
      retVal = (written == size);

      if (retVal)
      {
        session->lastSentUpdate = session->lastSent;
      }      
      break;
      
    default:
      break;
  }
  
  return retVal;
}