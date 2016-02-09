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
 * Provides the code for the SRX-RPKI router client connection.
 *
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2016/01/21 - kyehwanl
 *            * added pthread cancel state for enabling keyboard interrupt
 * 0.3.0.10 - 2015/11/10 - oborchert
 *            * Removed un-used attributes.
 * 0.3.0.7  - 2015/04/17 - oborchert
 *            * BZ599 - Changed typecase from (int) to (uintptr_t) to prevent
 *              compiler warnings and other nasty side affects while compiling
 *              on 32 and 64 bit OS.
 * 0.3.0    - 2013/01/28 - oborchert
 *            * Update to be compliant to draft-ietf-sidr-rpki-rtr.26. This
 *             update does not include the secure protocol section. The protocol
 *             will still use un-encrypted plain TCP
 *          - 2012/12/17 - oborchert
 *            * Adapted to the changes in the underlying client socket structure.
 *            * Fixed some spellers in documentation
 *            * Added documentation TODO
 * 0.2.0    - 2011/03/27 - oborchert
 *            * Changed implementation to follow draft-ietf-rpki-rtr-10
 * 0.1.0    - 2010/03/11 - pgleichm
 *            * Code Created
 * -----------------------------------------------------------------------------
 */
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>
#include "server/rpki_router_client.h"
#include "util/client_socket.h"
#include "util/log.h"
#include "util/socket.h"
#include "util/prefix.h"

#define HDR "([0x%08X] RPKI Router Client): "

/**
 * Handle received IPv4 Prefixes.
 *
 * @param client The router client instance.
 * @param hdr the IPv4 prefix header.
 * @return
 */
static bool handleIPv4Prefix(RPKIRouterClient* client,
                             RPKIIPv4PrefixHeader* hdr)
{
  IPPrefix  prefix;
  bool      isAnn;
  uint32_t  clientID;
  uint16_t  sessionID;

  /* Create the version independent prefix */
  prefix.ip.version = 4;
  memcpy(&prefix.ip.addr, &hdr->addr, sizeof(IPv4Address));
  prefix.length = hdr->prefixLen;

  /* Flags */
  isAnn     = (hdr->flags & PREFIX_FLAG_ANNOUNCEMENT);
  clientID  = client->routerClientID;
  sessionID = client->sessionID;

  /* Pass the information to the callback */
  client->params->prefixCallback(clientID, sessionID, isAnn, &prefix,
                                 hdr->maxLen, ntohl(hdr->as), client->user);
  return true;
}

/**
 * Creates a function to handle an IPv6 prefix.
 *
 * The parameters of the created function are:
 * @param client Client the client connection
 * @param hdr The IPv4 prefix header.
 */
static bool handleIPv6Prefix(RPKIRouterClient* client,
                             RPKIIPv6PrefixHeader* hdr)
{
  IPPrefix  prefix;
  bool      isAnn;
  uint32_t  clientID;
  uint16_t  sessionID;

  /* Create the version independent prefix */
  prefix.ip.version = 6;
  memcpy(&prefix.ip.addr, &hdr->addr, sizeof(IPv6Address));
  prefix.length = hdr->prefixLen;

  /* Flags */
  isAnn     = (hdr->flags & PREFIX_FLAG_ANNOUNCEMENT);
  clientID  = client->routerClientID;
  sessionID = client->sessionID;

  /* Pass the information to the callback */
  client->params->prefixCallback(clientID, sessionID,
                                 isAnn, &prefix, hdr->maxLen, ntohl(hdr->as),
                                 client->user);
  return true;
}

/**
 * Handles the receipt of an error pdu. The encapsulated PDU is ignored,
 * the error message will be printed though.
 *
 * @param client Client
 * @param hdr PDU header
 * @return \c 0 = stay connected, \c 1 = disconnect, \c -1 = socket error
 */
static int handleErrorReport(RPKIRouterClient* client,
                             RPKIErrorReportHeader* hdr)
{
  uint32_t epduLen = ntohl(hdr->len_enc_pdu);
  // Go to the message portion
  uint8_t* messagePtr = (uint8_t*)hdr+12+epduLen;
  // Set the messageLen
  uint32_t msgLen = ntohl(*(uint32_t*)messagePtr);
  char     msgStr[msgLen+1];
  int returnVal = (hdr->error_number == 2) ? 0 : 1; // all except 2 are fatal!

  // Zero terminate message String
  msgStr[msgLen] = '\0';
  // read the Message:
  int idx=0;
  // fill the string
  for (;idx < msgLen; idx++)
  {
    msgStr[idx] = *(messagePtr+4+idx);
  }
  // Read the error pdu


  if (client->params->errorCallback != NULL)
  {
    // Pass the code and message to the error callback of this connection
    if (client->params->errorCallback(ntohs(hdr->error_number), msgStr,
                                      client->user))
    {
      returnVal = 0;
    }
    else
    {
      returnVal = 1;
    }
  }
  else
  {
    LOG(LEVEL_INFO, "ERROR RECEIVING ERROR-PDU type:%d!", hdr->error_number);
    returnVal = -1;
  }

  return returnVal;
}

/**
 * Verify that the cache session id is correct. In case the cache session id is
 * incorrect == changed the flag session id_changed will be set to true. The old
 * session id value will be preserved to allow referencing old values.
 *
 * in case the flag client->startup is set to true the session id will be
 * initialized with the given parameter session id and the startup flag as well
 * as the client->session id_changed flag, both will be set to false.
 *
 * @param client The client connection.
 * @param sessionID The new cache session id (IN NETWORK ORDER).
 *
 * @return true if the cache session id is correct, otherwise false.
 */
static bool checkSessionID(RPKIRouterClient* client, uint32_t sessionID)
{
  bool retVal;

  if (client->startup)
  {
    client->startup    = false;
    client->sessionID = sessionID;
    client->sessionIDChanged = false;
  }

  retVal = client->sessionID == sessionID;
  if (!retVal)
  {
    client->sessionIDChanged = true;
    LOG(LEVEL_INFO, "Session ID changed, reboot session!");
  }
  // both values are in network order -> direct comparison possible.
  return retVal;
}

/**
 * This method implements the receiver thread between the RPKI client and
 * RPKI server. It reads each PDU completely.
 *
 * @param client The client connection to the RPKI router.
 * @param returnAterEndOfData Allows to exit the function once an end of data
 *                            is received. This is used during cache session id
 *                            change where the cache is reloaded.
 */
static void receivePDUs(RPKIRouterClient* client, bool returnAterEndOfData)
{
  RPKICommonHeader* hdr;  // A pointer to the Common header.
  uint32_t          pduLen;
  uint8_t*          byteBuffer;
  uint8_t*          bufferPtr;
  uint32_t          bytesMissing;
  // Use the "maximum" header. It can grow in case an error pdu is received
  // with a large error message or a PDU included or both. In this case the
  // memory will be extended to the space needed. In case the space can not be
  // extended, the PDU will be loaded as much as possible and the rest will be
  // skipped.
  uint32_t         bytesAllocated = sizeof(RPKIIPv6PrefixHeader);
  // Keep going is used to keep the received thread up and running. It will be
  // set false once the connection is shut down.
  bool             keepGoing = true;

  // Allocate the message buffer
  byteBuffer = malloc(bytesAllocated);
  // Set the bufferPtr to the position where the remaining data has be loaded
  // into.
  bufferPtr = (byteBuffer + sizeof(RPKICommonHeader));
  if (!byteBuffer)
  {
    RAISE_ERROR("Could not allocate enough memory to read from socket!");
    return;
  }

  // KeepGoing until a cache session id changed / in case of connection loss,
  // a break stops this while loop.
  while (keepGoing)
  {
    // Read the common data for the Common header. This method fails in case the
    // connection is lost.
    if (!recvNum(getClientFDPtr(&client->clSock), byteBuffer,
                 sizeof(RPKICommonHeader)))
    {
      LOG(LEVEL_DEBUG, HDR "Connection lost!", pthread_self());
      break;
    }

    hdr = (RPKICommonHeader*)byteBuffer;
    // retrieve the actual size of the message. In case more needs to be loaded
    // it will be done.
    pduLen = ntohl(hdr->length);
    if (pduLen < sizeof(RPKICommonHeader))
    {
      LOG(LEVEL_DEBUG, HDR "Received an invalid RPKI-RTR PDU!", pthread_self());
      break;
    }
    LOG(LEVEL_DEBUG, HDR "Received RPKI-RTR PDU[%d]", pthread_self(),
                     hdr->type);

/////////////////////////////////////////
    // Determine how much data is still missing
    bytesMissing = pduLen - sizeof(RPKICommonHeader);

    // Read the rest of the PDU
    if (bytesMissing > 0)
    {
      // Check if the current buffer is big enough
      if (bytesMissing > bytesAllocated)
      {
        // The current buffer is to small -> try to increase it.
        uint8_t* newBuffer = realloc(byteBuffer, bytesMissing);
        if (newBuffer)
        {
          byteBuffer = newBuffer; // reset to the bigger space
          bytesAllocated = bytesMissing;
          bufferPtr = (byteBuffer + sizeof(RPKICommonHeader));
        }
        else
        {
          // can only happen in case it is an error packet that contains an
          // erroneous PDU or extreme large error text.
          RAISE_ERROR("Invalid PDU length : type=%d, length=%u, data-size=%u",
                      hdr->type, pduLen, bytesMissing);

          // Skip over the data
          if (!skipBytes(&client->clSock, bytesMissing))
          {
            break;
          }
        }
      }

      // Now load the remaining data
      if (!recvNum(getClientFDPtr(&client->clSock), bufferPtr, bytesMissing))
      {
        break;
      }
    }
/////////////////////////////////////////
    client->lastRecv = hdr->type;

    LOG(LEVEL_DEBUG, HDR "Received RPKI-RTR PDU[%u] length=%u\n",
                     pthread_self(), hdr->type, ntohl(hdr->length));

    // Is needed in PDU_TYPE_ERROR_REPORT
    int ret;

    // Handle the data depending on the type
    switch (hdr->type)
    {
      case PDU_TYPE_SERIAL_NOTIFY :
        // Respond with a serial query
        if (checkSessionID(client, ((RPKISerialNotifyHeader*)hdr)->sessionID))
        {
          sendSerialQuery(client);
        }
        else
        {
          keepGoing = false;
        }
        break;
      case PDU_TYPE_CACHE_RESPONSE :
        keepGoing = checkSessionID(client,
                               ((RPKICacheResponseHeader*)hdr)->sessionID);
        // No need to do anything
        break;
      case PDU_TYPE_IP_V4_PREFIX :
        handleIPv4Prefix(client, (RPKIIPv4PrefixHeader*)byteBuffer);
        break;
      case PDU_TYPE_IP_V6_PREFIX :
        handleIPv6Prefix(client, (RPKIIPv6PrefixHeader*)byteBuffer);
        break;
      case PDU_TYPE_END_OF_DATA :
        if (checkSessionID(client, ((RPKIEndOfDataHeader*)hdr)->sessionID))
        {
          // store not byte-swapped
          client->serial = ((RPKIEndOfDataHeader*)byteBuffer)->serial;
          keepGoing = !returnAterEndOfData;
        }
        else
        {
          keepGoing = false;
        }
        break;
      case PDU_TYPE_CACHE_RESET :
        // Reset our cache
        client->params->resetCallback(client->routerClientID, client->user);
        // Respond with a cache reset
        sendResetQuery(client);
        break;
      case PDU_TYPE_ERROR_REPORT :
        ret = handleErrorReport(client, (RPKIErrorReportHeader*)byteBuffer);
        if (ret != 0)
        {
          if (ret == 1)
          {
            // BZ599 - Changed typecase from (int) to (uintptr_t) to prevent
            // compiler warnings and other nasty side affects while compiling
            // on 32 and 64 bit OS.
            close((uintptr_t)getClientFDPtr(&client->clSock));
          }
          return;
        }
        break;
      case PDU_TYPE_RESERVED :
        LOG(LEVEL_ERROR, "Received reserved RPKI-PDU Type 255");
        break;
      default :
        // We handled all known types already
        LOG(LEVEL_ERROR, "Unknown/unexpected RPKI-PDU Type %u", hdr->type);
    }
  }
  // Release the buffer again.
  free(byteBuffer);
}


void sigusr_rpki_pipe_handler(int signo)
{
  LOG(LEVEL_DEBUG, "([0x%08X]) received [%d]SIGPIPE from broken socket --> rpki"
                   " keep alive ", pthread_self(), signo);
  shutdown(g_rpki_single_thread_client_fd, SHUT_RDWR);
  close(g_rpki_single_thread_client_fd);
}

/**
 * Tries to keep the connection up - and starts the loop that receives
 * and processes all PDUs.
 *
 * @note PThread syntax
 *
 * @param clientPtr a pointer to the RPKIRouterClient*
 */
static void* manageConnection (void* clientPtr)
{
  RPKIRouterClient* client = (RPKIRouterClient*)clientPtr;
  int               sec;

  struct sigaction act;
  sigset_t errmask;
  sigemptyset(&errmask);
  sigaddset(&errmask, SIGPIPE);
  act.sa_handler = sigusr_rpki_pipe_handler;
  sigaction(SIGPIPE, &act, NULL);
  pthread_sigmask(SIG_UNBLOCK, &errmask, NULL);
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
  g_rpki_single_thread_client_fd = client->clSock.clientFD;


  LOG (LEVEL_DEBUG, "([0x%08X]) > RPKI Router Client Thread started!",
                    pthread_self());

  while (!client->stop)
  {
    // Start off every new connection with a reset
    if (sendResetQuery(client))
    {
      // Receive and process all PDUs - This is a loop until the connection
      // is either lost or closed.
      receivePDUs(client, false);
    }

    // The connection is lost or did not even exist yet.

    // Test if the connection stopped!
    if (client->stop)
    {
      LOG(LEVEL_DEBUG, HDR "Client Connection was stopped!", pthread_self());
      break;
    }

    // Should we try to reconnect
    sec = (client->params->connectionCallback == NULL)
              ? -1
              : client->params->connectionCallback(client->user);


    if (sec == -1)
    { // Stop trying to re-establish the connection
      pthread_exit((void*)1);
    }

    if (client->sessionIDChanged)
    {
      // prepare some settings to allow a fresh start
      client->startup = true;
    }

    // Now try to reconnect.
    reconnectToServer(&client->clSock, sec, MAX_RECONNECTION_ATTEMPTS);

    // See if the session_id changed!
    if (client->sessionIDChanged)
    {
      LOG (LEVEL_DEBUG, HDR "ENTER SESSION ID CHANGE", pthread_self());
      // The following work flow allows to implement a graceful restart
      // of the session to the validation cache.
      // the operation is intended to be as follow.
      // (1) notify the SRx cache of session_id change. This can delete the
      //     internal cache or mark it as stale
      // (2) reload the cache by processing a reset query
      // (3) notify the SRx cache that all data is loaded and the stale
      //     remaining data can be removed. This would be the point of notifying
      //     the BGP router of all changes in validation.
      if (client->params->sessionIDChangedCallback != NULL)
      {
        client->params->sessionIDChangedCallback(client->routerClientID,
                                                 client->sessionID);
      }
      LOG (LEVEL_DEBUG, HDR "CACHE SESSION ID CHANGE: SEND RESET QUERY",
                        pthread_self());
      if (sendResetQuery(client))
      {
        // Receive and process all PDUs. The flag client->session_id_changed
        // is already set to false.
        LOG (LEVEL_DEBUG, "SESSION ID CHANGE: RECEIVE DATA", pthread_self());
        receivePDUs(client, true);
      }
      LOG (LEVEL_DEBUG, "SESSION ID CHANGE: DATA ESTABLISHED", pthread_self());
      if (client->params->sessionIDEstablishedCallback != NULL)
      {
        client->params->sessionIDEstablishedCallback(client->routerClientID,
                                                     client->sessionID);
      }
      LOG (LEVEL_DEBUG, "SESSION ID CHANGE: DONE!", pthread_self());
    }
  }

  LOG (LEVEL_DEBUG, "([0x%08X]) < RPKI Router Client Thread stopped!",
                    pthread_self());

  pthread_exit(0);
}

/**
 * Creates an ID for this RouterClient.
 *
 * @param self the client instance
 *
 * @todo add some implementation
 *
 * @return currently only 0
 */
uint32_t createRouterClientID(RPKIRouterClient* self)
{
  // TODO: Add implementation for a unique ID. Maybe an initial hash over self.
  return 0;
}

/**
 * Create the RPKI Router Client instance and initialized the data structure.
 *
 * @param self pointer to the RPKI Router Client
 * @param params The parameters of the client
 * @param user The user of the client.
 *
 * @return true if a Client could be created, otherwise false.
 */
bool createRPKIRouterClient (RPKIRouterClient* self,
                             RPKIRouterClientParams* params,
                             void* user)
{
  int ret;

  // Check if the mandatory callback is set...
  if ((params->prefixCallback == NULL) || (params->resetCallback == NULL))
  {
    RAISE_ERROR("Not all mandatory callback methods are set");
    return false;
  }

  // Try to connect to the server
  if (!createClientSocket (&self->clSock,
                           params->serverHost, params->serverPort,
                           (params->connectionCallback == NULL),
                           RPKI_RTR_CLIENT_SOCKET, true))
  {
    RAISE_ERROR("Failed to file handle or to connect to the RPKI/Router "
                "protocol server");
    return false;
  }

  // Initialize a write-mutex - for the "send" functions
  if (!initMutex(&self->writeMutex))
  {
    RAISE_ERROR("Failed to initialize a write-mutex");
    closeClientSocket(&self->clSock);
  }

  // User data
  self->user = user;

  // Create a thread which handles the receipt of PDUs
  self->params = params;
  self->stop   = false;

  // Configure necessary data for cache session id. The configuration
  // startup=true allows the sessionID attribute to be set without further
  // action.
  self->sessionID        = 0xffff;
  self->sessionIDChanged = false;
  self->startup          = true;

  self->routerClientID = createRouterClientID(self);

  ret = pthread_create (&self->thread, NULL, manageConnection, self);
  if (ret)
  {
    RAISE_ERROR("Failed to spawn a receiving thread (result: %d)", ret);
    releaseMutex(&self->writeMutex);
    closeClientSocket(&self->clSock);
    return false;
  }

  return true;
}

#include <errno.h>
#define handle_error_en(en, msg) \
                 do { errno = en; perror(msg);  pthread_exit(0); } while (0)
//TODO: Documentation missing
void releaseRPKIRouterClient (RPKIRouterClient* self)
{
  // Close the connection
  self->stop = true;
  releaseMutex(&self->writeMutex);
  closeClientSocket(&self->clSock);

  int s;
  // Wait until the thread terminates
  s = pthread_cancel(self->thread);
  if (s != 0)
    handle_error_en(s, "pthread_join");
}

/**
 * Send a RESET QUERY to the validation cache to re-request the complete
 * data
 *
 * @param self The instance of the rpki router client
 *
 * @return true if the request could be send successfully
 */
bool sendResetQuery (RPKIRouterClient* self)
{
  RPKIResetQueryHeader hdr;
  bool                 succ = false;

  if (self->clSock.clientFD != -1)
  {
    LOG(LEVEL_DEBUG, HDR "Send Reset Query(srq)...", pthread_self());

    hdr.version  = RPKI_RTR_PROTOCOL_VERSION;
    hdr.type     = PDU_TYPE_RESET_QUERY;
    hdr.reserved = 0x0000;
    hdr.length   = htonl(sizeof(RPKIResetQueryHeader));

    lockMutex(&self->writeMutex);
    self->lastSent = PDU_TYPE_RESET_QUERY;

    succ = sendNum (getClientFDPtr(&self->clSock), &hdr,
                    sizeof(RPKIResetQueryHeader));

    if (succ)
    {
      self->lastSent = PDU_TYPE_RESET_QUERY;
    }
    else
    {
      // TODO: Maybe just close the old socket and set both to -1
      // The socket was not closed but the FD was set to -1. reset it to allow
      // proper closing.
      self->clSock.clientFD = self->clSock.oldFD;
    }
    unlockMutex(&self->writeMutex);

    LOG (LEVEL_DEBUG, HDR "...%s\n", pthread_self(), (succ ? "done(srq)."
                                                           : "failed!(srq)"));
  }


  return succ;
}

/**
 * Send a SERIAL QUERY to the rpki validation cache. The sessionID and serial
 * number are extracted of the router client itself.
 *
 * @param self the instance of rpki router client.
 *
 * @return true if the packet could be send successfully
 */
bool sendSerialQuery (RPKIRouterClient* self)
{
  RPKISerialQueryHeader hdr;
  hdr.version   = RPKI_RTR_PROTOCOL_VERSION;
  hdr.type      = PDU_TYPE_SERIAL_QUERY;
  hdr.sessionID = self->sessionID;
  hdr.length    = htonl(sizeof(RPKISerialQueryHeader));
  hdr.serial    = self->serial;

  bool succ  = false;

  lockMutex(&self->writeMutex);
  LOG(LEVEL_DEBUG, HDR "Sending Serial Query...\n", pthread_self());

  if (sendNum(getClientFDPtr(&self->clSock), &hdr,
              sizeof(RPKISerialQueryHeader)))
  {
    self->lastSent = PDU_TYPE_SERIAL_QUERY;
  }
  unlockMutex(&self->writeMutex);

  return succ;
}

//TODO: Documentation missing
inline RPKIRouterPDUType getLastSentPDUType(RPKIRouterClient* self)
{
  return self->lastSent;
}

//TODO: Documentation missing
inline RPKIRouterPDUType getLastReceivedPDUType(RPKIRouterClient* self)
{
  return self->lastRecv;
}

//TODO: Documentation missing
void sigusr_general_pipe_handler(int signo)
{
  LOG(LEVEL_DEBUG, "([0x%08X]) received signal %d from broken socket  ",
                   pthread_self(), signo);
  shutdown(g_rpki_single_thread_client_fd, SHUT_RDWR);
  //pthread_kill(pthread_self(), SIGPIPE);
}

//TODO: Documentation missing
void generalSignalProcess(void)
{
  struct sigaction act;
  sigset_t errmask;
  sigemptyset(&errmask);
  sigaddset(&errmask, SIGPIPE);
  act.sa_handler = sigusr_general_pipe_handler;
  sigaction(SIGPIPE, &act, NULL);
  pthread_sigmask(SIG_UNBLOCK, &errmask, NULL);
}

