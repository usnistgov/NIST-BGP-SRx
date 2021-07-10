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
 * @version 0.6.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.6.0.0 - 2021/03/31 - oborchert
 *           * Modified loops to be C99 compliant 
 *         - 2021/03/30 - oborchert
 *            * Added missing version control. Also moved modifications labeled 
 *              as version 0.5.2.0 to 0.6.0.0 (0.5.2.0 was skipped)
 *            * Cleaned up some merger left overs and synchronized with naming 
 *              used conventions.
 *          - 2021/02/26 - kyehwanl
 *            * Removed function handlePDUASPA
 *          - 2021/02/16 - oborchert
 *            * Added ERROR logging in case of invalid ASPA provider count.
 *            * Fixed bug in handlePDUASPA by converting also the providerAS to
 *              host format.
 *          - 2021/02/12 - oborchert
 *            * Fixed function _getPacket that did not resize the buffer 
 *              correctly if not of required length. 
 *            * Added some variable initialization to NULL where warranted.
 * 0.5.1.0  - 2018/03/09 - oborchert 
 *            * BZ1263: Merged branch 0.5.0.x (version 0.5.0.4) into trunk 
 *              of 0.5.1.0.
 *          - 2017/10/13 - oborchert
 *            * Temporarily modified hard coded return value of function 
 *              createRouterClientID from 0 to 1.
 * 0.5.0.5  - 2018/05/17 - oborchert
 *            (merged from branch 0.5.0.x)
 *          - 2018/04/24 - oborchert
 *            * Added missing code in error handling.
 * 0.5.0.4  - 2018/03/07 - oborchert
 *            * Modified packet handling and added proper error handling and
 *              version handshake, 
 *            * Added internal error defines (RRC_.....)
 *            * Completed missing documentation.
 *            * Added documentation and removed inline from getLastSendPDU and 
 *              getLastReceivedPDU.
 *            * Fixed incorrect error code printing and streamlined the code in 
 *              method method handleErrorReport (-1 return value was rubbish).
 *            * Removed functions getLastSentPDUType and getLastReceivedPDUType
 * 0.5.0.3  - 2018/02/26 - oborchert
 *            * Added function wrapper _sendPDU to encapsulate allow debugging
 *              debugging of sending packets.
 *            * Added rpki_packet_printer header file.
 *          - 2018/02/23 - oborchert
 *            * Removed unnecessary code form sendResetQuery
 * 0.5.0.1  - 2017/10/01 - oborchert
 *            * Fixed compiler warning
 * 0.5.0.0  - 2017/06/29 - oborchert
 *            * Added documentation to function handlePDURouterKey
 *            * Added function handleEndOfData
 *            * renamed processPDURouterKey into handlePDURouterKey
 *          - 2017/06/16 - oborchert
 *            * Version 0.4.1.0 is trashed and moved to 0.5.0.0
 *          - 2016/08/30 - oborchert
 *            * Added capability to only have the receiving of PDU's done once
 *              by using the clients stopAfterEndofData attribute rather than a
 *              hard coded bool value in manageConnection.
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
#include "server/rpki_queue.h"
#include "server/rpki_router_client.h"
#include "server/rpki_packet_printer.h"
#include "util/client_socket.h"
#include "util/log.h"
#include "util/socket.h"
#include "util/prefix.h"
#include "main.h"

#define HDR "([0x%08X] RPKI Router Client): "

// Error codes for function receive PDU
#define RRC_RCV_PDU_NO_ERROR     -1
#define RRC_RCV_PDU_SOCKET_ERROR -2
#define RRC_RCV_PDU_MEMORY_ERROR -3

// Define a default string length
#define RRC_MAX_STRING 255
// Maximum errors during PDU processing
#define RRC_MAX_ERRCT  10

/**
 * Handle received IPv4 Prefixes.
 *
 * @param client The router client instance.
 * @param hdr the IPv4 prefix header.
 * 
 * @return true if the IPv4 prefix could be properly processed.
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
 * This function is a wrapper for handling the received error pdu. 
 * In case the client does not provide an additional error handler, this
 * function will print the received error code, the error message and return
 * the specified return values according to the quick processing of the packet. 
 *
 * @param client This client
 * @param hdr The received error PDU
 * 
 * @return 0: stay connected, 1: disconnect
 */
static int handleErrorReport(RPKIRouterClient* client,
                             RPKIErrorReportHeader* hdr)
{
  uint32_t  epduLen = ntohl(hdr->len_enc_pdu);
  // Go to the message portion
  uint8_t*  messagePtr = (uint8_t*)hdr+12+epduLen;
  // Retrieve the messageLen
  uint32_t  msgLen = ntohl(*(uint32_t*)messagePtr);
  char      errorStr[msgLen+1];
  u_int16_t error_number = ntohs(hdr->error_number);
  
  // all except RPKI_EC_NO_DATA_AVAILABLE (2) are fatal!
  int returnVal = (error_number == RPKI_EC_NO_DATA_AVAILABLE) ? 0 : 1; 

  //Initialize and fill the message String
  memset (errorStr, '\0', msgLen+1);
  messagePtr += 4;
  memcpy (errorStr, messagePtr, msgLen);

  if (client->params->errorCallback != NULL)
  {
    // Pass the code and message to the error callback of this connection
    returnVal = (client->params->errorCallback(error_number, errorStr, 
                                               client->user)) ? 0 : 1;
  }
  else
  {
    LOG(LEVEL_INFO, "ERROR RECEIVING ERROR-PDU type:%d, msg:'%s'!", 
                    error_number, errorStr);
  }

  return returnVal;
}

/**
 * Processes the router key PDU 
 * 
 * @param client The client connection
 * @param hdr The header with the information
 * 
 * @return true
 */
static bool handlePDURouterKey(RPKIRouterClient* client,
                               RPKIRouterKeyHeader* hdr)
{
  bool      isAnn;
  uint32_t  clientID;
  uint16_t  sessionID;
  uint8_t*  ski;
  uint8_t*  keyInfo;



  isAnn     = (hdr->flags & PREFIX_FLAG_ANNOUNCEMENT);
  clientID  = client->routerClientID;
  sessionID = client->sessionID;
  ski       = hdr->ski;
  keyInfo   = hdr->keyInfo;

  client->params->routerKeyCallback(clientID, sessionID, isAnn, ntohl(hdr->as),
                                    (char*)ski, (char*)keyInfo, client->user);
  return true;
}


/**
 * Processes the ASPA PDU
 *
 * @param client The client connection
 * @param hdr The header with the information
 *
 * @return true
 */
/*
static bool handlePDUASPA(RPKIRouterClient* client,
                          RPKIASPAHeader* hdr)
{
  bool      isAnn;
  uint32_t  clientID;
  uint16_t  sessionID;

  uint8_t  afi;
  uint32_t customerAS;
  uint16_t providerCount;
  uint8_t* providerASBuffer;
  uint8_t* srcPtr;
  uint32_t* srcData;
  uint32_t* providerAS;
  int idx = 0;

  isAnn         = (hdr->flags & PREFIX_FLAG_ANNOUNCEMENT);
  afi           = (hdr->flags & PREFIX_FLAG_AFI_V6);
  clientID      = client->routerClientID;
  sessionID     = client->sessionID;
  customerAS    = ntohl(hdr->customer_asn);
  providerCount = ntohs(hdr->provider_as_count);
  providerASBuffer = malloc(providerCount * 4);
  srcPtr           = (uint8_t*)hdr + sizeof(RPKIASPAHeader);

  providerAS = (uint32_t*)providerASBuffer;
  srcData    = (uint32_t*)srcPtr;
  for (; idx < providerCount; idx++, providerAS++, srcData++)
  {
    *providerAS = ntohl(*srcData);
  }

  client->params->aspaCallback(clientID, sessionID, isAnn, afi, customerAS,
                               providerCount, (uint32_t*)providerASBuffer,
                               client->user);
  return true;
}

*/


/**
 * Process the End Of Data PDU
 * 
 * @param client The client connection
 * @param hdr The header with the information
 * 
 * @since 0.5.0.0
 */
static void handleEndOfData(RPKIRouterClient* client,
                             RPKIEndOfDataHeader* hdr)
{
  uint32_t  clientID;
  uint16_t  sessionID;

  clientID  = client->routerClientID;
  sessionID = client->sessionID;
  
  client->params->endOfDataCallback(clientID, sessionID, client->user);
}

/**
 * This function checks the version number between the client and the cache.
 * If the session is still in negotiation stage and the client can downgrade to
 * successfully negotiate the session, the client version number will be 
 * downgraded. If not and the versions differ this function returns false.
 * 
 * @param client This client. 
 * @param version The version of the peer
 * 
 * @return true if the communication can be continued.
 * 
 * @since 0.5.0.3
 */
static bool checkVersion(RPKIRouterClient* client, u_int8_t version)
{
  if (client->version != version)
  {
    // Check the startup stage
    if (client->startup)
    {
      // In case client(self) has a higher version than the requested one
      // but can downgrade, then downgrade to peers version.
      if (  (client->version > version) && client->params->allowDowngrade)
      {
        client->version = version;
      }
    }
  }
  
  return client->version == version;
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
 * Read the next packet from the socket into the provided buffer. In case the 
 * buffer is not of sufficient size, the buffer will be extended.
 * 
 * In case of an internal error receiving the PDU the returned length can be 
 * less then the length field of the PDU indicates. In this case the errCode
 * contains an error.
 * 
 * The following errors can be reported:
 * 
 *     RRC_RCV_PDU_NO_ERROR:       No error
 *     RRC_RCV_PDU_SOCKET_ERROR:   Somehow not all data could be loaded.
 * 
 * @param client The client session
 * @param errCode Returns the error code.
 * @param buffer The buffer to be filled.
 * @param buffSize The max size of the buffer.
 * 
 * @return 0 or the number of bytes received (can be less then the PDU length).
 */
static u_int32_t _getPacket(RPKIRouterClient* client, int* errCode, 
                            uint8_t** buffer, uint32_t* buffSize)
{
  uint32_t pduLen       = 0;
  uint32_t bytesMissing = 0;
  uint8_t* bufferPtr    = *buffer + sizeof(RPKICommonHeader);
  RPKICommonHeader* hdr = (RPKICommonHeader*)*buffer;
  
  // Initialize the values.
  memset (*buffer, 0, *buffSize);
  *errCode = RRC_RCV_PDU_NO_ERROR;
  
  // Read the common data for the Common header. This method fails in case the
  // connection is lost.
  if (!recvNum(getClientFDPtr(&client->clSock), *buffer,
                              sizeof(RPKICommonHeader)))
  {
    LOG(LEVEL_DEBUG, HDR "Connection lost!", pthread_self());
    *errCode  = RRC_RCV_PDU_SOCKET_ERROR;
  }
  else
  {
    // retrieve the actual size of the message. In case more needs to be loaded
    // it will be done.
    pduLen = ntohl(hdr->length);
    if (pduLen < sizeof(RPKICommonHeader))
    {
      LOG(LEVEL_DEBUG, HDR "Corrupted RPKI-RTR PDU: Size!", pthread_self());
      *errCode  = RPKI_EC_CORRUPT_DATA;
    }    
  }
  
  if (*errCode == RRC_RCV_PDU_NO_ERROR)
  {      
    // Determine how much data is still missing
    bytesMissing = pduLen - sizeof(RPKICommonHeader);

    // Read the rest of the PDU
    if (bytesMissing > 0)
    {
      // Check if the current buffer is big enough
      if (pduLen > *buffSize)
      {
        // The current buffer is to small -> try to increase it.
        uint8_t* newBuffer = realloc(*buffer, pduLen);
        if (newBuffer)
        {
          *buffer   = newBuffer; // reset to the bigger space
          *buffSize = pduLen;
          bufferPtr = (*buffer + sizeof(RPKICommonHeader));
        }
        else
        {
          // can only happen in case it is an error packet that contains an
          // erroneous PDU or extreme large error text.
          LOG(LEVEL_ERROR, "Invalid PDU length : type=%d, length=%u, "
                           "data-size=%u", hdr->type, pduLen, bytesMissing);

          // Try to skip over the data
          if (!skipBytes(&client->clSock, bytesMissing))
          {
            LOG(LEVEL_ERROR, "While reading a corrupted PDU, could not skip "
                             "over the remainig data");
          }
          *errCode = RPKI_EC_CORRUPT_DATA;
        }
      }

      // Now load the remaining data
      if (*errCode == RRC_RCV_PDU_NO_ERROR)
      {
        if (!recvNum(getClientFDPtr(&client->clSock), bufferPtr, bytesMissing))
        {
          *errCode = RRC_RCV_PDU_SOCKET_ERROR; 
          pduLen -= bytesMissing;
        }
      }
    }
  }
  
  return pduLen;
}

/**
 * This method implements the receiver loop between the RPKI client and
 * RPKI server. It reads and processes each PDU completely. It does NOT 
 * close the socket on return.
 * 
 * The following error codes can be returned:
 *   RPKI_EC_...: All RPKI error codes 0..255
 *   RRC_RCV_PDU_NO_ERROR:     No Error
 *   RRC_RCV_PDU_SOCKET_ERROR: Socket Error
 *   RRC_RCV_PDU_MEMORY_ERROR: Memory Error
 *
 * @param client The client connection to the RPKI router.
 * @param returnAterEndOfData Allows to exit the function once an end of data
 *                            is received. This is used during cache session id
 *                            change where the cache is reloaded.
 * @param errCode -3: Memory Error, -2: Socket error, -1: NO ERROR, 
 *                0..n RPKI_EC_... errors
 * @param singlePoll if true only one single packet will be processed. This 
 *                   allows to properly process a handshake.
 * 
 * @return true if all went well, false if an ERROR occurred.
 */
static bool receivePDUs(RPKIRouterClient* client, bool returnAterEndOfData, 
                        int* errCode, bool singlePoll)
{
  RPKICommonHeader* hdr        = NULL;  // A pointer to the Common header.
  uint32_t          pduLen     = 0;
  // Use the "maximum" header. It can grow in case an error pdu is received
  // with a large error message or an ASPA PDU with a large number of 
  // providerASs. In this case the memory will be extended to the space needed. 
  // In case the space can not be extended as needed, the PDU will be loaded as 
  // much as possible and the remainder will be skipped.
  uint32_t         bytesAllocated = sizeof(RPKIRouterKeyHeader);
  uint8_t*         byteBuffer = malloc(bytesAllocated);
  // Keep going is used to keep the received thread up and running. It will be
  // set false once the connection is shut down.
  bool             keepGoing   = !client->stop;
  
  if (byteBuffer != NULL)
  {
    // Reset the error code to NO ERROR
    *errCode = RRC_RCV_PDU_NO_ERROR;
  }
  else
  {
    RAISE_ERROR("Could not allocate enough memory to read from socket!");
    *errCode  = RRC_RCV_PDU_MEMORY_ERROR;
    keepGoing = false;
  }

  // KeepGoing until a cache session id changed / in case of connection loss,
  // a break stops this while loop.
  while (keepGoing && !client->stop)
  {
    // If singlePoll is selected, stop after this poll.
    keepGoing = !singlePoll;
    
    pduLen = _getPacket(client, errCode, &byteBuffer, &bytesAllocated);
    if (!pduLen)
    {
      keepGoing = false;
      continue;
    }
    hdr = (RPKICommonHeader*)byteBuffer;
    
    LOG(LEVEL_DEBUG, HDR "Received RPKI-RTR PDU[%u] length=%u\n",
                     pthread_self(), hdr->type, ntohl(hdr->length));

    // This is for printing received PDU's
    if (client->params->debugRecCallback != NULL)
    {
      printf ("Received Packet:\n");
      client->params->debugRecCallback(client, hdr);
    }
    
    // Check if a version conflict exist. During negotiation this method might 
    // downgrade the protocol.
    if (!checkVersion(client, hdr->version))
    {
      // Check if the cache has a higher unsupported version or if the
      // cache or client only supports version 0. In both cases use 
      // UNSUPPORTED, otherwise use UNEXPECTED (version 1+)
      *errCode = ((hdr->version > RPKI_RTR_PROTOCOL_VERSION)
                  || (client->version == 0))
                 ? RPKI_EC_UNSUPPORTED_PROT_VER
                 : RPKI_EC_UNEXPECTED_PROTOCOL_VERSION;
      
      // the router and cache might still be in handshake
      if (client->startup)
      {
        // Still in session establishment RFC8210 Section 7
        // Following RFC 8210 Section 7 the cache responded with a lower version.        
        if (client->params->allowDowngrade)
        {
          // 1st. let us downgrade and then decide what to do next.
          LOG(LEVEL_NOTICE, "Cache responded with a version %u PDU, the "
                            "'router' can downgrade.", hdr->version);
          client->version = hdr->version;
          
          // 2nd, check if we can continue processing or if we need to stop 
          // here.
        }
        else
        {
          LOG(LEVEL_NOTICE, "Cache responded with a version %u PDU, the "
                            "'router' cannot downgrade.", hdr->version);
        }
        
        // In case the cache did not respond with an error PDU, let's accept 
        // this PDU by clearing the error and continue processing.
        if (hdr->type != PDU_TYPE_ERROR_REPORT)
        {
          *errCode = RRC_RCV_PDU_NO_ERROR;
        }
      }
      
      // Error is not cleared, register the PDU as last received and end loop
      if (*errCode != RRC_RCV_PDU_NO_ERROR)
      {
        // Stop loop of receiving data
        client->lastRecv = hdr->type;
        keepGoing = false;
        continue;
      }  
    }
        
    // Handle the data depending on the type
    u_int32_t sessionID = 0;
    switch (hdr->type)
    {
      case PDU_TYPE_SERIAL_NOTIFY :
        // Respond with a serial query
        sessionID = ((RPKISerialNotifyHeader*)hdr)->sessionID;
        if (checkSessionID(client, sessionID))
        {
          sendSerialQuery(client);
        }
        else
        {
          // incorrect session ID 
          keepGoing = false;
          *errCode = RPKI_EC_CORRUPT_DATA;
        }
        break;
      case PDU_TYPE_CACHE_RESPONSE :
        sessionID = ((RPKICacheResponseHeader*)hdr)->sessionID;
        if (!checkSessionID(client, sessionID))
        {
          client->sessionIDChanged = true;
          // Mark the clients cache DB as stale.
          client->params->sessionIDChangedCallback(client->routerClientID, 
                                                   sessionID);
          // @TODO: Fix Session ID. 
          // Only in case the previous message was a "Request Query" the session
          // ID is allowed to change. RFC8210 5.5 2nd paragraph
          if (client->lastSent != PDU_TYPE_CACHE_RESET)
          {
            keepGoing = false;
            *errCode = RPKI_EC_CORRUPT_DATA;
          }
        }
        break;
      case PDU_TYPE_IP_V4_PREFIX :
        handleIPv4Prefix(client, (RPKIIPv4PrefixHeader*)byteBuffer);
        break;
      case PDU_TYPE_IP_V6_PREFIX :
        handleIPv6Prefix(client, (RPKIIPv6PrefixHeader*)byteBuffer);
        break;
      case PDU_TYPE_END_OF_DATA :
        sessionID = ((RPKIEndOfDataHeader*)hdr)->sessionID;
        if (checkSessionID(client, sessionID))
        {
          // store not byte-swapped
          client->serial = ((RPKIEndOfDataHeader*)byteBuffer)->serial;
          // Now process the RPKI_QUEUE
          handleEndOfData(client, (RPKIEndOfDataHeader*)byteBuffer);
          // Stop the client is only one data poll is to be done.
          // Replace client-stop with keepGoing
          keepGoing = !returnAterEndOfData;
        }
        else
        {
          keepGoing = false;
          *errCode  = RPKI_EC_CORRUPT_DATA; 
        }
        break;
      case PDU_TYPE_ROUTER_KEY:
        if (client->version != 0)
        {
          handlePDURouterKey(client, (RPKIRouterKeyHeader*)byteBuffer);
        }
        else
        {
          *errCode = RPKI_EC_UNSUPPORTED_PDU;
          keepGoing = false;
        }
        break;
      case PDU_TYPE_CACHE_RESET:
        // Reset our cache
        client->params->resetCallback(client->routerClientID, client->user);
        // Respond with a cache reset
        sendResetQuery(client);
        break;
      case PDU_TYPE_ERROR_REPORT :
        // Switched from client-stop to keepGoing
        keepGoing = !handleErrorReport(client, 
                                       (RPKIErrorReportHeader*)byteBuffer);
        break;
      case PDU_TYPE_ASPA :
        if (client->version > 1)
        {
          LOG(LEVEL_INFO, FILE_LINE_INFO "ASPA PDU received from Rpki rtr server");
          // ASPA validation  
          handleReceiveAspaPdu(client, (RPKIASPAHeader*)byteBuffer, pduLen);
        }
        else
        {
          *errCode = RPKI_EC_UNSUPPORTED_PDU;
          keepGoing = false;
        }
        break;
      case PDU_TYPE_RESERVED :
        LOG(LEVEL_ERROR, "Received reserved RPKI-PDU Type %u", 
            PDU_TYPE_RESERVED);
        *errCode  = RPKI_EC_UNSUPPORTED_PDU;
        keepGoing = false;
        break;
      default :
        // We handled all known types already
        LOG(LEVEL_ERROR, "Unsupported RPKI-PDU Type %u", hdr->type);
        *errCode  = RPKI_EC_UNSUPPORTED_PDU;
        keepGoing = false;
    }
    // Set the last received PDU
    client->lastRecv = hdr->type;
  }
  
  // Now do error handling but only if not in handshake mode.
  if ((!client->startup) && (*errCode != RRC_RCV_PDU_NO_ERROR))
  {
    char errStr[RRC_MAX_STRING];
    memset(errStr, '0', RRC_MAX_STRING);

    if (*errCode == RRC_RCV_PDU_MEMORY_ERROR)
    {
      *errCode = RPKI_EC_INTERNAL_ERROR;
      LOG(LEVEL_ERROR, "Not enough memory!");      
    }
    
    switch (*errCode)
    {
      case RPKI_EC_CORRUPT_DATA:
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_CORRUPT_DATA);
        break;
      case RPKI_EC_NO_DATA_AVAILABLE:
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_INTERNAL_ERROR);
        break;
      case RPKI_EC_INVALID_REQUEST:
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_INVALID_REQUEST);
        break;
      case RPKI_EC_UNSUPPORTED_PROT_VER:
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_UNSUPPORTED_PROT_VER);
        break;
      case RPKI_EC_UNSUPPORTED_PDU:
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_UNSUPPORTED_PDU);
        break;
      case RPKI_EC_UNKNOWN_WITHDRAWL:
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_UNKNOWN_WITHDRAWL);
        break;
      case RPKI_EC_DUPLICATE_ANNOUNCEMENT:
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_DUPLICATE_ANNOUNCEMENT);
        break;
      case RPKI_EC_UNEXPECTED_PROTOCOL_VERSION:
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_UNEXPECTED_PROTOCOL_VERSION);
        break;
      case RPKI_EC_RESERVED:
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_RESERVED);
        break;        
      case RPKI_EC_INTERNAL_ERROR:
      default:
        *errCode = RPKI_EC_INTERNAL_ERROR;
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_INTERNAL_ERROR);
        break;
    }
        
    switch (*errCode)
    {
      case RPKI_EC_CORRUPT_DATA:
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_CORRUPT_DATA);
        break;
      case RPKI_EC_NO_DATA_AVAILABLE:
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_INTERNAL_ERROR);
        break;
      case RPKI_EC_INVALID_REQUEST:
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_INVALID_REQUEST);
        break;
      case RPKI_EC_UNSUPPORTED_PROT_VER:
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_UNSUPPORTED_PROT_VER);
        break;
      case RPKI_EC_UNSUPPORTED_PDU:
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_UNSUPPORTED_PDU);
        break;
      case RPKI_EC_UNKNOWN_WITHDRAWL:
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_UNKNOWN_WITHDRAWL);
        break;
      case RPKI_EC_DUPLICATE_ANNOUNCEMENT:
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_DUPLICATE_ANNOUNCEMENT);
        break;
      case RPKI_EC_UNEXPECTED_PROTOCOL_VERSION:
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_UNEXPECTED_PROTOCOL_VERSION);
        break;
      case RPKI_EC_RESERVED:
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_RESERVED);
        break;        
      case RPKI_EC_INTERNAL_ERROR:
      default:
        *errCode = RPKI_EC_INTERNAL_ERROR;
        snprintf (errStr, RRC_MAX_STRING, "%s", RPKI_ESTR_INTERNAL_ERROR);
        break;
    }
    
    sendErrorReport(client, *errCode, (uint8_t*)hdr, pduLen, 
                    errStr, strlen(errStr));
  }
  
  // Release the buffer again.
  free(byteBuffer);
  byteBuffer = NULL;
  
  return *errCode == RRC_RCV_PDU_NO_ERROR;
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
  int               errCode;
  // Counter for errors 
  int errCount = 0;

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
      // is either lost, closed, or the end of data is received (single request)
      // Modified call with 0.5.0.0 to use variable as second parameter rather
      // than false
      receivePDUs(client, client->stopAfterEndOfData, &errCode, true);      
      // Check the expected response, 
      switch (client->lastRecv)
      {
        case PDU_TYPE_CACHE_RESPONSE:
          // Now, keep on going and receive data.
          receivePDUs(client, client->stopAfterEndOfData, &errCode, false);

          if (client->stopAfterEndOfData)
          {
            client->stop = true;
          }
          break;
        case PDU_TYPE_ERROR_REPORT:
          // Most likely an error regarding the version number, keep on going if 
          // we can downgrade the version (and only if)
          LOG(LEVEL_DEBUG, "Version conflict registered. ");
          switch (errCode)
          {
            case RPKI_EC_UNSUPPORTED_PROT_VER:
            case RPKI_EC_UNEXPECTED_PROTOCOL_VERSION:
              // Stop if client was not allowed to downgrade.
              client->stop = !client->params->allowDowngrade;
              break;
            default:
              LOG(LEVEL_DEBUG, "PDU receive error[%u]!", errCode);
              errCount++;
              if (errCount >= RRC_MAX_ERRCT)
              {
                LOG(LEVEL_ERROR, "Experienced %u errors during receiving PDU's"
                                 ", Stop client!", errCount);
                client->stop = true;
              }
          }
          break;
        default:
          RAISE_ERROR("Unexpected protocol behavior, type=%u!", 
                      client->lastRecv);
          client->stop = true;
      }
    }

    // Test if the connection stopped!
    if (client->stop)
    {
      LOG(LEVEL_DEBUG, HDR "Client Connection was stopped!", pthread_self());
      close((uintptr_t)getClientFDPtr(&client->clSock));
      break;
    }

    // Should we try to reconnect
    sec = (client->params->connectionCallback == NULL)
              ? -1
              : client->params->connectionCallback(client->user);


    if (sec == -1)
    { // Stop trying to re-establish the connection
      client->stop = true;
      close((uintptr_t)getClientFDPtr(&client->clSock));
      pthread_exit((void*)1);
    }

    if (client->sessionIDChanged)
    {
      // prepare some settings to allow a fresh start
      client->startup = true;
    }

    // Now try to reconnect if not stopped.
    client->clSock.reconnect = !client->stop;
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
        receivePDUs(client, true, &errCode, false);
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
  // BZ1239: For now use hard coded value 1. This ID is used for registering 
  // keys and 0 is reserved within SCA.
  return 1;
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

  self->routerClientID   = createRouterClientID(self);
  self->version          = params->version;

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
  switch (s)
  {
    case 0: // No error at all
    case 3: // No such process
      break;
    default:
      handle_error_en(s, "pthread_join");
      break;
  }
}

/**
 * Wrapper for function sendNum. This wrapper does call the debugCallback in 
 * case it is specified. The call will only be done if the call to sendNum was
 * successful.
 *  
 * @param client The RPKI Router Client (this)
 * @param hdr The header to be send.
 * 
 * @return true if the packed was send, otherwise false.
 * 
 * @since 0.5.0.3 
 */
static bool _sendPDU(RPKIRouterClient* client, RPKICommonHeader* hdr)
{
  bool succ = sendNum(getClientFDPtr(&client->clSock), hdr, ntohl(hdr->length)); 
  if (succ)
  {
    client->lastSent = hdr->type;
  }
  if (client->params->debugSendCallback != NULL)
  {
    printf("Sending packet:");
    if (succ)
    {
      printf("\n");
      client->params->debugSendCallback(client, hdr);
    }
    else
    {
      printf (" failed!\n");
    }
  }
  return succ;
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

    hdr.version  = self->version;
    hdr.type     = PDU_TYPE_RESET_QUERY;
    hdr.reserved = 0x0000;
    hdr.length   = htonl(sizeof(RPKIResetQueryHeader));

    lockMutex(&self->writeMutex);

    succ = _sendPDU (self, (RPKICommonHeader*)&hdr);
    if (!succ)
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
 * Send an error report to the server.
 * 
 * @param self the instance of rpki router client.
 * @param errCode The error code to be used.
 * @param erronPDU The PDU containing the error.
 * @param lenErronPDU Length of the erroneous PDU (host format).
 * @param errText The administrative text message that accompanies the error.
 * @param lenErrText Th length of the text string (host format).
 * 
 * @return true if the packet could be send successfully.
 * 
 * @since 0.5.0.3
 */
bool sendErrorReport(RPKIRouterClient* self, u_int16_t errCode,
                     u_int8_t* erronPDU, u_int32_t lenErronPDU,
                     char* errText, u_int32_t lenErrText)
{
  u_int32_t totalLen = sizeof(RPKIErrorReportHeader) + lenErronPDU
                       + (4 + lenErrText);  // 4 byte for length field + text
  bool  succ = false;

  if (self->clSock.clientFD != -1)
  {
    u_int8_t* buff = malloc(totalLen);
    memset(buff, 0, totalLen);
    u_int32_t* hdr_len_err_txt = NULL;
    RPKIErrorReportHeader* hdr = (RPKIErrorReportHeader*)buff;
    hdr->version      = self->version;
    hdr->type         = PDU_TYPE_ERROR_REPORT;
    hdr->error_number = htons(errCode);
    hdr->length       = htonl(totalLen);
    hdr->len_enc_pdu  = htonl(lenErronPDU);
    // Move buffer to position of error PDU
    buff += sizeof(RPKIErrorReportHeader);
    memcpy(buff, erronPDU, lenErronPDU);
    buff += lenErronPDU;
    hdr_len_err_txt  = (u_int32_t*)buff;
    *hdr_len_err_txt = htonl(lenErrText);
    buff += sizeof(u_int32_t);
    memcpy(buff, errText, lenErrText); 
    // Set buffer back to start of header; 
    buff = (u_int8_t*)hdr;

    lockMutex(&self->writeMutex);
    LOG(LEVEL_DEBUG, HDR "Sending Serial Query...\n", pthread_self());

    succ  = _sendPDU(self, (RPKICommonHeader*)hdr); 
    unlockMutex(&self->writeMutex);

    memset(buff, 0, totalLen);
    free(buff);

    buff = NULL;
    hdr  = NULL;
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
  bool  succ = false;

  if (self->clSock.clientFD != -1)
  {
    hdr.version   = self->version;
    hdr.type      = PDU_TYPE_SERIAL_QUERY;
    hdr.sessionID = self->sessionID;
    hdr.length    = htonl(sizeof(RPKISerialQueryHeader));
    hdr.serial    = self->serial;

    lockMutex(&self->writeMutex);
    LOG(LEVEL_DEBUG, HDR "Sending Serial Query...\n", pthread_self());

    succ  = _sendPDU(self, (RPKICommonHeader*)&hdr);
    unlockMutex(&self->writeMutex);
  }

  return succ;
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


bool handleReceiveAspaPdu(RPKIRouterClient* client, RPKIASPAHeader* hdr, 
                          uint32_t pduLen)
{
  // 
  // figure out the numbers how many provider ASes are in the received  pdu
  //
  //     1. parsing
  //     2. memcpy for providerASNs if providerAsCount is greater than 1
  //     3. inside hdr, there might have multiple provider asns
  //

  uint32_t customerAsn = ntohl(hdr->customer_asn);
  uint16_t providerAsCount = ntohs(hdr->provider_as_count);
  uint32_t *providerAsns;
  uint8_t  flags = hdr->flags;

  uint8_t announce       = flags & 0x01; // bit 0: 1 == announce, 0 == withdraw
  uint8_t addrFamilyType = flags & 0x02; // bit 1: AFI (IPv4 == 0, IPv6 == 1)

  uint8_t *byteHdr = (uint8_t*)hdr;
  uint32_t *startp_providerAsns = (uint32_t*)(byteHdr + sizeof(RPKIASPAHeader));
  
  // Index counter for loops
  int idx = 0;

  providerAsns = (uint32_t*)calloc(providerAsCount, sizeof(uint32_t));

  LOG(LEVEL_INFO, "---" FILE_LINE_INFO " receive ASPA Object PDU from rpki cache ---");
  LOG(LEVEL_INFO, "customer asn: %d", customerAsn);
  LOG(LEVEL_INFO, "provider as count: %d", providerAsCount);

  // 3. inside hdr, there might have multiple provider ASNs
  for (idx = 0; idx < providerAsCount; idx++)
  {
    providerAsns[idx] = ntohl(startp_providerAsns[idx]);
    LOG(LEVEL_INFO, "provider asn[%d]: %d", idx, providerAsns[idx]);
  }

  LOG(LEVEL_INFO, "afi : %d (0 == AFI_IP, 1 == AFI_IP6)", addrFamilyType);
  LOG(LEVEL_INFO, "flag: %s ", announce == 1 ? "Announce": 
                              (announce == 0 ? "Withdraw": "None"));

  // this calls 'handleAspaPdu()' in rpki_handler module
  client->params->cbHandleAspaPdu(client->user, customerAsn, providerAsCount, 
                                  providerAsns, addrFamilyType, announce); 
  return true;
}


