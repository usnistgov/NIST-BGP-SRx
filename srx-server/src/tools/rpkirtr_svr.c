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
 * An RPKI/Router Protocol server test harness. This Software simulates an
 * RPKI Validation Cache.
 *
 *  * - "Serial Notify"s are send out no more than once a minute
 *   (see SERVICE_TIMER_INTERVAL)
 * - Removed, i.e. withdrawn routes are kept for one hour
 *   (see CACHE_EXPIRATION_INTERVAL)
 *
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/10 - oborchert
 *            * Added parentheses around comparison in operand & in sendPrefixes
 *            * Removed unused sessionID from function readPrefixData
 * 0.3.0.2  - 2013/07/08 - oborchert
 *            * Added an ID for each command to allow acing on them after they
 *              are executed.
 *            * Allows the exit/quit/\q command to be executed from within a
 *              script
 *            * Allowed to end the program when a script is passed and the 
 *              last command is quit BZ# 351
 *            * Changed all command processing methods to return the proper
 *              command id CMD_ID_<command>
 * 0.3.0    - 2013/01/28 - oborchert
 *            * Update to be compliant to draft-ietf-sidr-rpki-rtr.26. This 
 *              update does not include the secure protocol section. The 
 *              protocol will still use un-encrypted plain TCP
 * 0.2.2    - 2012/12/28 - oborchert
 *            * Modified update 0.2.1. Fix BZ165 caused no ROA to be 
 *              installed into the cache. Applied new fix.
 * 0.2.1    - 2012/07/25 - kyehwan
 *            * Fixed segmentation fault while adding ROAs.
 * 0.2.0    - 2011/01/07 - oborchert
 *            * Changelog added with version 0.2.0 and date 2011/01/07
 *            * Version tag added
 *            * M0000713: Cleaned console input string with trim()
 *            * Added capability of adding single "white list" entries through
 *            * console (add ...).
 *            * Added version information.
 *            * Added addNow and removeNow to bypass the 60 seconds delay timer.
 *            * Rewritten code for prototype 2.
 *            * following draft-ietf-sidr-rpki-rtr.10
 * 0.1.0    - 2010/06/02 - pgleichm
 *            * Code Created Prototype 1
              * following draft-ymbk-rtr-protocol-05
 * -----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <uthash.h>
#include <unistd.h>
#include "server/srx_server.h"
#include "shared/rpki_router.h"
#include "util/debug.h"
#include "util/log.h"
#include "util/math.h"
#include "util/prefix.h"
#include "util/rwlock.h"
#include "util/mutex.h"
#include "util/server_socket.h"
#include "util/slist.h"
#include "util/socket.h"
#include "util/str.h"
#include "util/timer.h"
#include "util/prefix.h"

typedef struct {
  uint32_t  serial;     // Current serial number of the entry
  uint32_t  prevSerial; // Previous serial number (before being withdrawn)
  time_t    expires;    // When this entry expires, i.e. should be deleted
  bool      isV6;       // IPv6 prefix

  /** Prefix (v4, v6) - stored in network Byte order */
  uint8_t   flags;           // Might not be needed.
  uint8_t   prefixLength;    // Length of the prefix.
  uint8_t   prefixMaxLength; // Max length of prefix.
  uint32_t  asNumber;        // AS number.
  union {
    IPv4Address v4;          // V4 address.
    IPv6Address v6;          // V6 address.
  } address;
} ValCacheEntry;

/** Single client */
typedef struct {
  int             fd; ///< Socket - but also the hash identifier
  UT_hash_handle  hh; ///< Hash handle
} CacheClient;

#define CMD_ID_QUIT       0
#define CMD_ID_UNKNOWN    1
#define CMD_ID_VERBOSE    2
#define CMD_ID_CACHE      3
#define CMD_ID_VERSION    4
#define CMD_ID_HELP       5
#define CMD_ID_CREDITS    6
#define CMD_ID_SESSID     7
#define CMD_ID_EMPTY      8
#define CMD_ID_ADD        9
#define CMD_ID_ADDNOW    10
#define CMD_ID_REMOVE    11
#define CMD_ID_REMOVENOW 12
#define CMD_ID_ERROR     13
#define CMD_ID_NOTIFY    14
#define CMD_ID_RESET     15
#define CMD_ID_CLIENTS   16
#define CMD_ID_RUN       17
#define CMD_ID_SLEEP     18

/*----------
 * Constants
 */
const char* RPKI_RTR_SRV_VER          ="0.3.0.2";
const char* RPKI_RTR_SRV_NAME         ="RPKI Cache Test Harness";
const char* HISTORY_FILENAME          = ".rpkirtr_svr.history";
const char* USER_PROMPT               = ">> ";
const int   SERVICE_TIMER_INTERVAL    = 60;   ///< Service interval (sec)
const int   CACHE_EXPIRATION_INTERVAL = 3600; ///< Sec. to keep removed entries

/*-----------------
 * Global variables
 */
struct {
  SList     entries;
  RWLock    lock;
  uint32_t  maxSerial;
  uint32_t  minPSExpired, maxSExpired;
} cache;

struct {
  int   timer;
  bool  notify;
} service;

/** Reference to the server socket. */
ServerSocket svrSocket;
/** A list of cache clients */
CacheClient* clients   = NULL;
/** Verbose mode on or off */
bool         verbose   = true;
/** the current cache session id value */
uint16_t     sessionID = 0;

/*---------------
 * Utility macros
 */

#define OPROMPT() \
  puts(USER_PROMPT); \
  fflush(stdout)

#define OUTPUTF(LAST, FMT, ...) \
  if (verbose) {                 \
    putc('\r', stdout);          \
    printf(FMT, ## __VA_ARGS__); \
    if (LAST) {                  \
      OPROMPT();                 \
    }                            \
  }

#define ERRORF(FMT, ...) \
  printf(FMT, ## __VA_ARGS__); \
  OPROMPT()

////////////////////////////////////////////////////////////////////////////////
// CLIENT SERVER COMMUNICATION AND UTILITIES
////////////////////////////////////////////////////////////////////////////////
/**
 * This function checks the validity of the requested serial number. It might
 * be that the cache performed a serial number overflow. This means the serial
 * number reached its natural max and got rolled over to zero. In this case the
 * cache_min number could be greater than cache_max.
 *
 * @param cache_min The minimum serial number (oldest one)
 * @param cache_max The latest given serial number (newest one)
 * @param client_serial the serial number of the client.
 * @return
 */
bool checkSerial(uint32_t cache_min, uint32_t cache_max, uint32_t client_serial)
{
  bool result;
  if (cache_min < cache_max)
  {
    result = (client_serial >= cache_min) && (client_serial <= cache_max);
  }
  else
  {
    // check that the serial number is not located in the unused range
    // Valid serial numbers are 0..max and min...max(int) with max < min
    // Unused = [max+1...min-1]
    result = !(client_serial < cache_min) && (client_serial > cache_max);
  }
  return result;
}

/**
 * Drop the session to the session with the given file descriptor.
 * @param fdPtr The file descriptor
 *
 * @return true if the session could be dropped.
 */
bool dropSession(int* fdPtr)
{
  bool result = false;
  if (HASH_COUNT(clients) > 0)
  {
    CacheClient*  cl;

    acquireReadLock(&cache.lock);
    for (cl = clients; cl; cl = cl->hh.next)
    {
      if (&cl->fd == fdPtr)
      {
        OUTPUTF(true, "Close session to the given client\n");

        // TODO: Close session and remove it from list.

        result = true;
        break;
      }
    }
    unlockReadLock(&cache.lock);
  }

  return result;
}

/**
 * Send a PDU that contains the serial field. This method can be used to
 * send SERIAL_NOTIFY (4.1), SERIAL_QUERY (4.2), or END_OF_DATA (4.7)
 * @param fdPtr The file descriptor to be used to send the packet.
 * @param type The PDU type.
 *
 * @return
 */
bool sendPDUWithSerial(int* fdPtr, RPKIRouterPDUType type, uint32_t serial)
{
  uint8_t                pdu[sizeof(RPKISerialQueryHeader)];
  RPKISerialQueryHeader* hdr;

  // Create PDU
  hdr = (RPKISerialQueryHeader*)pdu;
  hdr->version   = RPKI_RTR_PROTOCOL_VERSION;
  hdr->type      = (uint8_t)type;
  hdr->sessionID = htons(sessionID);
  hdr->length    = htonl(sizeof(RPKISerialQueryHeader));
  hdr->serial    = htonl(serial);
  // Send
  OUTPUTF(true, "Sending an RPKI-RTR 'PDU[%u] with Serial'\n", type);
  return sendNum(fdPtr, &pdu, sizeof(RPKISerialQueryHeader));
}

/**
 * Send a CACHE RESET to the client.
 *
 * @param fdPtr the socket connection
 *
 * @return true id the packet was send successful.
 */
bool sendCacheReset(int* fdPtr)
{
  uint8_t               pdu[sizeof(RPKICacheResetHeader)];
  RPKICacheResetHeader* hdr;

  // Create PDU
  hdr = (RPKICacheResetHeader*)pdu;
  hdr->version  = RPKI_RTR_PROTOCOL_VERSION;
  hdr->type     = (uint8_t)PDU_TYPE_CACHE_RESET;
  hdr->reserved = 0;
  hdr->length   = htonl(sizeof(RPKICacheResetHeader));

  return sendNum(fdPtr, &pdu, sizeof(RPKICacheResetHeader));
}

/**
 * Send a CACHE RESPONSE to the client.
 *
 * @param fdPtr the socket connection
 *
 * @return true id the packet was send successful.
 */
bool sendCacheResponse(int* fdPtr)
{
  uint8_t                  pdu[sizeof(RPKICacheResetHeader)];
  RPKICacheResponseHeader* hdr;

  // Create PDU
  hdr = (RPKICacheResponseHeader*)pdu;
  hdr->version   = RPKI_RTR_PROTOCOL_VERSION;
  hdr->type      = (uint8_t)PDU_TYPE_CACHE_RESPONSE;
  hdr->sessionID = htons(sessionID);
  hdr->length    = htonl(sizeof(RPKICacheResetHeader));

  OUTPUTF(true, "Sending a 'Cache Response'\n");
  return sendNum(fdPtr, &pdu, sizeof(RPKICacheResetHeader));
}

/**
 * Send IP prefixes
 *
 * @param fdPtr The file descriptor
 * @param clientSerial the serial the client requested.
 * @param clientSessionID the sessionID of the client request.
 * @param isReset if set to true both clientSerial nor clientSessionID is
 *                ignored.
 */
void sendPrefixes(int* fdPtr, uint32_t clientSerial, uint16_t clientSessionID,
                  bool isReset)
{
  // No need to send the notify anymore
  service.notify = false;

  // Let no one modify the cache
  acquireReadLock(&cache.lock);

  // Send "Cache Reset" in case
  // A: The client and the cache operate on a different SESSION IDddd
  // B: The serial of the client can not be served buy the cache.
  if (!isReset && (clientSessionID != sessionID))
  { // session id is incorrect, drop this session
    dropSession(fdPtr);
  }
  else if (   !isReset
           && (checkSerial(cache.minPSExpired, cache.maxSExpired, clientSerial))
          )
  { // Serial is incorrect, send a Cache Reset
    if (!sendCacheReset(fdPtr))
    {
      ERRORF("Error: Failed to send a 'Cache Reset'\n");
    }
  }
  else
  { // Send the prefix
    // Send 'Cache Response'
    if (!sendCacheResponse(fdPtr))
    {
      ERRORF("Error: Failed to send a 'Cache Response'\n");
    }
    else
    {
      printf("Cache size = %u\n", cache.entries.size);
      if (cache.entries.size > 0) // there is always a root.
      {
        ValCacheEntry* cEntry;

        uint8_t               v4pdu[sizeof(RPKIIPv4PrefixHeader)];
        uint8_t               v6pdu[sizeof(RPKIIPv6PrefixHeader)];
        RPKIIPv4PrefixHeader* v4hdr = (RPKIIPv4PrefixHeader*)v4pdu;
        RPKIIPv6PrefixHeader* v6hdr = (RPKIIPv6PrefixHeader*)v6pdu;

        // Basic initialization of data that does NOT change
        v4hdr->version  = RPKI_RTR_PROTOCOL_VERSION;
        v4hdr->type     = PDU_TYPE_IP_V4_PREFIX;
        v4hdr->reserved = 0;
        v4hdr->length   = htonl(sizeof(RPKIIPv4PrefixHeader));

        v6hdr->version  = RPKI_RTR_PROTOCOL_VERSION;
        v6hdr->type     = PDU_TYPE_IP_V6_PREFIX;
        v6hdr->reserved = 0;
        v6hdr->length   = htonl(sizeof(RPKIIPv6PrefixHeader));

        // helps to find the next serial number
        SListNode*  currNode;
        uint32_t    serial;

        // Go through list until next available serial is found
        FOREACH_SLIST(&cache.entries, currNode)
        {
          serial = ((ValCacheEntry*)getDataOfSListNode(currNode))->serial;
          if (isReset || (serial > clientSerial))
          {
            break;
          }
        }

        // Go over each node. currNode is not null if a serial was found.
        for (; currNode; currNode = getNextNodeOfSListNode(currNode))
        {
          cEntry = (ValCacheEntry*)getDataOfSListNode(currNode);

          // Skip entries that are already expired.
          if (isReset)
          {
            if ((cEntry->flags & PREFIX_FLAG_ANNOUNCEMENT) == 0)
            {
              // This entry is NOT an announcement. Because we send a fresh set,
              // only announcements will be send, no withdrawals.
              continue;
            }
          }

          // Skip entries that were never announced to the client
          if (   (cEntry->serial != cEntry->prevSerial)
              && (cEntry->prevSerial > clientSerial))
          {
            continue;
          }

          // Send 'Prefix'
          if (!cEntry->isV6)
          {
            v4hdr->flags     = cEntry->flags;
            v4hdr->prefixLen = cEntry->prefixLength;
            v4hdr->maxLen    = cEntry->prefixMaxLength;
            v4hdr->zero      = (uint8_t)0;
            v4hdr->addr      = cEntry->address.v4;
            v4hdr->as        = cEntry->asNumber;
            OUTPUTF(false, "Sending an 'IPv4Prefix' (serial = %u)\n",
                    cEntry->serial);
            if (!sendNum(fdPtr, &v4pdu, sizeof(RPKIIPv4PrefixHeader)))
            {
              ERRORF("Error: Failed to send a 'Prefix'\n");
              break;
            }
          }
          else
          {
            v6hdr->flags     = cEntry->flags;
            v6hdr->prefixLen = cEntry->prefixLength;
            v6hdr->maxLen    = cEntry->prefixMaxLength;
            v6hdr->zero      = (uint8_t)0;
            v6hdr->addr      = cEntry->address.v6;
            v6hdr->as        = cEntry->asNumber;
            OUTPUTF(false, "Sending an 'IPv6Prefix' (serial = %u)\n",
                    cEntry->serial);
            if (!sendNum(fdPtr, &v6pdu, sizeof(RPKIIPv6PrefixHeader)))
            {
              ERRORF("Error: Failed to send a 'Prefix'\n");
              break;
            }
          }
        }
      }

      // Send 'End of Data'
      OUTPUTF(true, "Sending an 'End of Data (max. serial = %u)\n",
              cache.maxSerial);

      if (!sendPDUWithSerial(fdPtr, PDU_TYPE_END_OF_DATA, cache.maxSerial))
      {
        ERRORF("Error: Failed to send a 'End of Data'\n");
      }
    }
  }
  unlockReadLock(&cache.lock);
}

/**
 * Send a SERIAL NOTIFY to all clients of the test harness
 * 
 * @return CMD_ID_NOTIFY
 */
int sendSerialNotifyToAllClients()
{
  if (HASH_COUNT(clients) > 0)
  {
    CacheClient*  client;

    OUTPUTF(true, "Sending multiple 'Serial Notify' (max. serial = %u)\n",
            cache.maxSerial);

    acquireReadLock(&cache.lock);
    for (client = clients; client; client = client->hh.next)
    {
      if (!sendPDUWithSerial(&client->fd, PDU_TYPE_SERIAL_NOTIFY,
                             cache.maxSerial))
      {
        ERRORF("Error: Failed to send a 'Serial Notify\n");
      }
    }

    unlockReadLock(&cache.lock);
  }
  
  return CMD_ID_NOTIFY;
}

/**
 * Sends a Cache Reset message to all clients.
 * 
 * @return CMD_ID_RESET;
 */
int sendCacheResetToAllClients()
{
  if (HASH_COUNT(clients) > 0)
  {
    CacheClient*  client;

    OUTPUTF(true, "Sending 'Cache Reset' to all clients\n");

    for (client = clients; client; client = client->hh.next)
    {
      if (!sendCacheReset(&client->fd))
      {
        ERRORF("Error: Failed to send a 'Cache Reset\n");
      }
    }

    unlockReadLock(&cache.lock);
  }
  
  return CMD_ID_RESET;
}

/**
 * Send an error report to all clients.
 *
 * @param the error number to be send
 * @param data contains the error number followed by the PDU and text. The
 * character - as PDU or text generates a PDU / text length of zero.
 * @return true if it could be send.
 */
bool sendErrorReportToAllClients(uint16_t errNo, char* data)
{
  // ERROR CODE
  RPKIErrorReportHeader* hdr;
  uint32_t     length = 16; // includes the basic 8 bytes header plus 8 bytes
                            // for length fields of encapsulated PDU and msg
                            // must be extended by length of err PDU and msg
                            // text

  // Erroneous PDU
  uint8_t      errPdu[sizeof(RPKIIPv6PrefixHeader)]; // for now MAX encaps. PDU
  char*        pduTok     = NULL;
  uint16_t     pduLen     = 0;
  memset(errPdu, 0, sizeof(RPKIIPv6PrefixHeader));  // initialize with zero

  // Error Message
  char*        msgTok     = NULL;
  uint16_t     msgLen     = 0;

  // Error Message
  bool         succ = true;
  CacheClient* cl;

  // determine the error number
  if (strlen(data) == 0)
  {
    ERRORF("Parameter missing! Can not generate Error PDU!");
    return false;
  }

  // Set the pointer for the pdu and message
//  pduTok = strtok(data, " ");
//  msgTok = strtok(NULL, " "); // Only used to figure out if a message was given
                              // If so it will not be NULL

  msgTok = data;
  pduTok = strsep(&msgTok, " ");


  if (pduTok == NULL)
  {
    ERRORF("Parameter for PDU missing, either PDU specification or - !");
    return false;
  }

  if (msgTok == NULL)
  {
    ERRORF("Parameter for message text missing; either a message or - !");
    return false;
  }

  // Check if an erroneous PDU is specified and if so generate it
  if (*pduTok != '-')
  { // A PDU is specified, add it and create the proper length
    RPKICommonHeader* chdr = (RPKICommonHeader*)errPdu;
    RPKISerialNotifyHeader* shdr;
    RPKIIPv4PrefixHeader* v4hdr;
    RPKIIPv6PrefixHeader* v6hdr;

    chdr->version = (uint8_t)atoi(strtok(pduTok, ","));
    chdr->type    = (uint8_t)atoi(strtok(NULL, ","));
    chdr->mixed   = htons((uint16_t)atoi(strtok(NULL, ",")));
    pduLen        = (uint32_t)atol(strtok(NULL, ","));
    chdr->length  = htonl(pduLen);

    switch (chdr->type)
    {
      case PDU_TYPE_RESET_QUERY:
      case PDU_TYPE_CACHE_RESPONSE:
      case PDU_TYPE_CACHE_RESET:
        break;
      case PDU_TYPE_SERIAL_NOTIFY:
      case PDU_TYPE_SERIAL_QUERY:
      case PDU_TYPE_END_OF_DATA:
        shdr = (RPKISerialNotifyHeader*)errPdu;
        shdr->serial = htonl((uint32_t)atol(strtok(NULL, ",")));
        break;
      case PDU_TYPE_IP_V4_PREFIX:
      case PDU_TYPE_IP_V6_PREFIX:
        v4hdr = (RPKIIPv4PrefixHeader*)errPdu;
        v6hdr = (RPKIIPv6PrefixHeader*)errPdu;
        IPv4Address v4addr;
        IPv6Address v6addr;
        // Here and below V4 and V6 share the same data structure. we fill v4
        // and V6 will be fileld as well.
        v4hdr->flags     = (uint8_t)atoi(strtok(NULL, ","));
        v4hdr->prefixLen = (uint8_t)atoi(strtok(NULL, ","));
        v4hdr->maxLen    = (uint8_t)atoi(strtok(NULL, ","));
        v4hdr->zero      = (uint8_t)atoi(strtok(NULL, ","));
        if (chdr->type == PDU_TYPE_IP_V4_PREFIX)
        {
          strToIPv4Address(strtok(NULL, ","), &v4addr);
          v4hdr->addr = v4addr;
          v4hdr->as   = htonl((uint32_t)atol(strtok(NULL, ",")));
        }
        else
        {
          strToIPv6Address(strtok(NULL, ","), &v6addr);
          v6hdr->addr = v6addr;
          v6hdr->as   = htonl((uint32_t)atol(strtok(NULL, ",")));
        }
        break;
      case PDU_TYPE_ERROR_REPORT:
      case PDU_TYPE_RESERVED:
        // Do Nothing here, leave as is
        break;
    }
  }

  // Now add the length of the error pdu.
  length += pduLen;

  // Check if a messgae is provided
  if (*msgTok != '-')
  {
    // increase the packet length by the message itself.
    msgLen = strlen(msgTok);
    length += msgLen;
  }

  uint8_t  pdu[length];
  uint32_t posPDU = 0;
  uint32_t posData = 0;
  memset(pdu, 0, length);
  hdr = (RPKIErrorReportHeader*)pdu;
  hdr->version      = RPKI_RTR_PROTOCOL_VERSION;
  hdr->type         = PDU_TYPE_ERROR_REPORT;
  hdr->error_number = htons(errNo);
  hdr->length       = htonl(length); // Length of complete PDU
  hdr->len_enc_pdu  = htonl(pduLen); // length of erroneous PDU
  // Fill the error PDU into the PDU
  for (posData = 0, posPDU=12; posData < pduLen; posPDU++, posData++)
  {
    pdu[posPDU] = errPdu[posData];
  }

  // Fill Text
  uint32_t msgLenField = htonl(msgLen);
  pdu[posPDU++] = (uint8_t)(msgLenField & 0xff);;
  pdu[posPDU++] = (uint8_t)(msgLenField >>  8 & 0xff);;
  pdu[posPDU++] = (uint8_t)(msgLenField >> 16 & 0xff);;
  pdu[posPDU++] = (uint8_t)(msgLenField >> 24 & 0xff);

  for(posData = 0; posData < msgLen; posData++)
  {
    pdu[posPDU++] = (uint8_t)msgTok[posData];
  }

  // Send
  if (HASH_COUNT(clients) > 0)
  {
    OUTPUTF(true, "Sending multiple 'Error Report' (Error = %hhu)\n", errNo);

    for (cl = clients; cl; cl = cl->hh.next)
    {
      if (!sendNum(&cl->fd, &pdu, length))
      {
        ERRORF("Error: Failed to send an 'Error Report'\n");
        succ = false;
        break;
      }
    }
  }

  return succ;
}

/**
 * This method is used to print the given error report.
 *
 * @param errNo The number of the error.
 * @param data The data of the report. (It's the pdy minus the first 8 byrtes.
 * @param dataLen the length of the report data.
 * @return
 */
bool printErrorReport(uint8_t errNo, void* data, uint32_t dataLen)
{
  uint32_t len;

  // Here the data len do mess the first 8 bytes of the PDU. They were read in
  // the common header.
  OUTPUTF(false, "Error report - error number: %hhu\n", errNo);

  // Encapsulated PDU
  len = ntohl(*((uint32_t*)data));
  if (len > 0)
  {
    if (len > dataLen)
    {
      ERRORF("Error: Not enough data (found: %u, expected: %u)\n",
                      dataLen, len);
      return false;
    }

    OUTPUTF(false, "Erroneous PDU:\n");
    dumpHex(stderr, data + 4, len);

    data += len + 4;
    dataLen -= len + 4;
  }

  // Error message
  if (dataLen < 4)
  {
    ERRORF("Error: 'Error Text Length' is missing\n");
    return false;
  }
  len = ntohl(*((uint32_t*)data));
  if (len > 0)
  {
    if (len > dataLen)
    {
      ERRORF("Error: Not enough text (found: %u, expected: %u\n",
                      dataLen, len);
      return false;
    }
    OUTPUTF(true, "Message: '%*s'\n", len, (char*)(data + 4));
  }

  return true;
}

// ClientConnectionAccepted
/**
 * Handle the data received from the client.
 *
 * @param svrSock The socket through which the data is received.
 * @param sock
 * @param user
 */
void handleClient(ServerSocket* svrSock, int sock, void* user)
{
  time_t           lastReq, diffReq;
  RPKICommonHeader hdr;
  uint32_t         remainingDataLentgh;
  void*            buf;

  // Process client requests, store the current time
  lastReq = time(NULL);

  // read the beginning of the header to see how many bytes are actually needed
  while (recvNum(&sock, &hdr, sizeof(RPKICommonHeader)))
  {
    // determine the remaining data that needs to be received - if any
    remainingDataLentgh = ntohl(hdr.length) - sizeof(RPKICommonHeader);

    if (remainingDataLentgh > 0)
    {
      // allocate a buffer with the correct size to hold the remaining data
      buf = malloc(remainingDataLentgh);
      if (buf == NULL)
      {
        ERRORF("Error: Not enough memory to receive the data\n");
        close(sock);
        break;
      }

      // Read the remaining data
      if (!recvNum(&sock, buf, remainingDataLentgh))
      {
        ERRORF("Error: Failed to receive the data\n");
        close(sock);
        break;
      }
    }
    else
    {
      buf = NULL;
    }

    // Time since the last request
    diffReq = lastReq - time(NULL);

    printf ("Received Data From Client...[%i]\n", hdr.type);

    // Action depending on the type
    switch ((RPKIRouterPDUType)hdr.type)
    {
      case PDU_TYPE_SERIAL_QUERY:
        OUTPUTF(true, "[+%lds] Received a 'Serial Query'\n", diffReq);
        uint32_t serial;
        uint16_t sessionID;
        if (remainingDataLentgh != 4)
        {
          ERRORF("Error: Invalid 'Serial Query'\n");
          dumpHex(stderr, buf, remainingDataLentgh);
        }
        else
        {
          serial = ntohl(*((uint32_t*)buf));
          sessionID  = ntohs(hdr.mixed);
          sendPrefixes(&sock, serial, sessionID, false);
        }
        break;

      case PDU_TYPE_RESET_QUERY:
        OUTPUTF(true, "[+%lds] Received a 'Reset Query'\n", diffReq);
        sendPrefixes(&sock, 0, sessionID, true);
        break;

      case PDU_TYPE_ERROR_REPORT:
        printErrorReport(ntohs(hdr.mixed), buf, remainingDataLentgh);
        break;

      case PDU_TYPE_RESERVED:
        
      default:
        ERRORF("Error: Invalid PDU type: %hhu\n", hdr.type);
    }

    free(buf);

    // Time after processing the request
    lastReq = time(NULL);
  }
}

bool handleStatus(ServerSocket* svrSock, ServerClient* client, int fd,
                  bool connected, void* user)
{
  CacheClient* ccl;

  if (connected)
  {
    ccl = (CacheClient*)malloc(sizeof(CacheClient));
    if (ccl == NULL)
    {
      ERRORF("Error: Out of memory - rejecting client\n");
      return false;
    }
    ccl->fd = fd;
    HASH_ADD_INT(clients, fd, ccl);
  }
  else
  {
    HASH_FIND_INT(clients, &fd, ccl);
    if (ccl == NULL)
    {
      ERRORF("Error: Unknown client\n");
    }
    HASH_DEL(clients, ccl);
  }
  return true;
}


void* handleServerRunLoop(void* _unused)
{
  LOG (LEVEL_DEBUG, "([0x%08X]) > RPKI Server Thread started!", pthread_self());      
  
  runServerLoop (&svrSocket, MODE_CUSTOM_CALLBACK,
                 handleClient, handleStatus, NULL);
  
  LOG (LEVEL_DEBUG, "([0x%08X]) < RPKI Server Thread stopped!", pthread_self());      
  
  pthread_exit(0);
}

////////////////////////////////////////////////////////////////////////////////
// Read the data from the file.
////////////////////////////////////////////////////////////////////////////////

/*----------------------
 * Prefix file functions
 */

int stripLineBreak(char* str)
{
  int pos = strlen(str) - 1;

  while (pos >= 0)
  {
    if ((str[pos] != 0xA) && (str[pos] != 0xD))
    {
      break;
    }
    str[pos--] = '\0';
  }
  return pos + 1;
}

/**
 * Read prefix data from a given file or from command line. An error while
 * reading from command line will result in skipping the line and posting a
 * WARNING. An error from command line results in abort of the operation.
 *
 * @param arg The filename or the data provided via command line.
 * @param dest
 * @param serial The serial number of the prefix announcement(s).
 * @param isFile determine if the argument given specifies a file or input data.
 *
 * @return true if the prefix(es) could be send.
 */
bool readPrefixData(const char* arg, SList* dest, uint32_t serial, bool isFile)
{
  #define LINE_BUF_SIZE 80
  #define NUM_FIELDS    3  // prefix max_len as

  FILE*          fh;
  int            lineNo;
  char           buf[LINE_BUF_SIZE];
  char*          bptr;
  int            idx;
  char*          fields[NUM_FIELDS];
  IPPrefix       prefix;
  uint32_t       maxLen;
  uint32_t       oas;
  ValCacheEntry* cEntry;
  bool           goOn=true;

  #define SKIP_IF(COND, MSG, VAR) \
    if (COND)                     \
    {                             \
      ERRORF("Warning: " MSG " (line %d): '%s'\n", lineNo, VAR); \
      continue;                   \
    }

  if (isFile)
  {
    fh = fopen(arg, "rt");
    if (fh == NULL)
    {
      ERRORF("Error: Failed to open '%s'\n", arg);
      return false;
    }
  }
  else
  {
    if (arg == NULL)
    {
      ERRORF("Error: Data missing: <prefix> <maxlen> <as>\n");
      return false;
    }
  }

  // Read line by line
  for (; goOn; lineNo++)
  {
    if (isFile)
    {
      goOn = fgets(buf, LINE_BUF_SIZE, fh);
      if (!goOn)
      {
        continue;
      }
    }
    else
    {
      // Stop after the one line.
      goOn = false;
      // here filename is not the name of the file, it contains the one and only
      // line of data. (Called by addPrefix);
      strncpy(buf, arg, LINE_BUF_SIZE);
    }

    // Skip comments
    if (buf[0] == '#')
    {
      continue;
    }

    // Make sure the line is not empty
    if (stripLineBreak(buf) == 0)
    {
      continue;
    }

    // Put into fields for later processing
    bptr = buf;
    idx  = 0;
    // FIX BZ164
    bool fieldIsNull = false;
    do
    {
      fields[idx] = strsep(&bptr, " \t");
      fieldIsNull = fields[idx] == NULL;
      
      if (fieldIsNull)
      {
        if (idx < NUM_FIELDS)
        {
          if (isFile)
          {
            ERRORF("ERROR: Line[%d] Parameters missing : '%s'\n", lineNo, buf);
          }
          else
          {
            ERRORF("ERROR: Parameters missing : '%s'\n"
                   "try Help for more information\n", buf);
          }
          return false;
        }
      } 
      else if (fields[idx][0] == 0)
      {
        // To the else if block above:
        // It can happen that the buffer contains "      a.b.c.d/d   x   y   "
        // in this case the read field "fields[idx][0]" is zero for each list of
        // blanks. In this case read the next element in the buffer and don't 
        // increase the idx, the field has to be refilled.
        continue;
      }
      
      idx++;
    } while (idx < NUM_FIELDS && !fieldIsNull);

    // Parse fields
    SKIP_IF(!strToIPPrefix(fields[0], &prefix),
            "Invalid IP Prefix", fields[0]);

    maxLen = strtoul(fields[1], NULL, 10);
    SKIP_IF(!BETWEEN(maxLen, 0, GET_MAX_PREFIX_LEN(prefix.ip)),
            "Invalid max. length", fields[1]);

    oas = strtoul(fields[2], NULL, 10);
    SKIP_IF(oas == 0,
            "Invalid origin AS", fields[2]);

    // Append
    cEntry = (ValCacheEntry*)appendToSList(dest, sizeof(ValCacheEntry));
    if (cEntry == NULL)
    {
      fclose(fh);
      return false;
    }
    cEntry->serial  = cEntry->prevSerial = serial++;
    cEntry->expires = 0;

    cEntry->flags           = PREFIX_FLAG_ANNOUNCEMENT;
    cEntry->prefixLength    = prefix.length;
    cEntry->prefixMaxLength = (uint8_t)maxLen;

    if (prefix.ip.version == 4)
    {
      cEntry->isV6 = false;
      memcpy(&cEntry->address.v4.in_addr, &prefix.ip.addr, 4);
      cEntry->asNumber = htonl(oas);

    }
    else
    {
      cEntry->isV6 = true;
      memcpy(&cEntry->address.v6.in_addr, &prefix.ip.addr, 16);
      cEntry->asNumber = htonl(oas);
    }
  }

  if (isFile)
  {
    fclose(fh);
  }
  return true;
}

/**
 * Display or generate a session id.
 *
 * @param argument if NULL display the current cache session id otherwise use
 *                 value to generate new once.
 * 
 * @return CMD_ID_SESSID
 */
int processSessionID(char* argument)
{
  if (argument == NULL)
  {
    printf("Current SESSION ID: %d (0x%04X)\n", sessionID, sessionID);
  }
  else
  {
    uint16_t newSessionID = atoi(argument);
    if (newSessionID == 0) // it is zero for both, 0 as well as text
    {
      if (strcmp(argument, "reset") == 0)
      {
        printf ("Reset session id to 0\n");
        processSessionID(NULL);
        sendSerialNotifyToAllClients();
      }
      else
      {
        printf("ERROR: New SESSION ID '%s' is not a number!\n", argument);
      }
    }
    else
    {
      if (newSessionID < sessionID)
      {
        printf("ERROR: New SESSION ID %d must be greater than current SESSION "
               "IS %d!\n", newSessionID, sessionID);
      }
      else
      {
        // initiate a serial request from the clients. This will result in a 
        // session id error.
        sessionID = newSessionID;
        processSessionID(NULL);
        sendSerialNotifyToAllClients();
      }
    }
  }
  
  return CMD_ID_SESSID;
}

/*----------------
 * Single commands
 */

/**
 * Display the version information.
 * 
 * @return CMD_ID_VERSION
 */
int showVersion()
{
  printf("%s Version %s\n", RPKI_RTR_SRV_NAME, RPKI_RTR_SRV_VER);
  
  return CMD_ID_VERSION;
}


/**
 * Display the command help
 * 
 * @return CMD_ID_HELP
 */
int showHelp(char* command)
{
  if (command == NULL)
  {
    showVersion();
    printf("\nDisplay Commands:\n"
           "-----------------\n"
           "  - verbose            : Turns verbose output on or off\n"
           "  - cache              : Lists the current cache's content\n"
           "  - version            : Displays the version of this tool!\n"
           "  - sessionID          : Display the current session id\n"
           "  - help [command]     : Display this screen or detailed help for\n"
           "                         the given command!\n"
           "  - credits            : Display credits information!\n"
           "\n"
           "Cache Commands:\n"
           "-----------------\n"
           "  - empty              : Empties the cache\n"
           "  - sessionID <number> : Generates a new session id.\n"
           "  - append <filename>  : Appends a prefix file's content to the "
                                     "cache\n"
           "  - add <prefix> <maxlen> <as> : \n"
           "                         Manually add a whitelist entry\n"
           "  - addNow <prefix> <maxlen> <as> :\n"
           "                         Manually add a whitelist entry without\n"
           "                         any delay!\n"
           "  - remove <index> [end-index] :\n"
           "                         Remove one or more cache entries\n"
           "  - removeNow <index> [end-index] :\n"
           "                         Remove one or more cache entries without\n"
           "                         any delay!\n"
           "  - error <code> <pdu|-> <message|-> :\n"
           "                         Issues an error report. The pdu contains\n"
           "                         all real fields comma separated.\n"
           "  - notify               Send a SERIAL NOTIFY to all clients.\n"
           "  - reset                Send a CACHE RESET to all clients.\n"

           "\n"
           "Program Commands:\n"
           "-----------------\n"
           "  - quit, exit, \\q   : Quits the loop and terminates the server\n"
           "                        This command is allowed within scripts\n"
           "                        but only as the very last command!\n"
           "                        Otherwise it will be ignored!\n"
           "  - clients           : Lists all clients\n"
           "  - run <filename>    : Executes a file line-by-line\n"
           "  - sleep <seconds>   : Pauses execution\n"
           "\n\n");
  }
  else
  {
    #define SHOW_CMD_HLP(CMD, TXT)      \
        printf ("\nCommand: " CMD ":\n"); \
        printf ("-----------------------------------------------------\n"); \
        printf (TXT "\n\n");

    if (strcmp(command, "empty")==0)
    {
      SHOW_CMD_HLP("empty",
                   "This command cleans the complete cache. No message will be"
                   " send to the attached clients."
        );
    }
    else if (strcmp(command, "sessionID")==0)
    {
      SHOW_CMD_HLP("sessionID <number>",
                   "Depending if a number is provided or not the function "
                   "performs a different function.\n"
                   "- If no number is provided, the current cache sessionID "
                   "value will be displayed.\n"
                   "- If a number os provided the cache changes its internal "
                   "cache session id to the given number. In this "
                   "implementation the number can only grow. Once the number "
                   "is changed, a SERIAL NOTIFY message will be send to all "
                   "clients attached.\n"
                   "This might result in an earlier SERIAL REQUEST than the "
                   "client would otherwise do. As result a CACHE SESSION ID "
                   "error will occur on the client side. This SHOULD result in "
                   "a RESET QUERY from the client."
        );
    }
    else if (strcmp(command, "notify")==0)
    {
      SHOW_CMD_HLP("notify",
                   "Send a SERIAL NOTIFY to all clients right away."
      );
    }
    else if (strcmp(command, "error")==0)
    {
      SHOW_CMD_HLP("error <code> <pdu|-> <message|->",
                   "  code    ::= an error code according to the draft "
                                  "\"10. Error Codes\"\n"
                   "              0: Corrupt Data (fatal)\n"
                   "              1: Internal Error (fatal)\n"
                   "              2: No data Available.\n"
                   "              3: Invalid Request (fatal)\n"
                   "              4: Unsupported Protocol Version (fatal)\n"
                   "              5: Unsupported PDU type (fatal)\n"
                   "              6: Withdrawal of Unknown Record (fatal)\n"
                   "  pdu     ::= The pdu to encapsulate in the error message.\n"
                   "              Each field is comma separated and will be parsed "
                                  "according to its type.\n"
                   "              Use \"-\" to not include a pdu.\n"
                   "  message ::= A text message wrapped in quote marks.\n"
                   "              Use \"-\" to not include a message.\n"
      );
    }
    else
    {
      printf ("Detailed help for '%s' available - use standard help!\n",
              command);
    }
  }
  return CMD_ID_HELP;
}

/**
 * Display the credits of the program 
 * 
 * @return CMD_ID_CREDITS
 */
int showCredits()
{
  showVersion();
  printf(SRX_CREDITS);
  
  return CMD_ID_CREDITS;
}

/**
 * Turn Verbose mode on or off.
 * 
 * @return CMD_ID_VERBOSE
 */
int toggleVerboseMode()
{
  verbose ^= true;
  printf("Verbose output: %s\n", verbose ? "on" : "off");
  return CMD_ID_VERBOSE;
}

/**
 * This function does the real work of adding the prefix to the cache test
 * harness. It will be called in both modes, file and console.
 *
 * @param arg Can be a filename (file) or cache entry (console)
 * @param fromFile specified the type of "arg"
 *
 * @return true if the cache entrie(s) could be added.
 */
bool appendPrefixData(char* arg, bool fromFile)
{
  size_t  numBefore, numAdded;
  bool    succ;

  acquireReadLock(&cache.lock);
  numBefore = sizeOfSList(&cache.entries);

  changeReadToWriteLock(&cache.lock);
  succ = readPrefixData(arg, &cache.entries, cache.maxSerial + 1, fromFile);
  changeWriteToReadLock(&cache.lock);

  // Check how many entries were added
  numAdded = succ ? (sizeOfSList(&cache.entries) - numBefore) : 0;
  cache.maxSerial += numAdded;
  unlockReadLock(&cache.lock);

  OUTPUTF(true, "Read %d entr%s\n", (int)numAdded,(fromFile ? "ies" : "y"));

  // Send notify at least one entry was added
  if (numAdded > 0)
  {
    service.notify = true;
  }

  return succ;
}

/**
 * This method adds the RPKI cache entry into the test hareness. The format
 * is IP/len max AS
 *
 * @param line the cache entry.
 *
 * @return CMD_ID_APPEND
 */
int appendPrefix(char* line)
{
  if (!appendPrefixData(line, false))
  {
    printf ("ERROR: The prefix information '%s' could not be added to the "
            "cache\n", line);
  }
  return CMD_ID_ADD;
}

/**
 * This method adds the RPKI cache entry into the test harness. The format
 * is IP/len max AS. this method does not wait for the notification timer to
 * expire. The notification will be send out to all attached clients right away.
 *
 * @param line the cache entry.
 *
 * @return CMD_ID_ADDNOW
 */
int appendPrefixNow(char* line)
{
  bool returnVal = appendPrefixData(line, false);
  if (returnVal)
  {
    sendSerialNotifyToAllClients();
  }
  return CMD_ID_ADDNOW;
}

/**
 * Append the given prefix information in the given file.
 * 
 * @param fileName the filename containing the prefix information
 * 
 * @return CMD_ID_APPEND
 */
int appendPrefixFile(char* fileName)
{
  if (!appendPrefixData(fileName, true))
  {
    printf("Error appending prefix information of '%s'\n", fileName);    
  }
  
  return CMD_ID_ADD;
}

/**
 * Clear the cache without sending a notify.
 * 
 * @return CMD_ID_EMPTY
 */
int emptyCache()
{
  acquireWriteLock(&cache.lock);
  emptySList(&cache.entries);
  unlockWriteLock(&cache.lock);

  OUTPUTF(true, "Emptied the cache\n");
  
  return CMD_ID_EMPTY;
}

/**
 * Print the content of the cache test harness to the console.
 * 
 * @return CMD_ID_CACHE
 */
int printCache()
{
  #define IPBUF_SIZE   MAX_IP_V6_STR_LEN

  time_t      now;
  SListNode*  lnode;
  unsigned    pos = 1;
  ValCacheEntry* cEntry;
  char        ipBuf[IPBUF_SIZE];

  now = time(NULL);

  acquireReadLock(&cache.lock);
  printf("Session ID: %u (0x%04X)\n", sessionID, sessionID);
  if (sizeOfSList(&cache.entries) == 0)
  {
    printf("Cache is empty\n");
  }
  else
  {
    FOREACH_SLIST(&cache.entries, lnode)
    {
      cEntry = (ValCacheEntry*)getDataOfSListNode(lnode);

      printf("%c %4u: ",
             ((cEntry->flags & PREFIX_FLAG_ANNOUNCEMENT) ? ' ' : '*'), pos++);

      if (cEntry->isV6)
      {
        printf("%s/%hhu, OAS=%u",
               ipV6AddressToStr(&cEntry->address.v6, ipBuf, IPBUF_SIZE),
               cEntry->prefixLength, ntohl(cEntry->asNumber));
      }
      else
      {
        printf("%s/%hhu, OAS=%u",
               ipV4AddressToStr(&cEntry->address.v4, ipBuf, IPBUF_SIZE),
               cEntry->prefixLength, ntohl(cEntry->asNumber));
      }
      printf(", Max.Len=%hhu, Serial=%u, Prev.Serial=%u",
             cEntry->prefixMaxLength, cEntry->serial, cEntry->prevSerial);

      if (cEntry->expires > 0)
      {
        printf(" - Expires=%lds", (cEntry->expires - now));
      }

      printf("\n");
    }
  }
  unlockReadLock(&cache.lock);
  
  return CMD_ID_CACHE;
}

/**
 * Remove the specified entries. Format: "start [end]"
 *
 * @param arg list of entry-id's to be deleted from the cache.
 *
 * @return true if the entries could be removed.
 */
bool processEntryRemoval(char* arg)
{
  int            startIndex, endIndex, currPos;
  char*          aptr;
  ValCacheEntry* currEntry;
  SListNode*     prevNode, *currIndex;
  time_t         tsExp;
  int            removed = 0;

  if (arg == NULL)
  {
    ERRORF("Error: No indexes given\n");
    return false;
  }

  // Parse start and end-index string
  startIndex = strtoul(arg, &aptr, 10);
  if (aptr == arg)
  {
    ERRORF("Error: Index is not a number: '%s'\n", arg);
    return false;
  }
  if (*aptr != '\0')
  {
    endIndex = strtoul(aptr, NULL, 10);
  }
  else
  {
    endIndex = startIndex;
  }

  // Within bounds
  acquireReadLock(&cache.lock);
  if (   !BETWEEN(startIndex, 1, sizeOfSList(&cache.entries))
      || !BETWEEN(endIndex, startIndex, sizeOfSList(&cache.entries)))
  {
    unlockReadLock(&cache.lock);
    ERRORF("Error: Invalid index(es): '%s'\n", arg);
    return false;
  }

  // When removed entries expire
  tsExp = time(NULL) + CACHE_EXPIRATION_INTERVAL;

  // Go over the list
  changeReadToWriteLock(&cache.lock);

  prevNode  = (startIndex == 1)
              ? NULL
              : getNodeFromSList(&cache.entries, startIndex - 2);

  for (currPos = startIndex; currPos <= endIndex; currPos++)
  {
    currIndex = (prevNode == NULL)
                ? getNodeFromSList(&cache.entries, startIndex - 1)
                : getNextNodeOfSListNode(prevNode);

    currEntry = (ValCacheEntry*)getDataOfSListNode(currIndex);

    if (currEntry->serial == currEntry->prevSerial)
    {
      removed++;
      currEntry->flags &= ~PREFIX_FLAG_ANNOUNCEMENT;
      currEntry->serial = ++cache.maxSerial;
      currEntry->expires = tsExp;

      // Move to end
      moveSListNode(&cache.entries, &cache.entries, currIndex, prevNode);
    }
    else
    {
      prevNode = currIndex;
    }
  }

  unlockWriteLock(&cache.lock);
  OUTPUTF(true, "Removed %d entries\n", removed);

  // Notify the clients so that they can query the withdrawals
  if (removed > 0)
  {
    service.notify = true;
  }

  return true;
}

/** 
 * This method is a wrapper for processEntryRemoval(char* arg) which does
 * the actual work. This wrapper is necessary to return the correct integer 
 * value.
 * 
 * @param arg list of entry-id's to be deleted from the cache.
 *
 * @return CMD_ID_REMOVE
 * 
 * @since 0.3.0.2
 */
int removeEntries(char* arg)
{
  processEntryRemoval(arg);
  return CMD_ID_REMOVE;
}

/**
 * Same as removeEntries except the entries are removed this very second.
 * This method overwrites the sleeping period of the cache. It sends the
 * notification right away to the connected client(s) without waiting.
 *
 * @param arg The list of entries to be removed.
 *
 * @return CMD_ID_REMOVENOW
 */
int removeEntriesNow(char* arg)
{
  bool returnVal = removeEntries(arg);
  if (returnVal)
  {
    sendSerialNotifyToAllClients();
  }
  return CMD_ID_REMOVENOW;
}

/**
 * Prepare the generation of the error report.
 * 
 * @param arg <errorNo> <pdu | "-"> <msg | "-">
 * 
 * @return CMD_ID_ERROR
 */
int issueErrorReport(char* arg)
{
  uint16_t  errNo;
  char*     msg;

  if (arg == NULL)
  {
    ERRORF("Error: No error-code and/or message given\n");
    return CMD_ID_ERROR;
  }

  // Parse code and point to message
  errNo = (uint16_t)strtoul(arg, &msg, 10);
  if (msg == arg)
  {
    ERRORF("Error: Invalid error-code: %s\n", arg);
    return CMD_ID_ERROR;
  }
  if (*msg != '\0')
  {
    msg++;
  }

  // Send
  sendErrorReportToAllClients(errNo, msg);

  return CMD_ID_ERROR;
}

/**
 * Print the list of clients to the console.
 * 
 * @return CMD_ID_CLIENTS
 */
int listClients()
{
  #define BUF_SIZE (MAX_IP_V6_STR_LEN + 6)
  char          buf[BUF_SIZE];
  CacheClient*  cl;
  unsigned      idx = 1;

  if (HASH_COUNT(clients) == 0)
  {
    printf("No clients\n");
  }
  else
  {
    for (cl = clients; cl; cl = cl->hh.next, idx++)
    {
      printf("%d: %s\n", idx, socketToStr(cl->fd, true, buf, BUF_SIZE));
    }
  }
  
  return CMD_ID_CLIENTS;
}

// Necessary forward declaration
int handleLine(char* line);

/**
 * Load the file given and execute line by line.
 * 
 * @param arg The name of the file
 * 
 * @return The last comment in the script or CMD_ID_RUN if unknown
 */
int executeScript(char* fileName)
{
  #define MAX_LINE_LEN  128

  FILE* fh;
  char  cbuf[MAX_LINE_LEN];
  char* cpos;
  int last_command = CMD_ID_UNKNOWN;

  fh = fopen(fileName, "rt");
  if (fh == NULL)
  {
    ERRORF("Error: Failed to open the script '%s'\n", fileName);
    return CMD_ID_RUN;
  }

  while (fgets(cbuf, MAX_LINE_LEN, fh))
  {
    // Strip comment
    cpos = strchr(cbuf, '#');
    if (cpos != NULL)
    {
      *cpos = '\0';
    }

    // Remove white-space(s)
    chomp(cbuf);

    // Empty line?
    if (*cbuf == '\0')
    {
      continue;
    }

    last_command = handleLine(cbuf);
  }

  fclose(fh);
  
  return (last_command == CMD_ID_UNKNOWN) ? CMD_ID_RUN : last_command;
}

/**
 * Pauses the application for a given number of seconds
 * 
 * @param noSeconds The time in seconds the program has to pause.
 * 
 * @return CMD_ID_SLEEP.
 */
int pauseExecution(char* noSeconds)
{
  int sec;

  sec = strtol(noSeconds, NULL, 10);
  if (sec <= 0)
  {
    ERRORF("Error: Invalid number of seconds: %s\n", noSeconds);
  }
  else
  {
    sleep(sec);
  }
  return CMD_ID_SLEEP;
}

/**
 * Doesn't really do anything
 * 
 * @return CMD_ID_QUIT
 * 
 * @since 0.3.0.2
 */
int processQuit()
{
  return CMD_ID_QUIT;
}

////////////////////////////////////////////////////////////////////////////////
// CONSOLE INPUT
////////////////////////////////////////////////////////////////////////////////

/**
 * This method parses the line by splitting it into command and argument
 * separated by a blank. Depending on the command the appropriate method is
 * called. With version 0.3.0.2 this method will return true if the parser can 
 * continue and false if not. (false does not necessarily mean an error.
 *
 * @param line The line to be parsed
 *
 * @return the integer value of the executed command.
 */
int handleLine(char* line)
{  
  char* cmd, *arg;
  int retVal = CMD_ID_UNKNOWN;

  // Split into command and argument
  arg = line;
  cmd = strsep(&arg, " ");

  // Call function that is going to handle the command
  #define CMD_CASE(STR, FUNC) \
    if (!strcmp(cmd, STR)) { return FUNC(arg); }

  CMD_CASE("verbose",   toggleVerboseMode);
  CMD_CASE("cache",     printCache);
  CMD_CASE("version",   showVersion);
  CMD_CASE("\\h",       showHelp);
  CMD_CASE("help",      showHelp);
  CMD_CASE("credits",   showCredits);

  CMD_CASE("sessionID", processSessionID);

  CMD_CASE("empty",     emptyCache);
  CMD_CASE("append",    appendPrefixFile);
  CMD_CASE("add",       appendPrefix);
  CMD_CASE("addNow",    appendPrefixNow);
  CMD_CASE("remove",    removeEntries);
  CMD_CASE("removeNow", removeEntriesNow);
  CMD_CASE("error",     issueErrorReport);
  CMD_CASE("notify",    sendSerialNotifyToAllClients);
  CMD_CASE("reset",     sendCacheResetToAllClients);

  CMD_CASE("clients",   listClients);
  CMD_CASE("run",       executeScript);
  CMD_CASE("sleep",     pauseExecution);
  
  CMD_CASE("quit",      processQuit);
  CMD_CASE("exit",      processQuit);
  CMD_CASE("\\q",       processQuit);

  // Unknown
  printf("Error: Unknown command '%s'\n", cmd);
  return retVal;
}

/**
 * Processes the input from the command line.
 */
void handleUserInput()
{
  char* line;

  using_history();
  read_history(HISTORY_FILENAME);
  int cmd = CMD_ID_UNKNOWN;
  // Added trim = M0000713
  while((line = trim(readline(USER_PROMPT))))
  {
    // Empty line - ignore
    if (*line == '\0')
    {
      free(line);
      continue;
    }

    // Execute the line
    
    cmd = handleLine(line);
    if (cmd == CMD_ID_QUIT)
    {
      free(line);
      break;
    }
    else if (cmd != CMD_ID_UNKNOWN)
    {      
      // Store so that the user does not have to type it again
      add_history(line);       
    }
    free(line);        
  }

  write_history(HISTORY_FILENAME);
}

/*----------
 * Callbacks
 */
void deleteExpiredEntriesFromCache(time_t now)
{
  SListNode*  currNode, *nextNode;
  ValCacheEntry* cEntry;
  uint32_t    removed = 0;

  acquireWriteLock(&cache.lock);
  currNode = getRootNodeOfSList(&cache.entries);
  while (currNode)
  {
    cEntry   = (ValCacheEntry*)getDataOfSListNode(currNode);
    nextNode = getNextNodeOfSListNode(currNode);

    // Entry expired
    if ((cEntry->expires > 0) && (cEntry->expires <= now))
    {
      cache.minPSExpired = MIN(cache.minPSExpired, cEntry->prevSerial);
      cache.maxSExpired  = MAX(cache.maxSExpired, cEntry->serial);

      deleteFromSList(&cache.entries, cEntry);
      removed++;
    }

    currNode = nextNode;
  }
  unlockWriteLock(&cache.lock);

  if (removed > 0)
  {
    OUTPUTF(true, "Deleted %d expired entries\n", removed);
  }
}

void serviceTimerExpired(int id, time_t now)
{
  deleteExpiredEntriesFromCache(now);

  // A change occurred that requires a serial notify
  if (service.notify)
  {
    service.notify = false;
    sendSerialNotifyToAllClients();
  }
}

void printLogMessage(LogLevel level, const char* fmt, va_list args)
{
  if ((level == LEVEL_ERROR) || verbose)
  {
    putc('\r', stdout);
    vprintf(fmt, args);
    printf("\n");
    OPROMPT();
  }
}

void handleSigInt(int signal)
{
  // Let 'readline' return 0, i.e. stop the user-input loop
  fclose(stdin);
}


////////////////////////////////////////////////////////////////////////////////
// MAIN PROGRAM
////////////////////////////////////////////////////////////////////////////////

bool setupCache()
{
  initSList(&cache.entries);
  if (!createRWLock(&cache.lock))
  {
    ERRORF("Error: Failed to create the cache R/W lock");
    return false;
  }
  cache.maxSerial     = 0;
  cache.minPSExpired  = UINT32_MAX;
  cache.maxSExpired   = 0;

  return true;
}

bool setupService()
{
  service.timer = setupTimer(serviceTimerExpired);
  if (service.timer == -1)
  {
    ERRORF("Error: Failed to create the service timer");
    return false;
  }
  service.notify = false;
  startIntervalTimer(service.timer, SERVICE_TIMER_INTERVAL, false);

  return true;
}

int main(int argc, const char* argv[])
{
  int       port;
  pthread_t rlthread;
  int       ret;

  // Help and port number
  if (argc < 2)
  {
    printf("Start RPKI-Cache test harness using default port 50001\n");
    port = 50001;
  }
  else
  {
    port = strtol(argv[1], NULL, 10);
  }
  if (port == 0)
  {
    ERRORF("Error: Unknown port \'%s\'\n", argv[1]);
    return -1;
  }

  // Output all log messages to stderr
  setLogMethodToCallback(printLogMessage);

  // Initialize the cache
  if (!setupCache())
  {
    return -2;
  }

  // Bind to the port
  if (!createServerSocket(&svrSocket, port, true))
  {
    releaseRWLock(&cache.lock);
    return -3;
  }

  // Service (= maintenance)
  if (!setupService())
  {
    stopServerLoop(&svrSocket);
    releaseRWLock(&cache.lock);
    return -4;
  }

  showVersion();

  // Start run loop and handle user input
  if (pthread_create(&rlthread, NULL, handleServerRunLoop, NULL) == 0)
  {
    // Handle Ctrl-C
    signal(SIGINT, handleSigInt);

    ret = 0;
    bool doContiunue = true; 
    if (argc >= 3)
    {
      doContiunue = executeScript((char*)argv[2]) != CMD_ID_QUIT;
    }
    if (doContiunue)
    {
      handleUserInput();
    }
  }
  else
  {
    ret = -5;
    ERRORF("Error: Failed to start server run-loop\n");
  }

  // Stop all timers
  deleteAllTimers();

  // Release port
  stopServerLoop(&svrSocket);

  // Cleanup
  releaseRWLock(&cache.lock);
  releaseSList(&cache.entries);

  return ret;
}