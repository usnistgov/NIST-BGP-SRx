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
 * @version 0.5.1.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.5.1.0  - 2018/06/09 - oborchert
 *            * Added command 'echo' to allow printing messaged from a script
 *              to the console. CMD_ID_ECHO
 *            * Added command waitFor <client-ip> to allow to wait until the 
 *              specific client connects. This will time out after 60 seconds.
 *            * Added command pause to allow to wait until any key is pressed.
 *          - 2018/03/09 - oborchert 
 *            * BZ1263: Merged branch 0.5.0.x (version 0.5.0.4) into trunk 
 *              of 0.5.1.0.
 *          - 2017/10/12 - oborchert
 *            * BZ1103: Fixed incorrect RFC reference
 * 0.5.0.5  - 2018/05/17 - oborchert
 *            * (merged branch 0.5.0 into trunk)
 *          - 2018/04/24 - oborchert
 *            * Modified the function printLogMessage to use the current log 
 *              level rather than hard coded log level.
 *            * Change default value for verbose to false.
 * 0.5.0.4  - 2018/03/08 - oborchert
 *            * Fixed incorrect processing of parameters.
 *            * Fixed incorrect syntax printout.
 * 0.5.0.3  - 2018/03/01 - oborchert
 *            * Added proper program stop when help parameter is provided.
 *            * Fixed printout for router keys.
 *          - 2018/02/28 - oborchert
 *            * Fixed usage of incorrect version number.
 * 0.5.0.1  - 2017/09/25 - oborchert
 *            * Fixed compiler warnings.
 * 0.5.0.0  - 2017/07/08 - oborchert
 *            * Fixed some prompt handling in console
 *            * BZ1185: fixed issue with 'cache' command showing all entries
 *              as SKI's
 *            * Added '*' to allow switching between auto complete and browsing
 *              the file system.
 *          - 2017/07/07 - oborchert
 *            * BZ1183: Fixed issues with history.
 *            * Added auto completion in command window (use tab)
 *          - 2017/06/05 - oborchert
 *            * Added parameter -D <level> to set debug level.
 *              Moved current debug level to LEVEL_ERROR
 *            * fixed segmentation fault for addKey with missing parameters.
 *            * Modified the ley loading aligning it with the command set of
 *              prefix loading.
 *            * Added keyLoc to provide a key location folder
 *            * Added addKeyNow
 *          - 2017/06/16 - kyehwanl
 *            * Updated code to use RFC8210 (former 6810-bis-9)
 *          - 2017/06/16 - oborchert
 *            * Version 0.4.1.0 is trashed and moved to 0.5.0.0
 *          - 2016/08/30 - oborchert
 *            * Added a proper configuration section.
 *          - 2016/08/26 - oborchert
 *            * Changed client list display from using index to file descriptor
 *              which does not change when another client disconnects.
 *          - 2016/08/19 - oborchert
 *            * Modified the CTRL+C handler to use sigaction instead. Added
 *              a more gracefull stop.
 *            * Modified old fix M713 to not call trim on NULL. BZ1017
 * 0.4.0.2  - 2016/08/12 - oborchert
 *            * Changed default port from 50000 to 323 as specified by RFC6810
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
#include <srx/srxcryptoapi.h>
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

// Max characters per line
#define LINE_BUF_SIZE 255

/** This structure specified one cache entry. */
typedef struct {
  /** Current serial number of the entry */
  uint32_t  serial;
  /** Previous serial number (before being withdrawn) */
  uint32_t  prevSerial;
  /** When this entry expires, i.e. should be deleted */
  time_t    expires;
  /** true if IPv6 prefix */
  bool      isV6;
  /* router key indicator */
  bool      isKey;

  /** Prefix (v4, v6) - stored in network Byte order */
  uint8_t   flags;           // Might not be needed.
  /** Length of the prefix */
  uint8_t   prefixLength;
  /** Max length of prefix */
  uint8_t   prefixMaxLength;
  /** The AS number for this entry */
  uint32_t  asNumber;
  /** The IP Address */
  union {
    /** The IPv4 Address */
    IPv4Address v4;
    /** The IPv6 Address */
    IPv6Address v6;
  } address;

  char* ski;            // Subject Key Identifier
  char* pPubKeyData;    // Subject Public Key Info
} ValCacheEntry;

/** Single client */
typedef struct {
  /** Socket - but also the hash identifier */
  int             fd;
  /** Hash handle */
  UT_hash_handle  hh;
  /** The version used with this client */
  int             version;
} CacheClient;

/**
 * This configuration structure allows to pass some more configuration settings
 * to the server.
 *
 * @since 0.5.0.0
 */
typedef struct {
  /** The configured port */
  int   port;
  /** A script containing cache commands to be executed upon start */
  char* script;
} RPKI_SRV_Configuration;

#define CMD_ID_QUIT          0
#define CMD_ID_UNKNOWN       1
#define CMD_ID_VERBOSE       2
#define CMD_ID_CACHE         3
#define CMD_ID_VERSION       4
#define CMD_ID_HELP          5
#define CMD_ID_CREDITS       6
#define CMD_ID_SESSID        7
#define CMD_ID_EMPTY         8
#define CMD_ID_ADD           9
#define CMD_ID_ADDNOW       10
#define CMD_ID_REMOVE       11
#define CMD_ID_REMOVENOW    12
#define CMD_ID_ERROR        13
#define CMD_ID_NOTIFY       14
#define CMD_ID_RESET        15
#define CMD_ID_CLIENTS      16
#define CMD_ID_RUN          17
#define CMD_ID_SLEEP        18
#define CMD_ID_KEY_LOC      19
#define CMD_ID_ECHO         20
#define CMD_ID_WAIT_CLIENT  21
#define CMD_ID_PAUSE        22

#define DEF_RPKI_PORT    323
#define UNDEF_VERSION    -1
/*----------
 * Constants
 */
#ifdef PACKAGE_VERSION
const char* RPKI_RTR_SRV_VER          = PACKAGE_VERSION "\0";
#else
const char* RPKI_RTR_SRV_VER          = "> 0.5.0\0";
#endif
const char* RPKI_RTR_SRV_NAME         = "RPKI Cache Test Harness\0";
const char* HISTORY_FILENAME          = ".rpkirtr_svr.history\0";
const char* USER_PROMPT               = ">> \0";
const int   SERVICE_TIMER_INTERVAL    = 60;   ///< Service interval (sec)
const int   CACHE_EXPIRATION_INTERVAL = 3600; ///< Sec. to keep removed entries

#define PUB_KEY_OCTET 91
#define KEY_BIN_SIZE 91
#define MAX_CERT_READ_SIZE 260
#define OFFSET_PUBKEY 170
#define OFFSET_SKI 130
#define COMMAND_BUF_SIZE 256
/*-----------------
 * Global variables
 */
struct {
  SList     entries;
  RWLock    lock;
  uint32_t  maxSerial;
  uint32_t  minPSExpired, maxSExpired;
  uint8_t   version;
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
bool         verbose   = false;
/** The current cache session id value */
uint16_t     sessionID = 0;

/** Used to indicate if the system is in a controlled wait loop. This allows
 *  The CTRL+C handler to not initiate a shutdown but set the ctr__c variable
 *  to true. */
bool         inWait    = false;
/** Indicates if the ctrl+c combination was pressed.  */
bool         ctrl_c    = false;
/** Location (directory) where the key files are stored. */
char keyLocation[LINE_BUF_SIZE];

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
bool sendPDUWithSerial(int* fdPtr, RPKIRouterPDUType type, uint32_t serial, 
                       uint8_t version)
{
  uint8_t                pdu[sizeof(RPKISerialQueryHeader)];
  RPKISerialQueryHeader* hdr;

  // Create PDU
  hdr = (RPKISerialQueryHeader*)pdu;
  hdr->version   = version;
  hdr->type      = (uint8_t)type;
  hdr->sessionID = htons(sessionID);
  hdr->length    = htonl(sizeof(RPKISerialQueryHeader));
  hdr->serial    = htonl(serial);
  // Send
  OUTPUTF(false, "Sending an RPKI-RTR 'PDU[%u] with Serial'\n", type);
  return sendNum(fdPtr, &pdu, sizeof(RPKISerialQueryHeader));
}

/**
 * Send a CACHE RESET to the client.
 *
 * @param fdPtr the socket connection
 * @param version The version for this session.
 *
 * @return true id the packet was send successful.
 */
bool sendCacheReset(int* fdPtr, u_int8_t version)
{
  uint8_t               pdu[sizeof(RPKICacheResetHeader)];
  RPKICacheResetHeader* hdr;

  // Create PDU
  hdr = (RPKICacheResetHeader*)pdu;
  hdr->version  = version;
  hdr->type     = (uint8_t)PDU_TYPE_CACHE_RESET;
  hdr->reserved = 0;
  hdr->length   = htonl(sizeof(RPKICacheResetHeader));

  return sendNum(fdPtr, &pdu, sizeof(RPKICacheResetHeader));
}

/**
 * Send a CACHE RESPONSE to the client.
 *
 * @param fdPtr the socket connection
 * @param version The version number of this session
 *
 * @return true id the packet was send successful.
 */
bool sendCacheResponse(int* fdPtr, u_int8_t version)
{
  uint8_t                  pdu[sizeof(RPKICacheResetHeader)];
  RPKICacheResponseHeader* hdr;

  // Create PDU
  hdr = (RPKICacheResponseHeader*)pdu;
  hdr->version   = version;
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
                  bool isReset, u_int8_t version)
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
    if (!sendCacheReset(fdPtr, version))
    {
      ERRORF("Error: Failed to send a 'Cache Reset'\n");
    }
  }
  else
  { // Send the prefix
    // Send 'Cache Response'
    if (!sendCacheResponse(fdPtr, version))
    {
      ERRORF("Error: Failed to send a 'Cache Response'\n");
    }
    else
    {
      OUTPUTF(true, "Cache size = %u\n", cache.entries.size);
      if (cache.entries.size > 0) // there is always a root.
      {
        ValCacheEntry* cEntry;

        uint8_t               v4pdu[sizeof(RPKIIPv4PrefixHeader)];
        uint8_t               v6pdu[sizeof(RPKIIPv6PrefixHeader)];
        RPKIIPv4PrefixHeader* v4hdr = (RPKIIPv4PrefixHeader*)v4pdu;
        RPKIIPv6PrefixHeader* v6hdr = (RPKIIPv6PrefixHeader*)v6pdu;
        RPKIRouterKeyHeader   rkhdr;

        // Basic initialization of data that does NOT change
        v4hdr->version  = version;
        v4hdr->type     = PDU_TYPE_IP_V4_PREFIX;
        v4hdr->reserved = 0;
        v4hdr->length   = htonl(sizeof(RPKIIPv4PrefixHeader));

        v6hdr->version  = version;
        v6hdr->type     = PDU_TYPE_IP_V6_PREFIX;
        v6hdr->reserved = 0;
        v6hdr->length   = htonl(sizeof(RPKIIPv6PrefixHeader));

        rkhdr.version   = version;
        rkhdr.type      = PDU_TYPE_ROUTER_KEY;
        rkhdr.zero      = 0;

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

          // Send 'Router Key'
          if( cEntry->isKey == true && cEntry->prefixLength == 0 &&
              cEntry->prefixMaxLength == 0 &&
              cEntry->ski && cEntry->pPubKeyData)

          {
            if (version == 1)
            {
              rkhdr.flags     = cEntry->flags;
              memcpy(&rkhdr.ski, cEntry->ski, SKI_LENGTH);
              memcpy(&rkhdr.keyInfo, cEntry->pPubKeyData, KEY_BIN_SIZE);
              rkhdr.as        = cEntry->asNumber;
              rkhdr.length    = htonl(sizeof(RPKIRouterKeyHeader));

              OUTPUTF(false, "Sending an 'Router Key' (serial = %u)\n",
                  cEntry->serial);
              if (!sendNum(fdPtr, &rkhdr, sizeof(RPKIRouterKeyHeader)))
              {
                ERRORF("Error: Failed to send a 'RouterKey'\n");
                break;
              }
              continue;
            }
          }
          else
          {
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
      }

      // Send 'End of Data'
      OUTPUTF(true, "Sending an 'End of Data (max. serial = %u)\n",
              cache.maxSerial);

      // was sending cache version, not session version.
      if (!sendPDUWithSerial(fdPtr, PDU_TYPE_END_OF_DATA, cache.maxSerial, version))
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
                             cache.maxSerial, client->version))
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
      if (!sendCacheReset(&client->fd, client->version))
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
 * @param fdPtr the socket connection
 * @param the error number to be send
 * @param data contains the error number followed by the PDU and text. The
 *             character - as PDU or text generates a PDU / text length of zero.
 * @param version The version of this session.
 * 
 * @return true if it could be send.
 */
bool sendErrorPDU(int* fdPtr, RPKICommonHeader* pdu, char* reason, 
                  u_int8_t version)
{
  // @TODO: Fix this code.
  printf("ERROR: invalid PDU because of %s\n", reason);
//  uint8_t                  pdu[sizeof(RPKIErrorReportHeader)];
//  RPKICacheResponseHeader* hdr;
//
//  // Create PDU
//  hdr = (RPKICacheResponseHeader*)pdu;
//  hdr->version   = RPKI_RTR_PROTOCOL_VERSION;
//  hdr->type      = (uint8_t)PDU_TYPE_CACHE_RESPONSE;
//  hdr->sessionID = htons(sessionID);
//  hdr->length    = htonl(sizeof(RPKICacheResetHeader));

//  OUTPUTF(true, "Sending a 'Cache Response'\n");
//  return sendNum(fdPtr, &pdu, sizeof(RPKICacheResetHeader));
  return false;
}

/**
 * Send an error report to all clients.
 *
 * @param fdPtr the socket connection
 * @param the error number to be send
 * @param data contains the error number followed by the PDU and text. The
 * character - as PDU or text generates a PDU / text length of zero.
 * @return true if it could be send.
 */
bool sendErrorReport(int* fdPtr, uint16_t errNo, char* data)
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

  // Check if a message is provided
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
  CacheClient*     ccl = NULL;

  HASH_FIND_INT(clients, &sock, ccl);
  if (ccl == NULL)
  {
    ERRORF("Error: Cannot find client sessoin!\n");
    close(sock);
    return;
  }

  // Process client requests, store the current time
  lastReq = time(NULL);

  // read the beginning of the header to see how many bytes are actually needed
  while (recvNum(&sock, &hdr, sizeof(RPKICommonHeader)))
  {
    if (hdr.version > RPKI_RTR_PROTOCOL_VERSION)
    {
      sendErrorPDU(&ccl->fd, &hdr, "Unsupported Version", 
                   RPKI_RTR_PROTOCOL_VERSION);
      close(sock);
      break;          
    }
    if (ccl->version == UNDEF_VERSION)
    {
      ccl->version = hdr.version;
    } 
    else if (hdr.version != ccl->version)
    {
      // @TODO: Fix this and also close connection in this case.
      sendErrorPDU(&ccl->fd, &hdr, "Illegal switch of version number!", 
                   ccl->version);
      close(sock);
      break;
    }
    
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

    OUTPUTF(true, "Received Data From Client [%x]...\n", sock);

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
          sendPrefixes(&sock, serial, sessionID, false, ccl->version);
        }
        break;

      case PDU_TYPE_RESET_QUERY:
        OUTPUTF(true, "[+%lds] Received a 'Reset Query'\n", diffReq);
        sendPrefixes(&sock, 0, sessionID, true, ccl->version);
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

/**
 * Handles client session status
 *
 * @param svrSock The server socket that receives the data
 * @param client NOT USED
 * @param fd The file descriptor
 * @param connected Indicates if the connection will be established of shut down
 * @param user NOT USED
 *
 * @return false is an error occured.
 */
bool handleStatus(ServerSocket* svrSock, ServerClient* client, int fd,
                  bool connected, void* user)
{
  CacheClient* ccl = NULL;

  if (connected)
  {
    ccl = (CacheClient*)malloc(sizeof(CacheClient));
    if (ccl == NULL)
    {
      ERRORF("Error: Out of memory - rejecting client\n");
      return false;
    }
    memset(ccl, 0, sizeof(CacheClient));
    ccl->fd      = fd;
    ccl->version = UNDEF_VERSION;
    HASH_ADD_INT(clients, fd, ccl);
  }
  else
  {
    HASH_FIND_INT(clients, &fd, ccl);
    if (ccl != NULL)
    {
      HASH_DEL(clients, ccl);
      memset(ccl, 0, sizeof(CacheClient));
      ccl = NULL;
    }
    else
    {
      ERRORF("Error: Unknown client\n");
    }
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
    cEntry->isKey           = false;

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
           "  - verbose\n"
           "                 Turns verbose output on or off\n"
           "  - cache\n"
           "                 Lists the current cache's content\n"
           "  - version\n"
           "                 Displays the version of this tool!\n"
           "  - sessionID\n"
           "                 Display the current session id\n"
           "  - help [command]\n"
           "                 Display this screen or detailed help for the\n"
           "                 given command!\n"
           "  - credits\n"
           "                 Display credits information!\n"
           "\n"
           "Cache Commands:\n"
           "-----------------\n"
           "  - keyLoc <location>\n"
           "                 The key volt location.\n"
           "  - empty\n"
           "                 Empties the cache\n"
           "  - sessionID <number>\n"
           "                 Generates a new session id.\n"
           "  - append <filename>\n"
           "                 Appends a prefix file's content to the cache\n"
           "  - add <prefix> <maxlen> <as>\n"
           "                 Manually add a whitelist entry\n"
           "  - addNow <prefix> <maxlen> <as>\n"
           "                 Manually add a whitelist entry without any \n"
           "                 delay!\n"
           "  - addKey <as> <cert file>\n"
           "                 Manually add a RPKI Router Certificate\n"
           "  - remove <index> [end-index]\n"
           "                 Remove one or more cache entries\n"
           "  - removeNow <index> [end-index]\n"
           "                 Remove one or more cache entries without any\n"
           "                 delay!\n"
           "  - error <code> <pdu|-> <message|->\n"
           "                 Issues an error report. The pdu contains all\n"
           "                 real fields comma separated.\n"
           "  - notify\n"
           "                 Send a SERIAL NOTIFY to all clients.\n"
           "  - reset\n"
           "                 Send a CACHE RESET to all clients.\n"
           "  - echo [text]\n"
           "                 Print the given text on the console window.\n"
           "  - waitFor <client-IP>\n"
           "                 Wait until the client with the given IP connect.\n"
           "                 This function times out after 60 seconds.\n"
           "  - pause [prompt]\n"
           "                 Wait until any key is pressed. This is mainly\n"
           "                 for scripting scenarios. If no prompt is used,\n"
           "                 the default prompt will be applied!\n"

           "\n"
           "Program Commands:\n"
           "-----------------\n"
           "  - quit, exit, \\q\n"
           "                 Quits the loop and terminates the server.\n"
           "                 This command is allowed within scripts but only\n"
           "                 as the very last command otherwise it will be\n"
           "                 ignored!\n"
           "  - clients\n"
           "                 Lists all clients\n"
           "  - run <filename>\n"
           "                 Executes a file line-by-line\n"
           "  - sleep <seconds>\n"
           "                 Pauses execution\n"
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
    else if (strcmp(command, "echo")==0)
    {
      SHOW_CMD_HLP("echo [text]",
                   "This command allows to display a given text on the console "
                   "window. It is mainly useful for scripted scenarios, where "
                   "follow up actions by the user is needed or where the "
                   "it makes sense to inform about the script process.\n"
      );
    }
    else if (strcmp(command, "waitFor")==0)
    {
      SHOW_CMD_HLP("waitFor <client-IP>",
                   "This command waits for a client to connect but will time "
                   "out after 60 seconds and writes a timeout statement on the "
                   "console.\n"
      );
    }
    else if (strcmp(command, "pause")==0)
    {
      SHOW_CMD_HLP("pause [prompt]",
                   "This command is for scripting scenarios the have user "
                   "interactions to continue. For instance CTRL+C will "
                   "further loading or deleting of cache entries. In case "
                   "no prompt is provided the default prompt is used.\n"
      );
    }
    else
    {
      printf ("No detailed help for '%s' available - use standard help!\n",
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

  OUTPUTF(false, "Read %d Prefix entr%s\n", (int)numAdded,
          (numAdded != 1 ? "ies" : "y"));

  // Send notify at least one entry was added
  if (numAdded > 0)
  {
    service.notify = true;
  }

  return succ;
}


#define CHAR_CONV_CONST     0x37
#define DIGIT_CONV_CONST    0x30
#define LEN_BYTE_NIBBLE     0x02

unsigned char hex2bin_byte(char* in)
{
  unsigned char result=0;
  int i=0;
  for(i=0; i < LEN_BYTE_NIBBLE; i++)
  {
    if(in[i] > 0x40)
      result |= ((in[i] - CHAR_CONV_CONST) & 0x0f) << (4-(i*4));
    else if(in[i] > 0x30 && in[i] < 0x40)
      result |= (in[i] - DIGIT_CONV_CONST) << (4-(i*4));
  }
  return result;
}

/**
 * This function loops through the list of clients and checks if one client
 * matches the given IP address.
 * 
 * @param clientIP The IP address the clients will be compared too.
 * 
 * @return true if one client exists with the given IP address.
 * 
 * @since 0.5.1.0 
 */
bool hasClient(char* clientIP)
{
  #define BUF_SIZE (MAX_IP_V6_STR_LEN + 6)
  char*        buf = malloc(BUF_SIZE);
  char*        ipStr1 = malloc(BUF_SIZE);
  char*        ipStr2 = malloc(BUF_SIZE);
  CacheClient* cl;
  bool         retVal = false;

  if ((clientIP != NULL) && (HASH_COUNT(clients) != 0))
  {
    cl = clients;
    snprintf(ipStr1, BUF_SIZE, "%s:", clientIP);
    while (cl != NULL)
    {
      socketToStr(cl->fd, true, buf, BUF_SIZE);
      snprintf(ipStr2, strlen(ipStr1)+1, "%s:", buf);
      // ==0 because the client also has the port number attached.
      retVal = strcmp(ipStr1, ipStr2) == 0;
      cl = retVal ? cl=NULL : cl->hh.next;
    }
  }

  free (buf);
  free (ipStr1);
  free (ipStr2);
  return retVal;
}

/**
 * Read the router key certificate file.
 *
 * @param arg the arguments (asn algoid certFile)
 * @param dest The list where to store it in
 * @param serial The serial number
 *
 * @return true if the cert could be read or not.s
 */
bool readRouterKeyData(const char* arg, SList* dest, uint32_t serial)
{

  char  buffKey[KEY_BIN_SIZE];
  char  buffSKI_asc[SKI_LENGTH * 2];
  char  buffSKI_bin[SKI_LENGTH];
  uint16_t keyLength, skiLength;
  FILE*   fpKey;
  ValCacheEntry* cEntry;

  char           streamBuf[COMMAND_BUF_SIZE];
  char*          bptr;

  if (arg == NULL)
  {
    ERRORF("Error: Data missing: <as> <algo-id> <cert file>\n");
    return false;
  }
  strncpy(streamBuf, arg, COMMAND_BUF_SIZE);
  stripLineBreak(streamBuf);
  bptr = streamBuf;

  char* asnStr     = strsep(&bptr, " \t");
  char* _certFile  = strsep(&bptr, " \t");

  if (_certFile == NULL)
  {
    ERRORF("Error: Data missing: <as> <cert file>\n");
    return false;
  }

  char certFile[512];
  snprintf(certFile, 512, "%s/%s", keyLocation, _certFile);

  // to read certificate file
  fpKey = fopen (certFile, "rb");
  if (fpKey == NULL)
  {
    ERRORF("Error: Failed to open '%s'\n", certFile);
    return false;
  }
  // to read a certificate and
  // parsing pubkey part and SKI
  //
  fseek(fpKey, OFFSET_PUBKEY, SEEK_SET);
  keyLength = (u_int16_t)fread (&buffKey, sizeof(char), KEY_BIN_SIZE, fpKey);

  if (keyLength != KEY_BIN_SIZE)
  {
    ERRORF("Error: Failed to read, key size mismatch\n");
    return false;
  }

  fseek(fpKey, OFFSET_SKI, SEEK_SET);
  // read two times of SKI_SIZE(20 bytes) because of being written in a way of ASCII
  skiLength = (u_int16_t)fread(&buffSKI_asc, sizeof(char), SKI_LENGTH * 2,
                               fpKey);

  int idx;
  for(idx = 0; idx < SKI_LENGTH; idx++)
  {
    buffSKI_bin[idx] = hex2bin_byte(buffSKI_asc+(idx*2));
  }

  // new instance to append
  cEntry = (ValCacheEntry*)appendToSList(dest, sizeof(ValCacheEntry));

  if (cEntry == NULL)
  {
    fclose(fpKey);
    return false;
  }

  cEntry->serial          = cEntry->prevSerial = serial++;
  cEntry->expires         = 0;
  cEntry->flags           = PREFIX_FLAG_ANNOUNCEMENT;
  cEntry->prefixLength    = 0;
  cEntry->prefixMaxLength = 0;
  cEntry->isV6            = false;
  cEntry->isKey           = true;
  cEntry->address.v4.in_addr.s_addr= 0;

  cEntry->asNumber    = htonl(strtoul(asnStr, NULL, 10));
  cEntry->ski         = (char*) calloc(1, SKI_LENGTH);
  cEntry->pPubKeyData = (char*) calloc(1, KEY_BIN_SIZE);

  memcpy(cEntry->ski, buffSKI_bin, SKI_LENGTH);
  memcpy(cEntry->pPubKeyData, buffKey, KEY_BIN_SIZE);

  fclose(fpKey);

  return true;
}

/**
 * Append the given public router key to the cache.
 *
 * @param line the arguments line.
 *
 * @return true if the key could be added.
 */
bool appendRouterKeyData(char* line)
{

  size_t  numBefore, numAdded;
  bool    succ;

  acquireReadLock(&cache.lock);
  numBefore = sizeOfSList(&cache.entries);

  changeReadToWriteLock(&cache.lock);

  // function for certificate reading
  succ = readRouterKeyData(line, &cache.entries, cache.maxSerial+1);

  changeWriteToReadLock(&cache.lock);

  numAdded = succ ? (sizeOfSList(&cache.entries) - numBefore) : 0;
  cache.maxSerial += numAdded;
  unlockReadLock(&cache.lock);

  OUTPUTF(false, "Read %d Router Key%s entry\n", (int)numAdded,
          numAdded != 1 ? "s" : "");

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
 * Append the key cert to the cache.
 *
 * @param line The command line
 *
 * @return CMD_ID_ADDKEY
 */
int appendRouterKey(char* line)
{
  if (!appendRouterKeyData(line))
  {
    printf ("ERROR: The key cert '%s' could not be added to the "
            "cache\n", line);
  }

  return CMD_ID_ADD;
}

/**
 * Append the key cert to the cache.
 *
 * @param line The command line
 *
 * @return CMD_ID_ADDKEY
 */
int appendRouterKeyNow(char* line)
{
  if (!appendRouterKeyData(line))
  {
    printf ("ERROR: The key cert '%s' could not be added to the "
            "cache\n", line);
  }
  else
  {
    sendSerialNotifyToAllClients();
  }

  return CMD_ID_ADDNOW;
}

/**
 * Set the key location
 *
 * @param line the location where the keys are stored (if null the key location
 *             will be removed.)
 *
 * @return CMD_ID_KEY_LOC
 */
int setKeyLocation(char* line)
{
  if (line == NULL)
  {
    line = ".\0";
  }
  snprintf(keyLocation, LINE_BUF_SIZE, "%s", line);

  return CMD_ID_KEY_LOC;
}

/**
 * Append the given prefix information in the given file.
 *
 * @param fileName the filename containing the prefix information
 *
 * @return CMD_ID_AD
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
  int         idx=0;

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

      if (cEntry->isKey)
      {
        printf("SKI: ");
        for (idx = 0; idx < SKI_LENGTH; idx++)
        {
          printf ("%02X", (u_int8_t)cEntry->ski[idx]);
        }
        printf (", OAS=%u", ntohl(cEntry->asNumber));
      }
      else
      {
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
      }

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
  CacheClient* ccl = NULL;
  if (HASH_COUNT(clients) > 0)
  {
    OUTPUTF(true, "Sending multiple 'Error Report' (Error = %hhu)\n", errNo);

    for (ccl = clients; ccl; ccl = ccl->hh.next)
    {
      sendErrorReport(&ccl->fd ,errNo, msg);
    }
  }

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
      printf("%i: %s\n", cl->fd, socketToStr(cl->fd, true, buf, BUF_SIZE));
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
  FILE* fh;
  char  cbuf[LINE_BUF_SIZE];
  char* cpos;
  int last_command = CMD_ID_UNKNOWN;

  fh = fopen(fileName, "rt");
  if (fh == NULL)
  {
    ERRORF("Error: Failed to open the script '%s'\n", fileName);
    return CMD_ID_RUN;
  }

  while (fgets(cbuf, LINE_BUF_SIZE, fh))
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
 * Display the given text on the screen. A new line will be added at the end.
 * 
 * @param text the text to be printed.
 * 
 * @return CMD_ID_ECHO
 * 
 * @since 0.5.1.0
 */
int printText(char* text)
{
  if (text == NULL)
  {
    text = "";
  }
  printf ("%s\n", text);
  
  return CMD_ID_ECHO;
}

/**
 * Wait for a client to connect but no longer than 60 seconds
 * 
 * @param clientIP The IP of the client
 * 
 * @return CMD_ID_WAIT_CLIENT 
 * 
 * @since 0.5.1.0
 */
int waitForClient(char* clientIP)
{
  int  timeout = 60;
  bool found = hasClient(clientIP);
  
  // initialize flags
  inWait = true;
  ctrl_c = false;
  char* space = " ";
  
  if (clientIP != NULL)
  {
    printf("Waiting for client (%s)", clientIP);
    while (!found && (timeout != 0) && !ctrl_c)
    {
      space = "";
      found = hasClient(clientIP);
      found = false;
      if (!found && !ctrl_c)
      {
        printf(".");
        sleep(1);
        timeout--;
      }
    }
    printf("%s%s!\n", space, found ? "connected" 
                                   : ctrl_c ? "stopped" : "timeout");
  }
  else
  {
    printf("No IP provided!\n");
  }
  
  // clear flags
  ctrl_c = false;
  inWait = false;
    
  return CMD_ID_WAIT_CLIENT;
}

/**
 * This function waits until any key was pressed.
 * 
 * @param prompt Contains the prompt. If not provided the default prompt will 
 *               be used.
 * 
 * @return CMD_ID_PAUSE 
 */
int doPause(char* text)
{
  printf("%s ", text != NULL ? text : "Press any key to continue!");
  fgetc(stdin);   
  return CMD_ID_PAUSE;
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
/** List of commands for auto completion. */
char* commands[] = {
  "verbose",
  "cache",
  "version",
  "help",
  "credits",
  "sessionID",
  "empty",
  "append",
  "add",
  "addNow",
  "keyLoc",
  "addKey",
  "addKeyNow",
  "remove",
  "removeNow",
  "error",
  "notify",
  "reset",
  "clients",
  "run",
  "sleep",
  "quit",
  "exit",
  "echo",
  "waitFor",
  "pause",
  "*",
  NULL};

char** command_completion(const char *, int, int);
char*  command_generator(const char *, int);

char** command_completion(const char *text, int start, int end)
{
  rl_attempted_completion_over = 1;
  return rl_completion_matches(text, command_generator);
}

char* command_generator(const char *text, int state)
{
  static int list_index, len;
  char *name;

  if (!state)
  {
    list_index = 0;
    len = strlen(text);
  }

  while ((name = commands[list_index++]))
  {
    if (strncmp(name, text, len) == 0)
    {
      return strdup(name);
    }
  }

  return NULL;
}

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
  CMD_CASE("keyLoc",    setKeyLocation);
  CMD_CASE("addKey",    appendRouterKey);
  CMD_CASE("addKeyNow", appendRouterKeyNow);
  CMD_CASE("remove",    removeEntries);
  CMD_CASE("removeNow", removeEntriesNow);
  CMD_CASE("error",     issueErrorReport);
  CMD_CASE("notify",    sendSerialNotifyToAllClients);
  CMD_CASE("reset",     sendCacheResetToAllClients);

  CMD_CASE("clients",   listClients);
  CMD_CASE("run",       executeScript);
  CMD_CASE("sleep",     pauseExecution);
  CMD_CASE("waitFor",   waitForClient);
  CMD_CASE("pause",     doPause);
  
  CMD_CASE("echo",      printText);

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
  char cmdLine[255];
  char historyLine[255];
  // Add auto completion
  rl_attempted_completion_function = command_completion;
  OUTPUTF(false, "Enable command auto completion - switch to file browser "
                 "using '*'\n");
  // Added trim = M0000713
  while((line = readline(USER_PROMPT)) != NULL)
  {
    line = trim(line);
    if (strcmp(line, "*")==0)
    {
      // Toggle auto completion
      if (rl_attempted_completion_function != 0)
      {
        OUTPUTF(false, "Enable file browser - switch using '*'\n");
        rl_attempted_completion_function = 0;
      }
      else
      {
        OUTPUTF(false, "Enable command auto completion - switch using '*'\n");
        rl_attempted_completion_function = command_completion;
      }
      free(line);
      continue;
    }
    snprintf(cmdLine, 255, line);
    snprintf(historyLine, 255, line);
    free(line);

    // Empty line - ignore
    if (strlen(cmdLine) == 0)
    {
      continue;
    }

    // Execute the line
    cmd = handleLine(cmdLine);
    if (cmd == CMD_ID_QUIT)
    {
      break;
    }
    else if (cmd != CMD_ID_UNKNOWN)
    {
      // Store so that the user does not have to type it again
      add_history(historyLine);
    }
  }

  if (write_history(HISTORY_FILENAME) != 0)
  {
    printf("Failed writing history file '%s'\n", HISTORY_FILENAME);
  }
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

      // free ski and key allocations
      if(cEntry->isKey)
      {
        if (cEntry->ski)
        {
          free(cEntry->ski);
          cEntry->ski = NULL;
        }
        if (cEntry->pPubKeyData)
        {
          free(cEntry->pPubKeyData);
          cEntry->pPubKeyData = NULL;
        }
      }

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

/** 
 * Use the log level specified or if verbose is enabled.
 * 
 * @param level The log level of the message/
 * @param fmt The format string
 * @param args The argument list matching the format string.
 */
void printLogMessage(LogLevel level, const char* fmt, va_list args)
{
  if ((level == getLogLevel()) || verbose)
  {
    putc('\r', stdout);
    vprintf(fmt, args);
    printf("\n");
    OPROMPT();
  }
}

/**
 * This handler deals with SIGINT signals and relaces the old handler.
 *
 * @param signal
 */
void handleSigInt(int signal)
{
  if (!inWait)
  {
    printf ("\nUse command 'exit'\n");
  }
  ctrl_c = true;
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
  cache.version       = 1; // cache version

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

/**
 * Print the program syntax on stdio
 *
 * @param prgName The program name.
 *
 * @since 0.5.0.0
 */
static void syntax(const char* prgName)
{
  printf ("Syntax: %s [options] [port [script]]\n", prgName);
  printf ("  options:\n");
  printf ("    -f <script>  A script that has to be executed as soon as\n");
  printf ("                 the server is started.\n");
  printf ("    -D <level>   Set the logging level ERROR(%i) to DEBUG(%i)\n\n",
                            LEVEL_ERROR, LEVEL_DEBUG);
  printf ("  For backwards compatibility a script also can be added after a\n");
  printf ("  port is specified.! - For future usage, use -f <script> to \n");
  printf ("  specify a script!\n");
  printf ("  If No port is specified the default port %u is used.\n",
          DEF_RPKI_PORT);
  printf ("\n");
  showVersion();
}

/**
 * Parses the program parameters and set the configuration. This function
 * returns true if the program can continue and the exit Value.
 *
 * @param argc    The argument count
 * @param argv    The Argument array
 * @param cfg     The program configuration
 * @param exitVal The exit value pointer if needed
 *
 * @return true if the program can continue, false if it should be ended.
 *
 * @since 0.5.0.0
 */
static bool parseParams(int argc, const char* argv[],
                        RPKI_SRV_Configuration* cfg, int* exitVal)
{
  bool retVal = true;
  int  eVal   = 0;
  bool doHelp = false;
  char* arg   = NULL;
  int idx     = 0;
  
  #define HMSG " - try '-?' for more info"

  for (idx = 1; (idx < argc) && !doHelp && retVal; idx++)
  {
    arg = (char*)argv[idx];
    if (arg[0] == '-')
    {
      arg++;
      if (strcmp(arg, "-help") == 0)
      {
        doHelp = true;
      }
      else switch(arg[0])
      {
        case 'h':
        case 'H':
        case '?':
          doHelp = true;
          break;
        case 'D':
          idx++;
          if (idx < argc)
          {
            int logLevel = atoi(argv[idx]);
            if ((logLevel >= LEVEL_ERROR) && (logLevel <= LEVEL_DEBUG))
            {
              setLogLevel(logLevel);
            }
            else
            {
              printf ("ERROR: Invalid log level!\n");
              printf ("  Accepted values range from ERROR(%i) to DEBUG(%i)\n",
                      LEVEL_ERROR, LEVEL_DEBUG);
              retVal = false;
              eVal   = 1;
            }
          }
          else
          {
            printf ("ERROR: Log level missing%s!\n", HMSG);
            retVal = false;
            eVal   = 1;
          }
          break;
          break;
        case 'f':
          if (cfg->script == NULL)
          {
            idx++;
            if (idx < argc)
            {
              cfg->script = (char*)argv[idx];
            }
            else
            {
              printf ("ERROR: filename missing%s!\n", HMSG);
              retVal = false;
              eVal   = 1;
            }
          }
          else
          {
            printf ("ERROR: Script already added%s!\n", HMSG);
            retVal = false;            
            eVal   = 1;
          }    
          break;
        default:
          printf ("ERROR: Invalid parameter '%s'%s!\n", arg, HMSG);
          retVal = false;
          eVal   = 1;
          break;
      }
    }
    else if ((strcmp(arg, "help") == 0) || (arg[0] == '?'))
    {
      doHelp = true;
    }
    else if (cfg->port == 0)
    {
      cfg->port = strtol(arg, NULL, 10);
    }
    else
    {
      if (cfg->script == NULL)
      {
        cfg->script = arg;
        printf ("WARNING: Script added but use -f <script> to add scripts in "
                "the future.\n");
      }
      else
      {
        printf ("ERROR: Script already added%s!\n", HMSG);
        retVal = false;
      }
    }
  }

  if (doHelp)
  {
    syntax(argv[0]);
    retVal = false;
  }

  // Configure the default port if not specified otherwise.
  if (cfg->port == 0)
  {
    cfg->port = DEF_RPKI_PORT;
  }

  if (exitVal != NULL)
  {
    *exitVal = eVal;
  }

  return retVal;
}

/**
 * Start the RPKI Test Harness.
 *
 * @param argc The number of arguments passed to the program
 * @param argv The arguments passed to the program
 *
 * @return The program exit level.
 */
int main(int argc, const char* argv[])
{
  pthread_t rlthread;
  int       ret = 0;
  
  // Disable printout buffering.
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
  
  RPKI_SRV_Configuration config;
  memset(&config, 0, sizeof(RPKI_SRV_Configuration));
  // Initialize keyLocation
  setKeyLocation(NULL);

  setLogLevel(LEVEL_WARNING);

  if (!parseParams(argc, argv, &config, &ret))
  {
    return ret;
  }

  printf("Start %s using port %u\n", RPKI_RTR_SRV_NAME, config.port);
  // Output all log messages to stderr
  setLogMethodToCallback(printLogMessage);

  // Initialize the cache
  if (!setupCache())
  {
    return -2;
  }

  // Bind to the port
  if (!createServerSocket(&svrSocket, config.port, true))
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
    struct sigaction new_sigaction, old_sigaction;
    new_sigaction.sa_handler = handleSigInt;
    sigemptyset(&new_sigaction.sa_mask);
    new_sigaction.sa_flags = 0;

    sigaction (SIGINT, NULL, &old_sigaction);
    if (old_sigaction.sa_handler != SIG_IGN)
    {
      sigaction(SIGINT, &new_sigaction, NULL);
    }
    sigaction (SIGHUP, NULL, &old_sigaction);

    if (old_sigaction.sa_handler != SIG_IGN)
    {
      sigaction (SIGHUP, &new_sigaction, NULL);
    }
    sigaction (SIGTERM, NULL, &old_sigaction);

    if (old_sigaction.sa_handler != SIG_IGN)
    {
      sigaction (SIGTERM, &new_sigaction, NULL);
    }

    //signal(SIGINT, handleSigInt);

    ret = 0;
    bool doContiunue = true;
    if (config.script != NULL)
    {
      doContiunue = executeScript(config.script) != CMD_ID_QUIT;
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
  memset(keyLocation, 0, LINE_BUF_SIZE);

  return ret;
}
