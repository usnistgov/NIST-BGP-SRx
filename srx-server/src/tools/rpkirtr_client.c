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
 * This software might use libraries that are under GNU public license or
 * other licenses. Please refer to the licenses of all libraries required
 * by this software.
 *
 * Connects to an RPKI/Router Protocol server and prints all received
 * information on stdout.
 *
 * @version 0.5.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 *  0.5.0.0 - 2017/06/29 - oborchert
 *            * Added end of data handler.
 *            * Modified pringHex and calls to it to not have compiler warnings.
 *          - 2017/06/16 - kyehwanl
 *            * Updated code to use RFC8210 (former 6810-bis-9)
 *          - 2017/06/16 - oborchert
 *            * Version 0.4.1.0 is trashed and moved to 0.5.0.0
 *          - 2016/09/29 - oborchert
 *            * Modified test tool to be used as a receiver.
 *  0.3.0.0 - 2013/01/28 - oborchert
 *            * Update to be compliant to draft-ietf-sidr-rpki-rtr.26. This
 *              update does not include the secure protocol section. The protocol
 *              will still use un-encrypted plain TCP
 *  0.2.0.0 - 2011/01/07 - oborchert
 *            * Rewritten
 *  0.1.0/0 - 2010/03/31 - pgleichm
 *            * Code Created
 * -----------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include "server/rpki_router_client.h"
#include "util/log.h"
#include "util/prefix.h"
#include "util/io_util.h"

/** The default RPKI port (rfc6810) */
#define DEF_RPKI_PORT  323
#define DEF_RPKI_CACHE "localhost";
#define DEF_FMT_AN "+ %u %s(%u)"
#define DEF_FMT_WD "+ %u %s(%u)"
#define RPKI_CONNECTION_TIMEOUT 3;

/**
 * Static parameter that specifies if this runs program in debug mode or not.
 *
 * @since 0.5.0.0
 */
static bool st_debug   = false;

/**
 * Static parameter to specify additional verbose information to be printed.
 */
static bool st_verbose = false;

/**
 * Static parameter that indicates if this program should only perform a single
 * request.
 *
 * @since 0.5.0.0
 */
static bool st_single_request = false;

/**
 * Static parameter for prefix announcement format string
 *
 * @since 0.5.0.0
 */
static char st_add_format[256] = {DEF_FMT_AN "\n\0"};
/**
 * Static parameter for prefix withdrawal format string
 *
 * @since 0.5.0.0
 */
static char st_del_format[256] = {DEF_FMT_WD "\n\0"};
/*
 * RPKI/Router client handlers
 */
void printPrefix(uint32_t valCacheID, uint16_t sessionID,
                 bool isAnn, IPPrefix* prefix, uint16_t maxLen, uint32_t oas,
                 void* _u)
{
  char prefixBuf[MAX_PREFIX_STR_LEN_V6];

  if (st_debug)
  {
    LOG(LEVEL_DEBUG, "[Prefix] %s (vcd=0x%08X sessionID=0x%04X): prefix=%s-%u, "
                     "as=%u", (isAnn ? "Ann" : "Wd"), valCacheID, sessionID,
                     ipPrefixToStr(prefix, prefixBuf, MAX_PREFIX_STR_LEN_V6),
                     maxLen, oas);
  }
  else if (isAnn)
  {
    printf (st_add_format, oas,
            ipPrefixToStr(prefix, prefixBuf, MAX_PREFIX_STR_LEN_V6), maxLen);
  } else
  {
    printf (st_del_format, oas,
            ipPrefixToStr(prefix, prefixBuf, MAX_PREFIX_STR_LEN_V6), maxLen);
  }
}

/**
 * Only adds a log entry
 */
void printReset()
{
  LOG(LEVEL_INFO, "Received a Cache Reset");
}

/**
 * Print the given byte stream as a formated HEX dump
 * 
 * @param len The length of the byte buffer
 * @param buff The buffer to be printed/
 * 
 * @since 0.5.0.0
 */
static void printHex(int len, u_int8_t* buff)
{
  int idx;
  for (idx = 0; idx < len; idx++, buff++)
  {
    if (idx % 16 == 0)
    {
      printf("\n");
    }
    printf("%02x ", *buff);
  }
  printf("\n");
}

  /**
   * This function is called for each prefix announcement / withdrawal received
   * from the RPKI validation cache.
   * 
   * Here it just prints out the information received.
   *
   * @param valCacheID  This Id represents the cache. It is used to be able to
   *                    later on identify the white-list / ROA entry in case the
   *                    cache state changes.
   * @param sessionID   The cache sessionID entry for this data. It is be useful
   *                    for sessionID changes in case SRx is implementing a
   *                    performance driven approach.
   * @param isAnn       Indicates if this in an announcement or not.
   * @param oas         The as number in network format
   * @param ski         the ski buffer
   * @param keyInfo     Pointer to the key in DER format.
   * @param user        Some user data. (might be deleted later on)             // THIS MIGHT BE DELETED LATER ON
   */
void handleRouterKey(uint32_t valCacheID, uint16_t sessionID, bool isAnn,
                     uint32_t oas, const char* ski, const char* keyInfo,
                     void* _u)
{
  LOG(LEVEL_DEBUG, "[Prefix] %s (vcd=0x%08X sessionID=0x%04X): "
      "as=%u", (isAnn ? "Ann" : "Wd"), valCacheID, sessionID,
      ntohl(oas));

  printf(" ski[%p]: ", ski);
  printHex(20, (u_int8_t*)ski);
  printf("\n");

  printf(" keyInfo[%p]: ", keyInfo);
  printHex(91, (u_int8_t*)keyInfo);
}

/**
 * Just an empty shell. Here nothing is to do.
 * 
 * @param valCacheID The Validation Cache ID
 * @param sessionID The Session ID
 * @param user The user.
 * 
 * @since 0.5.0.0
 */
void handleEndOfData(uint32_t valCacheID, uint16_t sessionID, void* user)
{}

/**
 * Print the error code and message. Returns true for keeping the connection
 * active only for non fatal Error "No Data Available".
 *
 * @param errNo The error code received
 * @param msg The message associated with the error
 * @param _u come parameter (ignored)
 * @return true for keeping the connection active only for non fatal Error
 * "No Data Available".
 */
bool handleError(uint16_t errNo, const char* msg, void* _u)
{
  LOG(LEVEL_ERROR, "Received an error [%u], msg='%s'", errNo, msg);
  return errNo == 2; // Keep the connection only if not fatal
}

/**
 * Is called when the connection is lost.
 *
 * @param _u
 *
 * @return the number of seconds to sleep while continuous connection attempts
 */
int handleConnection(void* _u)
{
  LOG(LEVEL_INFO, "Establish connection");
  return 10; // seconds
}

/**
 * Is called when the session ID to the validation cache changed.
 *
 * @param valCacheID The ID of the validation cache
 * @param newSessionID The new session ID
 */
void sessionIDChanged(uint32_t valCacheID, uint16_t newSessionID)
{
  LOG(LEVEL_INFO, "SessionID changed, update internal data for cache 0x%08X "
                  "with new sessionID 0x%04X", valCacheID, newSessionID);
}
/**
 * Is called when the session ID to the validation cache is established.
 *
 * @param valCacheID The ID of the validation cache
 * @param newSessionID The new session ID
 */
void sessionIDEstablished (uint32_t valCacheID, uint16_t newSessionID)
{
  LOG(LEVEL_INFO, "New SessionID 0x%04X established for cache 0x%08X",
                  newSessionID, valCacheID);
}

/**
 * Print the syntax of this tool
 *
 * @param Program name
 *
 * @since 0.5.0.0
 */
void syntax(const char* prgName)
{
    printf ("syntax: %s [options] [<host> [<port>]]\n", prgName);
    printf (" options: -hH?Dvs --help help\n");
    printf ("   help, --help, -h, -H: This screen.\n");
    printf ("     -D: enable debug output.\n");
    printf ("     -D: enable debug output.\n");
    printf ("     -v: verbose.\n");
    printf ("     -s: perform only a single run.\n");
    printf ("     -a <format>: The printout format for announcements.\n");
    printf ("     -r <format>: The printout format for withdrawals.\n");
    printf ("     -V <0|1>: version for rpki router client.\n");
    printf (" format:\n");
    printf ("    The default format if \"%s\" for announcements and\n"
            "    \"%s\" for withdrawals.\n", DEF_FMT_AN, DEF_FMT_WD);
    printf ("    The order in which the data is printed is ASN, Prefix, Maxlen");
    printf ("\n    This means the formating string must contain the order\n");
    printf ("\n    integer - string - integer\n");
}

/**
 *
 * @param argc    The number of arguments
 * @param argv    The argument string
 * @param params  The program parameter structure
 * @param exitVal The exit value in case the program has to be stopped/
 *
 * @return false if the program has to exit.
 *
 * @since 0.5.0.0
 */
bool parseParams(int argc, char** argv, RPKIRouterClientParams* params,
                 int* exitVal)
{
  char* arg    = NULL;
  bool  retVal = true;
  bool  doHelp = false;
  int idx = 0;

  *exitVal = 0;

  params->serverHost = NULL;
  params->serverPort = 0;
  params->version = 0;

  for (idx = 1; (idx < argc) && !doHelp; idx++)
  {
    arg = (char*)argv[idx];
    if (argv[idx][0] == '-')
    {
      // Move over the '-'
      arg++;
      if (strcmp(arg, "-help") == 0)
      {
        doHelp = true;
      }
      else
      {
        bool isA = false;
        switch (arg[0])
        {
          case 'h':
          case 'H':
          case '?':
            doHelp = true;
            break;
          case 'v':
            // Add verbose information.
            st_verbose = true;
            break;
          case 'D':
            // Add debug information
            st_debug = true;
            break;
          case 's':
            // Perform a single request only
            st_single_request = true;
            break;
          case 'a':
            isA = true;
          case 'V':
            params->version= atoi(argv[2] );
            idx++;
            break;
          case 'w':
            idx++;
            if (idx < argc)
            {
              arg = argv[idx];
              if (isA) snprintf(st_add_format, 256, "%s\n", arg);
              else     snprintf(st_add_format, 256, "%s\n", arg);
            }
            else
            {
              printf ("Parameter 'format' is missing!\n");
              doHelp   = true;
              *exitVal = 1;
            }
            break;
          default:
            printf ("Invalid parameter '%s'\n", arg);
            doHelp = true;
            break;
        }
      }
    }
    else
    {
      if (strcmp(arg, "help") == 0)
      {
        doHelp = true;
      }
      else
      {
        if (params->serverHost == NULL)
        {
          params->serverHost = arg;
        }
        else if (params->serverPort == 0)
        {
          params->serverPort = strtol(arg, NULL, 10);
        }
        else
        {
          printf ("Invalid parameter '%s'\n", arg);
          doHelp   = true;
          *exitVal = 1;
        }
      }
    }
  }

  if (doHelp)
  {
    syntax(argv[0]);
    retVal = false;
  }
  else
  {
    if (params->serverHost == NULL)
    {
      params->serverHost = DEF_RPKI_CACHE;
    }
    if (params->serverPort == 0)
    {
      params->serverPort = DEF_RPKI_PORT;
    }
  }

  return retVal;
}

/*
 * The main start function of the RPKI Validation Cache Client test harness.
 */
int main(int argc, const char* argv[])
{
  RPKIRouterClientParams params;
  RPKIRouterClient client;

  int cmd     = 0;
  int exitVal = 0;

  memset (&client, 0, sizeof(RPKIRouterClient));
  memset (&params, 0, sizeof(RPKIRouterClientParams));

  if (!parseParams(argc, (char**)argv, &params, &exitVal))
  {
    return exitVal;
  }

  client.stopAfterEndOfData = st_single_request;

  // Print the configures settings.
  if (st_verbose)
  {
    printf ("Use Configuration RPKT/RTR:\n");
    printf (" - Server...: %s\n", params.serverHost);
    printf (" - Port.....: %i\n", params.serverPort);
  }

  // Send all errors and debugging to stdout
  setLogMethodToFile(st_debug ? stdout : NULL);

  // Create a new client (establish connection, "Reset Query")
  params.prefixCallback               = printPrefix;
  params.resetCallback                = printReset;
  params.errorCallback                = handleError;
  params.routerKeyCallback            = handleRouterKey;
  params.connectionCallback           = handleConnection;
  params.endOfDataCallback            = handleEndOfData;
  params.sessionIDChangedCallback     = sessionIDChanged;
  params.sessionIDEstablishedCallback = sessionIDEstablished;

  if (!createRPKIRouterClient(&client, &params, NULL))
  {
    return 3;
  }

  // Accept user-commands
  bool doRun = true;
  int  timeoutCt = RPKI_CONNECTION_TIMEOUT;
  exitVal = 0;
  while(doRun)
  {
    while (client.clSock.clientFD < 0)
    {
      sleep(1);
      timeoutCt--;
      if (client.clSock.clientFD < 0)
      {
        if (timeoutCt <= 0)
        {
          printf ("timeout\n");
          doRun = false;
          exitVal = 1;
          break;
        }
      }
    };
    if (!doRun)
    {
      continue;
    }
    do
    {
      if (!st_single_request)
      {
        printf (">> ");
      }
      cmd = au_getchar(&client.stop, 0);
    } while (cmd == '\n');

    switch (cmd)
    {
      case 's':
        sendSerialQuery(&client);
        break;
      case 'r':
        sendResetQuery(&client);
        break;
      case 'q':
        doRun = false;
        break;
      case 'h':
        printf("s = Send Serial Query - Request all new PDU's\n"
               "r = Send Reset Query  - Request all PDU's known to the cache\n"
               "q = Quit the program\n"
               "h = This screen\n"
               "e = Send the last received PDU as error.\n");
      default:
        if (client.stop)
        {
          doRun = false;
        }
        break;
    }

  }
  // Close the connection
  releaseRPKIRouterClient(&client);

  return exitVal;
}

