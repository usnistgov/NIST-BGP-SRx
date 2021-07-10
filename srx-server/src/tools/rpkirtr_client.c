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
 * @version 0.6.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.6.0.0  - 2021/03/30 - oborchert
 *            * Added missing version control. Also moved modifications labeled 
 *              as version 0.5.2.0 to 0.6.0.0 (0.5.2.0 was skipped)
 *          - 2021/02/26 - kyehwanl
 *            * Removed aspaCallback.
 *          - 2021/02/16 - oborchert
 *            * Added aspaCallback.
 *  0.5.1.1 - 2020/07/31 - oborchert
 *            * Use define SRX_DEV_TOYEAR for year printout.
 *  0.5.0.4 - 2018/03/09 - oborchert
 *            * Do not print starting string on single run except if verbose is 
 *              enabled.
 *          - 2018/03/07 - oborchert
 *            * Modified setting of st_verbose and st_debug. Also modified
 *              logging according to the st_... values.
 *          - 2018/03/06 - oborchert
 *            * Renamed printReset and printPrefix into handle... 
 *            * Added information if client can downgrade if protocol is 
 *              larger than cache protocol.
 *            * Added Program header printout.
 *          - 2018/03/01 - oborchert
 *            * BZ1264: Fixed define DEF_FMT_WD to correct default withdrawal 
 *              formating.
 *            * Added usage of readline to command for non single run.
 *  0.5.0.3 - 2018/02/22 - oborchert
 *            * Added version printout to program start.
 *            * Fixed syntax printout.
 *            * Moved some defines into rpki_router.h header file.
 *            * Added rpki_packet_printer.h
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
#include <readline/readline.h>
#include "shared/rpki_router.h"
#include "server/rpki_packet_printer.h"
#include "server/rpki_router_client.h"
#include "util/log.h"
#include "util/prefix.h"
#include "util/io_util.h"
#include "util/str.h"

/** The default RPKI port (rfc6810) */
#define DEF_FMT_AN "+ %u %s(%u)"
#define DEF_FMT_WD "- %u %s(%u)"

#define SRX_TOOLS_CACHE_CLIENT_NAME "RPKI Cache Client Tester"

#define CMD_SERIAL_QUERY        's'
#define CMD_RESET_QUERY         'r'
#define CMD_QUIT_CLIENT         'q'
#define CMD_HELP_CLIENT         'h'
#define CMD_SEND_ERR_LAST_PD    'e'
#define CMD_DEBUG_REC           '1'
#define CMD_DEBUG_SND           '2'

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
 * Static parameter to indicate if received packages to be printed.
 * @since 0.5.0.4
 */
static bool st_print_receive = false;

/**
 * Static parameter to indicate if send packages to be printed.
 * @since 0.5.0.4
 */
static bool st_print_send = false;

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
void handlePrefix(uint32_t valCacheID, uint16_t sessionID,
                  bool isAnn, IPPrefix* prefix, uint16_t maxLen, uint32_t oas,
                  void* _u)
{
  char prefixBuf[MAX_PREFIX_STR_LEN_V6];

  if (isAnn)
  {
    if (st_add_format[0] != 0)
    {
      printf (st_add_format, oas,
              ipPrefixToStr(prefix, prefixBuf, MAX_PREFIX_STR_LEN_V6), maxLen);
    }
  } 
  else
  {
    if (st_del_format[0] != 0)
    {
      printf (st_del_format, oas,
              ipPrefixToStr(prefix, prefixBuf, MAX_PREFIX_STR_LEN_V6), maxLen);
    }
  }
}

/**
 * Only adds a log entry
 */
void handleReset()
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
void handleASPA(uint32_t valCacheID, uint16_t sessionID, bool isAnn,
                uint8_t afi, uint32_t customerAS, uint16_t providerCt, 
                uint32_t* providerASList, void* _u)
{
  
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
  return errNo == RPKI_EC_NO_DATA_AVAILABLE; // Keep the connection only if not 
                                             // fatal
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
    printf ("\nSyntax: %s [options] [<host> [<port>]]\n\n", prgName);
    printf (" Options:\n");
    printf ("     -h, -H, -? --help\n"
            "         This screen.\n");
    printf ("     -D\n"
            "         Enable debug output.\n");
    printf ("     -v\n"
            "         Verbose.\n");
    printf ("     -pr\n"
            "         Print receive.\n");
    printf ("     -ps\n"
            "         Print send.\n");
    printf ("     -s\n"
            "         Perform only a single run.\n");
    printf ("     -a <format>\n"
            "         The printout format for announcements.\n");
    printf ("     -w <format>\n"
            "         The printout format for withdrawals.\n");
    printf ("     -V <0|1>\n"
            "         Version for RPKI router client.\n");
    printf ("     -d\n"
            "         Allow downgrading to Version 0 (only for -V 1)\n\n");
    printf (" format:\n");
    printf ("    The default format is \"%s\" for announcements and\n"
            "    \"%s\" for withdrawals.\n", DEF_FMT_AN, DEF_FMT_WD);
    printf ("    The order in which the data is printed is ASN, Prefix, Maxlen");
    printf ("\n    This means the formating string must contain the order");
    printf ("\n    integer - string - integer");
    printf ("\n\n 2010-%s ANTD NIST - Version %s\n", SRX_DEV_TOYEAR, SRX_TOOLS_VERSION);
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
  char* arg     = NULL;
  bool  retVal  = true;
  bool  doHelp  = false;
  // Determine if a parameter switch is provided
  bool  pSwitch = false;
  bool  isA     = false;
  int idx = 0;

  *exitVal = 0;

  // serverhost MUST be NULL to indicate if it is set already
  params->serverHost = NULL;
  // serverPort MUST be set to 0 to indicate if it is set already
  params->serverPort = 0;
  // The protocol version to be used
  params->version    = RPKI_RTR_PROTOCOL_VERSION;

  for (idx = 1; (idx < argc) && !doHelp && !*exitVal; idx++)
  {
    arg = (char*)argv[idx];
    pSwitch = false;
    
    switch (arg[0])
    {
      case '-' :
        pSwitch = true;
        break;
      case '?' :
        doHelp = true;
      default:
        break;
    }
    
    if (pSwitch)
    {
      // Move over the '-'
      arg++;
      isA = false;

      switch (arg[0])
      {
        case 'h':
        case 'H':
        case '?':
          doHelp = true;
          break;
        case 'D':
          // Add debug information
          st_debug   = true;
          // Debugging requires verbose to be enabled - no break here
        case 'v':
          // Add verbose information.
          st_verbose = true;
          break;
        case 'p':
          if (strlen(arg) == 2)
          {
            if (arg[1] == 'r')
            {
              st_print_receive = true;
            }
            else if (arg[1] == 's')
            {
              st_print_send = true;
            }
          }
          else
          {
            printf ("Error: Invalid print parameter '-%s'!\n", arg);
            *exitVal = 1;            
          }
          break;
        case 's':
          // Perform a single request only
          st_single_request = true;
          break;
        case 'V':
          if (++idx < argc)
          {
            params->version= atoi(argv[idx]);
          }
          else
          {
            printf ("Error: Version 0|1 is missing!\n");
            *exitVal = 1;
            doHelp = true;
          }
          if (params->version > RPKI_RTR_PROTOCOL_VERSION)
          {
            printf ("Error: Invalid version number %u!\n", params->version);
            *exitVal = 1;
            doHelp = true;            
          }
          break;
        case 'd':
          params->allowDowngrade = true;
          break;
        case 'a':
          isA = true;
        case 'w':
          idx++;
          if (idx < argc)
          {
            arg = argv[idx];
            snprintf(isA ? st_add_format : st_del_format, 256, "%s\n", arg);
          }
          else
          {
            printf ("Parameter 'format' is missing!\n");
            doHelp   = true;
            *exitVal = 1;
          }
          break;
        case '-':
          if (strcmp(arg, "-help") == 0)
          {
            doHelp = true;
            break;
          }
        default:
          printf ("Invalid parameter '%s'\n", arg);
          doHelp = true;
          *exitVal = 1;
          break;
      }
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

  if (doHelp)
  {
    syntax(argv[0]);
    retVal = false;
  }
  else
  {
    if (params->serverHost == NULL)
    {
      params->serverHost = RPKI_DEFAULT_CACHE;
    }
    if (params->serverPort == 0)
    {
      params->serverPort = RPKI_DEFAULT_CACHE_PORT;
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

  // Retrieve program name out of the first program argument
  char* realNamePtr = (char*)argv[0];
  char* nextPtr = strstr(realNamePtr, "/");
  while (nextPtr != NULL)
  {
    realNamePtr = nextPtr + 1;
    nextPtr = strstr(realNamePtr, "/");
  }
  
  if (!st_single_request || st_verbose)
  {
    printf ("Starting %s (%s) V%s\n", SRX_TOOLS_CACHE_CLIENT_NAME, realNamePtr,
                                      SRX_TOOLS_VERSION);
  }
  
  // Print the configures settings.
  if (st_verbose)
  {
    printf ("Use Configuration RPKT/RTR:\n");
    printf (" - Server.........: %s\n", params.serverHost);
    printf (" - Port...........: %i\n", params.serverPort);
    printf (" - Version........: %i\n", params.version);
    if (params.version > 0)
    {
      printf (" - Can Downgrade..: %s\n", params.allowDowngrade ? "on\0" 
                                                                : "off\0");
    }
  }

  // if verbose is enabled log to stdout, otherwise drop it.
  setLogMethodToFile(st_verbose ? stdout : NULL);
  // set log-level.
  setLogLevel(st_debug ? LEVEL_DEBUG : LEVEL_INFO);
  
  // Create a new client (establish connection, "Reset Query")
  params.prefixCallback               = handlePrefix;
  params.resetCallback                = handleReset;
  params.errorCallback                = handleError;
  params.routerKeyCallback            = handleRouterKey;
  //params.aspaCallback                 = handleASPA;
  params.connectionCallback           = handleConnection;
  params.endOfDataCallback            = handleEndOfData;
  params.sessionIDChangedCallback     = sessionIDChanged;
  params.sessionIDEstablishedCallback = sessionIDEstablished;
  // The following is a default PDU printer.
  params.debugRecCallback             = st_print_receive 
                                        ? doPrintRPKI_to_RTR_PDU : NULL;
  params.debugSendCallback            = st_print_send
                                        ? doPrintRPKI_to_RTR_PDU : NULL;

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
          printf ("** timeout **\n");
          // For development of Experimental ASPA we do not want to stop polling
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
    if (!st_single_request)
    {
      char* line = readline(">> ");
      if (line != NULL)
      {
        cmd = line[0];
        free(line);
        line=NULL;
      }
    }
    else 
    {
      do
      {
        cmd = au_getchar(&client.stop, 0);
      } while (cmd == '\n');
      printf ("\n");
    }
      
    switch (cmd)
    {
      case CMD_SERIAL_QUERY:
        printf ("\n");
        sendSerialQuery(&client);
        break;
      case CMD_RESET_QUERY:
        printf ("\n");
        sendResetQuery(&client);
        break;
      case CMD_QUIT_CLIENT:
        doRun = false;
        break;
      case CMD_SEND_ERR_LAST_PD:
        printf("Not implemented yet!\n");
        break;
      case CMD_DEBUG_REC:
        if (params.debugRecCallback != NULL)
        {
          params.debugRecCallback = NULL;
          printf ("Disabled debugging receiving PDUs\n");
        }
        else
        {
          params.debugRecCallback = doPrintRPKI_to_RTR_PDU;
          printf ("Enable debugging receiving PDUs\n");          
        }
        break;
      case CMD_DEBUG_SND:
        if (params.debugSendCallback != NULL)
        {
          params.debugSendCallback = NULL;
          printf ("Disabled debugging sending PDUs\n");
        }
        else
        {
          params.debugSendCallback = doPrintRPKI_to_RTR_PDU;
          printf ("Enable debugging sending PDUs\n");          
        }
        break;
      case CMD_HELP_CLIENT:
        printf ("%c = Send Serial Query\n"
                "    * Request all new PDU's\n", 
                CMD_SERIAL_QUERY);
        printf ("%c = Send Reset Query\n"
                "    * Request all PDU's known to the cache\n", 
                CMD_RESET_QUERY);
        printf ("%c = Quit the program\n", CMD_QUIT_CLIENT);
        printf ("%c = This screen\n", CMD_HELP_CLIENT);
        printf ("%c = Send the last received PDU as error.\n",
                CMD_SEND_ERR_LAST_PD);
        printf ("%c = Toggle Printing of received messages (currently %s)\n",
                CMD_DEBUG_REC, params.debugRecCallback != NULL ? "on"  : "off");
        printf ("%c = Toggle Printing of send messages (currently %s)\n",
               CMD_DEBUG_SND, params.debugSendCallback != NULL ? "on"  : "off");
        printf ("\n");
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

