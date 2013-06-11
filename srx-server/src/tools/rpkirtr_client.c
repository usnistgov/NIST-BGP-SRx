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
 * @version 0.3.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 *   0.3.0 - 2013/01/28 - oborchert
 *           * Update to be compliant to draft-ietf-sidr-rpki-rtr.26. This 
 *             update does not include the secure protocol section. The protocol
 *             will still use un-encrypted plain TCP
 *   0.2.0 - 2011/01/07 - oborchert
 *           * Rewritten
 *   0.1.0 - 2010/03/31 - pgleichm
 *           * Code Created
 * -----------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include "server/rpki_router_client.h"
#include "util/log.h"
#include "util/prefix.h"

/*
 * RPKI/Router client handlers
 */
void printPrefix(uint32_t valCacheID, uint16_t sessionID,
                 bool isAnn, IPPrefix* prefix, uint16_t maxLen, uint32_t oas,
                 void* _u)
{
  char prefixBuf[MAX_PREFIX_STR_LEN_V6];

  LOG(LEVEL_INFO, "[Prefix] %s (vcd=0x%08X sessionID=0x%04X): prefix=%s-%u, "
                  "as=%u", (isAnn ? "Ann" : "Wd"), valCacheID, sessionID,
          ipPrefixToStr(prefix, prefixBuf, MAX_PREFIX_STR_LEN_V6), maxLen, oas);
}

void printReset()
{
  LOG(LEVEL_INFO, "Received a Cache Reset");
}

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

/*
 * The main start function of the RPKI Validation Cache Client test harness.
 */
int main(int argc, const char* argv[])
{
  RPKIRouterClientParams params;
  RPKIRouterClient client;
  int cmd;

  // Handle the command line
  if (argc > 3)
  {
    printf("usage: %s [<host> [<port>]]\n", argv[0]);
    return 1;
  }
  if (argc >= 2 && strcmp(argv[1], "help") == 0)
  {
    printf("usage: %s [<host> [<port>]]\n", argv[0]);
    return 0;
  }


  // Configure the settings of the RPKI_RTR server to connect to.
  params.serverHost = argc >= 2 ? argv[1] : "localhost";
  params.serverPort = argc == 3 ? strtol(argv[2], NULL, 10) : 50001;

  if ((params.serverPort == EINVAL) || (params.serverPort == ERANGE))
  {
    printf("Invalid port number '%s'\n", argv[2]);
    return 1;
  }

  // Print the configures settings.
  printf ("Use Configuration RPKT/RTR:\n");
  printf (" - Server...: %s\n", params.serverHost);
  printf (" - Port.....: %i\n", params.serverPort);

  // Send all errors to stdout
  setLogMethodToFile(stdout);

  // Create a new client (establish connection, "Reset Query")
  params.prefixCallback        = printPrefix;
  params.resetCallback         = printReset;
  params.errorCallback         = handleError;
  params.connectionCallback    = handleConnection;
  params.sessionIDChangedCallback     = sessionIDChanged;
  params.sessionIDEstablishedCallback = sessionIDEstablished;

  if (!createRPKIRouterClient(&client, &params, NULL))
  {
    return 3;
  }

  // Accept user-commands
  for (;;)
  {
    while (client.clSock.clientFD < 0)
    {
      printf(".");
      sleep(1);
      if (client.clSock.clientFD >= 0)
      {
        printf ("done.\n");
      }
    };
    printf("s = Send Serial Query - Request all new PDU's\n"
           "r = Send Reset Query  - Request all PDU's known to the cache\n"
           "q = Quit the program\n"
  //         "e = Send the last received PDU as error.\n"
           ">> ");
    do
    {
      cmd = getchar();
    } while (cmd == '\n');

    if (cmd == 's')
    {
      sendSerialQuery(&client);
    }
    else if (cmd == 'r')
    {
      sendResetQuery(&client);
    }
    else if (cmd == 'q')
    {
      break;
    }
  }

  // Close the connection
  releaseRPKIRouterClient(&client);

  return 0;
}

