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
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2016/01/21 - kyehwanl
 *            * added pthread cancel function for enabling keyboard interrupt
 * 0.3.0.10 - 2015/11/10 - oborchert
 *           * Removed unused variables.
 *           * Replaced string comparison "==" with "strcmp(...)" in doShowRPKI
 *           * Fixed bug in doShowRPKI which did use cmd in lieu of param.
 *           * Fixed bug that prevented the recognition of broken telnet console
 *             sessions.
 *           * Changed internal functions to static
 * 0.3.0.7 - 2015/04/21 - oborchert
 *           * Modified the version output.
 * 0.3.0.0 - 2013/03/20 - oborchert
 *           * Added information about receive queue settings to output of
 *             'show-srxconfig'
 *         - 2013/02/27 - oborchert
 *           * Disabled command 'doRtrGoodbye' and removed from help
 *         - 2013/02/15 - oborchert
 *           * Added command show-version.
 *           * Added number of updates per client to show-proxies
 *         - 2013/01/24 - oborchert
 *           * Modified command set-log to display the current log level if none
 *             is provided.
 *           * Removed unnecessary static statement from functions.
 *           * extended the num-updates to also include the PC-updates
 *         - 2012/12/31 - oborchert
 *           * Added dump-ucache
 *           * Fixed formating of max 80 characters per line.
 *         - 2012/12/17 - oborchert
 *           * updated num-proxies to allow showing all proxy mappings
 * 0.1.0.0 - 2011/05/24 - oborchert
 *           * Code created.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>

#include "server/configuration.h"
#include "server/console.h"
#include "server/prefix_cache.h"
#include "server/srx_server.h"
#include "server/srx_packet_sender.h"
#include "server/update_cache.h"
#include "shared/srx_defs.h"

// Needed for the reset command to allow sending resets to the rpki validation
// caches
#include "command_handler.h"
#include "rpki_handler.h"
#include "rpki_handler.h"
#include "rpki_router_client.h"

#include "util/log.h"
#include "util/server_socket.h"
#include "util/prefix.h"
#include "util/slist.h"

#define MIN_CONSOLE_BUFFER 1024
#define MAX_ROAS_TO_DIPLAY 20
#define CP1 "[console(%u)] "
#define CP2 "Process command "
#define CP1_NOPROMPT "\r\n"
#define CP1_PROMPT   "\r\n[SRx]> "
#define CP2_NOPROMPT "\r"
#define CP2_PROMPT   "\r[SRx]> "
#define CON_STDOUT   '-'

#define INITIAL_BUFFER_SIZE 1

typedef enum {
  CST_UPDATES = 0,
  CST_RPKI    = 1,
  CST_SRXCFG  = 2,
  CST_PROXIES = 3,
  CST_VERSION = 4
} ConsoleShowType;

static void* consoleLoop(void* selfPtr);
static bool sendToConsoleClient(SRXConsole* self, char* message, bool prompt);
static bool processConsoleCommand(SRXConsole* self, char* buffer,
                                   int buffLength);
static bool doProcessCommand(SRXConsole* self);
static void doHelp(SRXConsole* self, char* cmd, char* param);
static void doShowVersion(SRXConsole* self, char* cmd, char* param);
static void doClose(SRXConsole* self, char* cmd, char* param);
static bool doShutdown(SRXConsole* self, char* cmd, char* param);
static void doChangeLogLevel(SRXConsole* self, char* cmd, char* param);

static void doValCacheReset(SRXConsole* self, char* cmd, char* param);
static void doClearPrefixCache(SRXConsole* self, char* cmd, char* param);

static void doRtrSync(SRXConsole* self, char* cmd, char* param);
static void doRtrGoodbye(SRXConsole* self, char* cmd, char* param);

static void doShow(SRXConsole* self, char* cmd, char* param,
            ConsoleShowType type);

static void doNumUpdates(SRXConsole* self, char* cmd, char* param);
static void doNumPrefixes(SRXConsole* self, char* cmd, char* param);
static void doNumProxies(SRXConsole* self, char* cmd, char* param);

static void doCommandQueue(SRXConsole* self, char* cmd, char* param);
static void doDumpPCache(SRXConsole* self, char* cmd, char* param);
static void doDumpUCache(SRXConsole* self, char* cmd, char* param);

static uint32_t hexToInt(char[]);

char* CON_WELCOME_RESP = "\r\nWelcome to BGP-SRx!\r\n"
                         "=======================================\r\n";


char* CON_HELP_CMD = "help";
char* CON_HELP_RESP= "\r\nAvailable commands are:\r\n"
                 "=======================================================\r\n"
                 " close, quit, exit     Close this console!\r\n"
                 " shutdown <password>   Shutdown the SRx Server!\r\n"
                 " log-level [number]    Set/display the log level of the "
                 "server.\r\n"
                 "                       3=ERROR, 5=NOTICE, 6=INFO, 7=DEBUG\r\n"
#ifdef SRX_ALL
                 " reset-valcache        Send reset to origin validation "
                                             "cache.\r\n"
                 " empty-roacache        Clear the internal white list "
                                         "cache.\r\n"
#endif
                 " rtr-sync [proxyID]    Send synchronization request to\r\n"
                 "                       the provided proxy or all.\r\n"
#ifdef SRX_ALL
                 " rtr-goodbye [proxyID] Close the connection to provided\r\n"
                 "                       proxy or all!\r\n"
#endif
                 " show-version          Display the full version number of the"
                                         " SRx-server.\r\n"
                 " show-srxconfig        Display the configuration of the srx "
                                         "server\r\n"
#ifdef SRX_ALL
                 " show-rpki <cmd>       Display rpki data according to\r\n"
                 "                       the command string.\r\n"
                 "      cmd:= (as|prefix|count [(as|prefix)])\r\n"
                 "             as, prefix: Show the rpki-rtr data that match"
                                           " the given input\r\n"
                 "             count     : total number of rpki-rtr data"
                                           " records!\r\n"
                 "             count (as|prefix): total number of rpki-rtr\r\n"
                 "                                data record that match the "
                                                  "given data\r\n"
#endif
                 " show-update <cmd>     Display update data according to\r\n"
                 "                       the command string.\r\n"
#ifdef SRX_ALL
                 "      cmd:= (as|prefix|id <id>|count [(as|prefix)])\r\n"
                 "             as, prefix: Show the updates that match the"
                                           " given input\r\n"
                 "             id <id>   : Show the update with the ID (hex)."
                                           "\r\n"
                 "             count     : total number of updates, same as "
                                           "no-updates\r\n"
                 "             count (as|prefix): total number of updates\r\n"
                 "                                that match the given data\r\n"
                "                                for the particular update!\r\n"
#else
                 "      cmd:= id <id>    Show the update with the ID (hex)."
                                         "\r\n"
                 " show-proxies          Display the list of proxies.\r\n"
#endif
                 " num-updates           Display the number of updates "
                                             "stored in update cache!\r\n"
                 " num-prefixes          Display the number of prefixes stored"
                 "\r\n                       in the prefix cache!\r\n"
                 " num-proxies           Display the number of proxies "
                                             "attached\r\n"
                 " command-queue         Displays the content of the "
                                             "command queue.\r\n"
#ifdef SRX_ALL
                 " dump-pcache <file>    Dump the prefix cache into a file with"
                 "\r\n                       the given name.\r\n"
                 " dump-ucache <file>    Dump the update cache into a file with"
                 "\r\n                       the given name.\r\n"
#else
                 " dump-pcache           Dump the prefix cache to command line"
                 "\r\n                       of SRx!\r\n"
                 " dump-ucache           Dump the update cache to command line"
                 "\r\n                       of SRx!\r\n"
#endif
                 " !! [<parameter>]      Repeat last command with optional new"
                 "\r\n                       parameter if specified, otherwise"
                 "\r\n                       old parameter!"
                 "\r\n\r\n";

char* CON_VERSION_CMD  = "show-version";

char* CON_LASTCMD_CMD = "!!";

char* CON_CLOSE_CMD  = "close";
char* CON_QUIT_CMD   = "quit";
char* CON_EXIT_CMD   = "exit";
char* CON_CLOSE_RESP = "Goodbye!\r\n";
char* CON_LOGL_CMD   = "log-level";

char* CON_SHUT_CMD      = "shutdown";
char* CON_SHUT_RESP_OK  = "Shutdown in progress...\r\nGoodbye!\r\n";
char* CON_SHUT_RESP_NOK = "Shutdown aborted, invalid password!\r\n";
char* CON_RESET_VALCACHE_CMD = "reset-valcache";
char* CON_EMPTY_ROACACHE_CMD = "empty-roacache";

char* CON_RTR_SYNC_CMD    = "rtr-sync";
char* CON_RTR_GOODBYE_CMD = "rtr-goodbye";

char* CON_SHUPD_CMD     = "show-update";
char* CON_SHRPKI_CMD    = "show-rpki";
char* CON_SHSRX_CMD     = "show-srxconfig";
char* CON_SHPROXIES_CMD = "show-proxies";

char* CON_NOUPD_CMD    = "num-updates";
char* CON_NOPREFIX_CMD = "num-prefixes";
char* CON_NOPROXY_CMD  = "num-proxies";

char* CON_COMMAND_QUEUE   = "command-queue";
char* CON_DUMP_PCACHE_CMD = "dump-pcache";
char* CON_DUMP_UCACHE_CMD = "dump-ucache";

char* CON_NOTSUPPORTED_CMD = "Command not supported yet!\r\n";
char* CON_UNKNOWN_CMD = "I don\'t understand the command "
                                                    "- Use \'help\'!\r\n";
const char* STR_SRx_RESULT_VALID     = "VALID";
const char* STR_SRx_RESULT_NOTFOUND  = "NOTFOUND";
const char* STR_SRx_RESULT_INVALID   = "INVALID";
const char* STR_SRx_RESULT_UNDEFINED = "--";
const char* STR_SRx_RESULT_DONOTUSE  = "DO NOT USE";
const char* STR_SRxRS_SRX     = "SRx";
const char* STR_SRxRS_ROUTER  = "ROUTER";
const char* STR_SRxRS_IGP     = "IGP";
const char* STR_SRxRS_UNKNOWN = "UNKNOWN";
const char* STR_QUESTIONMARK  = "????";

/**
 * Used to allow displaying the result value as string.
 *
 * @param resSrc The result source
 *
 * @return the string representation
 */
static const char* getSRxResultStr(SRxValidationResultVal resVal)
{
  switch (resVal)
  {
    case SRx_RESULT_VALID:     return STR_SRx_RESULT_VALID;
    case SRx_RESULT_NOTFOUND:  return STR_SRx_RESULT_NOTFOUND;
    case SRx_RESULT_INVALID:   return STR_SRx_RESULT_INVALID;
    case SRx_RESULT_UNDEFINED: return STR_SRx_RESULT_UNDEFINED;
    case SRx_RESULT_DONOTUSE:  return STR_SRx_RESULT_DONOTUSE;
    default: RAISE_ERROR("Invalid result value [%u] given", resVal);
  }
  return STR_QUESTIONMARK;
}

/**
 * Used to allow displaying the result source value as string.
 *
 * @param resSrc The result source
 *
 * @return the string representation
 */
static const char* getSRxResultSrcStr(SRxResultSource resSrc)
{
  switch (resSrc)
  {
    case SRxRS_SRX:     return STR_SRxRS_SRX;
    case SRxRS_ROUTER:  return STR_SRxRS_ROUTER;
    case SRxRS_IGP:     return STR_SRxRS_IGP;
    case SRxRS_UNKNOWN: return STR_SRxRS_UNKNOWN;
    default: RAISE_ERROR("Invalid result source value [%u] given", resSrc);
  }
  return STR_QUESTIONMARK;
}

/**
 * Create the server console and binds to the server port.
 * @param self The Console itself.
 * @param port The server port to listen on.
 * @param sysConfig The system configuration
 * @param shutDown The shutdown method.
 * @param rpkiHandler The instance of the rpkiHandler.
 * @param commandHandler The command handler of the application.
 *
 * @return true if the console could be established and bound to the port.
 */
bool createConsole(SRXConsole* self, int port, ShutDownMethod shutDown,
                   Configuration* sysConfig, RPKIHandler* rpkiHandler,
                   CommandHandler* commHandler)
{
  int ret = 1;

  self->sysConfig      = sysConfig;
  self->shutDown       = shutDown;
  self->rpkiHandler    = rpkiHandler;
  self->commandHandler = commHandler;
  self->keepGoing      = true;
  self->cmdBuffSize    = INITIAL_BUFFER_SIZE;
  self->paramBuffSize  = INITIAL_BUFFER_SIZE;
  self->cmd            = malloc(INITIAL_BUFFER_SIZE);
  self->param          = malloc(INITIAL_BUFFER_SIZE);
  memset(self->cmd,   '\0', INITIAL_BUFFER_SIZE);
  memset(self->param, '\0', INITIAL_BUFFER_SIZE);

  struct sockaddr_in srvAddr;
  int yes = 1;

  // Create a TCP socket
  self->srvSockFd = socket(AF_INET, SOCK_STREAM, 0);
  if (self->srvSockFd < 0)
  {
    RAISE_SYS_ERROR("Failed to open a socket");
    return false;
  }

  // Bind to a server-address
  bzero(&srvAddr, sizeof (struct sockaddr_in));
  srvAddr.sin_family = AF_INET;
  srvAddr.sin_addr.s_addr = INADDR_ANY; // inet_pton
  srvAddr.sin_port = htons(port);

  // Inserted to be able to restart after crash without having to wait for the
  // socket to be released by the OS.
  setsockopt(self->srvSockFd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (yes));

  if (bind(self->srvSockFd, (struct sockaddr*)&srvAddr,
           sizeof (struct sockaddr_in)) < 0)
  {
    RAISE_ERROR("Failed to bind the socket to the address");
    close(self->srvSockFd);
    return false;
  }

  ret = pthread_create(&self->consoleThread, NULL, consoleLoop, (void*)self);
  if (ret > 0)
  {
    RAISE_ERROR("Failed to create the console Thread!");
    close(self->srvSockFd);
    return false;
  }

  LOG(LEVEL_INFO, "Server console on port [%u] created.", port);
  return true;
}

/**
 * Stops and releases the server console.
 *
 * @param self the server console.
 *
 * @return ture if the server console could be stopped.
 */
bool releaseConsole(SRXConsole* self)
{
  bool retVal = true;

  if (self->keepGoing)
  {
    // prepare the server thread to stop
    self->keepGoing = false;
    // Close the server socket
    close(self->srvSockFd);

    retVal = pthread_cancel(self->consoleThread);
  }

  free(self->cmd);
  free(self->param);

  return retVal;
}

/**
 * Keeps the console open. Once this method comes back the console is closed.
 *
 * @param selfPtr The pointer to the console instance.
 */
static void* consoleLoop(void* selfPtr)
{
  SRXConsole* self = (SRXConsole*)selfPtr;
  socklen_t clientLen;
  struct sockaddr_in clientAddr;

  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

  int buffLength = MIN_CONSOLE_BUFFER;
  char* buffer = malloc(buffLength);

  int bytesRead;

  listen(self->srvSockFd,1);
  clientLen = sizeof(clientAddr);

  bool keepSession;

  LOG (LEVEL_DEBUG, "([0x%08X]) > SRx Server Console Thread started!",
                    pthread_self());

  while(self->keepGoing)
  {
    self->clientSockFd = accept(self->srvSockFd,
                                (struct sockaddr *) &clientAddr,
                                &clientLen);
    if (self->clientSockFd < 0)
    {
      RAISE_ERROR("Error during establishment of console connection!");
    }
    else
    {
      LOG(LEVEL_DEBUG, CP1 "New console connection established!",
                       self->clientSockFd);
      bytesRead = 0;
      keepSession = sendToConsoleClient(self, CON_WELCOME_RESP, true);
      while (keepSession)
      {
        bzero(buffer, buffLength);
        bytesRead = read(self->clientSockFd, buffer, buffLength);
        if (bytesRead <= 0)
        {
          keepSession = false;
          if (bytesRead != 0)
          {
            LOG(LEVEL_INFO, "Error reading console data, close connection!");
          }
          else
          {
            LOG(LEVEL_INFO, "Peer closed connection!");
          }
        }
        else
        {
          // Shorten \r\n\t and white space
          while (    (buffer[bytesRead] == '\n')
                  || (buffer[bytesRead] == '\r')
                  || (buffer[bytesRead] == ' ')
                  || (buffer[bytesRead] == '\t'))
          {
            bytesRead--;
          }
          keepSession = processConsoleCommand(self, buffer, bytesRead);
        }
      }
    }
    close (self->clientSockFd);
  }
  free (buffer);

  LOG (LEVEL_DEBUG, "([0x%08X]) > SRx Server Console Thread stopped!",
                    pthread_self());

  pthread_exit(0);
}

/**
 * This function processes the console command.
 *
 * @param self The pointer to the console.
 * @param buffer The data buffer received from the client.
 * @param buffLength The length of data within the buffer.
 *
 * @return false if the connection has to be closed. True, the connection has
 *               to be kept open.
 */
static bool processConsoleCommand(SRXConsole* self, char* buffer, int buffLength)
{
  char* strStart  = buffer;
  char* strPtr    = buffer;
  int cmdLen      = 0;
  int paramLen    = 0;
  int pos         = 0;
  bool retVal     = true;
  bool newCmd     = false;

  // Determine if the telnet client needs \n in the message
  if (buffLength > 0)
  {
    if (buffLength > 1)
    {
      self->prependNextLine =    (buffer[buffLength-1] != '\n')
                              && (buffer[buffLength-2] != '\n');
    }
    else
    {
      self->prependNextLine =    (buffer[buffLength-1] != '\n');
    }
  }
  else
  {
    self->prependNextLine = true;
  }

  // Not get the command and parameter

  // Find first non white character
  while((pos < buffLength) && ((*strPtr == ' ') || (*strPtr == '\t')))
  {
    strPtr++; // skip all leading blanks.
    pos++;
  }
  strStart = strPtr;
  // now determine the length of the command
  while((pos < buffLength) && (   (*strPtr != ' ' ) && (*strPtr != '\t')
                               && (*strPtr != '\n') && (*strPtr != '\r')))
  {
    cmdLen++; // calculate the cmd length
    strPtr++; // move string pointer to the end of the command.
    pos++;    // The position within the string buffer.
  }
  // Generate the memory needed for the command string

  // Check if a new command or the old one is to repeated!
  if (strncmp(strStart, CON_LASTCMD_CMD, cmdLen) != 0)
  {
     // New command. adjust the buffer size if needed.
    if (cmdLen+1 > self->cmdBuffSize)
    {
      self->cmdBuffSize = cmdLen+1;
      self->cmd = realloc(self->cmd, self->cmdBuffSize);
    }
    newCmd = true;
  }

  // If new command, write it into the command field.
  if (newCmd)
  {
    // initialize the buffer and then copy the new command into it.
    memset(self->cmd, '\0', self->cmdBuffSize);
    memcpy(self->cmd, strStart, cmdLen);
  }
  // now redetermine the command length
  cmdLen = strlen(self->cmd);

  // Now move the pointer to the first parameter
  while((pos < buffLength) && (   (*strPtr == ' ' ) || (*strPtr == '\t')
                               || (*strPtr == '\n') || (*strPtr == '\r')))
  {
    strPtr++; // skip all leading blanks.
    pos++;
  }
  // Set the string start to the parameter (if it exists that is)
  strStart = strPtr;

  // now determine the length of the parameters
  while((pos < buffLength) && ((*strPtr != '\n') && (*strPtr != '\r')))
  {
    strPtr++;   // move the string pointer to the end of the parameter
    paramLen++; // Count the characters of the parameter string
    pos++;
  }

  // In case it is not a new parameter => the repeat command "!!" and the
  // parameter length is 0 then use the previous parameter
  if (paramLen > 0)
  {
    // Determine if the parameter buffer is big enough or if it has to be
    // adjusted
    if (self->paramBuffSize < (paramLen+1))
    {
      self->paramBuffSize = paramLen+1;
      self->param = realloc(self->param, self->paramBuffSize);
    }
    memset(self->param, '\0', self->paramBuffSize);
    memcpy(self->param, strStart, paramLen);
  }
  else if (newCmd)
  {
    // new Command and no parameter, clear the parameter buffer
    memset(self->param, '\0', self->paramBuffSize);
  }

  if (cmdLen > 0)
  {
    retVal = doProcessCommand(self);
  }
  else
  {
    sendToConsoleClient(self, "", true);
  }

  return retVal;
}

/**
 * Send the given string using the provided file descriptor.
 *
 * @param self The server console
 * @param message The message to be send.
 * @param prompt Add the prompt at the end or just '\r\n'.
 *
 * @return true if the data could be send, otherwise false.
 */
static bool sendToConsoleClient(SRXConsole* self, char* message, bool prompt)
{
  int noBytes = strlen(message);
  bool retVal = false;
  char* end = self->prependNextLine ? (prompt ? "\n" CP1_PROMPT
                                              : "\n" CP1_NOPROMPT)
                                    : (prompt ? CP2_PROMPT
                                              : CP2_NOPROMPT);
  if (write(self->clientSockFd, message, noBytes) == noBytes)
  {
    noBytes = strlen(end);
    retVal = write(self->clientSockFd, end, noBytes) == noBytes;
  }
  return retVal;
}

/**
 * Answer to client that the provided command is not supported yet!.
 *
 * @param self The console instance
 *
 * @return true if the data could be send, otherwise false.
 */
static bool cmdNotSupportedYet(SRXConsole* self)
{
  return sendToConsoleClient(self, CON_NOTSUPPORTED_CMD, true);
}

/**
 * Process the given command.
 *
 * @param self The command console.
 * @param cmd The command (NOT NULL).
 * @param param The parameter (NOT NULL).
 *
 * @return false the session has to be closed, otherwise true.
 */
static bool doProcessCommand(SRXConsole* self)
{
  bool retVal = true;
  char* cmd  = self->cmd;
  char*param = self->param;

  if (cmd == NULL)
  {
    RAISE_SYS_ERROR("console Command MUST not be NULL!");
    return false;
  }
  if (param == NULL)
  {
    RAISE_SYS_ERROR("Console Parameter MUST not be NULL!");
    return false;
  }

  int cmdLen = strlen(cmd);

  // Now check what was received
  // HELP RECEIVED
  if (    (cmdLen == strlen(CON_HELP_CMD))
       && (strncmp(CON_HELP_CMD, cmd, cmdLen)==0))
  {
    doHelp(self, cmd, param);
  }
  // show-version received
  else if (    (cmdLen == strlen(CON_VERSION_CMD))
       && (strncmp(CON_VERSION_CMD, cmd, cmdLen)==0))
  {
    doShow(self, cmd, param, CST_VERSION);
  }
  // CLOSE RECEIVED
  else if (    (cmdLen == strlen(CON_CLOSE_CMD))
            && (strncmp(CON_CLOSE_CMD, cmd, cmdLen)==0))
  {
    doClose(self, cmd, param);
    retVal = false;
  }
  // QUIT RECEIVED
  else if (    (cmdLen == strlen(CON_QUIT_CMD))
            && (strncmp(CON_QUIT_CMD, cmd, cmdLen)==0))
  {
    doClose(self, cmd, param);
    retVal = false;
  }
  // EXIT RECEIVED
  else if (    (cmdLen == strlen(CON_EXIT_CMD))
            && (strncmp(CON_EXIT_CMD, cmd, cmdLen)==0))
  {
    doClose(self, cmd, param);
    retVal = false;
  }
  // SHUTDOWN RECEIVED!
  else if (    (cmdLen == strlen(CON_SHUT_CMD))
            && (strncmp(CON_SHUT_CMD, cmd, cmdLen)==0))
  {
    // In case a shutdown is allowed the result must be set to false.
    // The value is written into keepGoing! -> !shutdown == keepGoing
    retVal = !doShutdown(self, cmd, param);
  }
  // Change LOG LEVEL
  else if (    (cmdLen == strlen(CON_LOGL_CMD))
            && (strncmp(CON_LOGL_CMD, cmd, cmdLen)==0))
  {
    doChangeLogLevel(self, cmd, param);
  }
  // SEND RESET REQUEST TO VALIDATION CACHE
  else if (    (cmdLen == strlen(CON_RESET_VALCACHE_CMD))
            && (strncmp(CON_RESET_VALCACHE_CMD, cmd, cmdLen)==0))
  {
    doValCacheReset(self, cmd, param);
  }
  // CLEAR INTERNAL VALIDATION CACHE
  else if (    (cmdLen == strlen(CON_EMPTY_ROACACHE_CMD))
            && (strncmp(CON_EMPTY_ROACACHE_CMD, cmd, cmdLen)==0))
  {
    doClearPrefixCache(self, cmd, param);
  }
  // GOODBYE RECEIVED
  else if (    (cmdLen == strlen(CON_RTR_GOODBYE_CMD))
            && (strncmp(CON_RTR_GOODBYE_CMD, cmd, cmdLen)==0))
  {
    doRtrGoodbye(self, cmd, param);
  }
  // SYNCH REQUEST
  else if (    (cmdLen == strlen(CON_RTR_SYNC_CMD))
            && (strncmp(CON_RTR_SYNC_CMD, cmd, cmdLen)==0))
  {
    doRtrSync(self, cmd, param);
  }
  // show-updates command
  else if (    (cmdLen == strlen(CON_SHUPD_CMD))
            && (strncmp(CON_SHUPD_CMD, cmd, cmdLen)==0))
  {
    doShow(self, cmd, param, CST_UPDATES);
  }
  // show-rpki command
  else if (    (cmdLen == strlen(CON_SHRPKI_CMD))
            && (strncmp(CON_SHRPKI_CMD, cmd, cmdLen)==0))
  {
    doShow(self, cmd, param, CST_RPKI);
  }
  // show-srxproxy command
  else if (    (cmdLen == strlen(CON_SHSRX_CMD))
            && (strncmp(CON_SHSRX_CMD, cmd, cmdLen)==0))
  {
    doShow(self, cmd, param, CST_SRXCFG);
  }
  else if (    (cmdLen == strlen(CON_SHPROXIES_CMD))
            && (strncmp(CON_SHPROXIES_CMD, cmd, cmdLen)==0))
  {
    doShow(self, cmd, param, CST_PROXIES);
  }
  // number of unique updates in total
  else if (    (cmdLen == strlen(CON_NOUPD_CMD))
            && (strncmp(CON_NOUPD_CMD, cmd, cmdLen)==0))
  {
    doNumUpdates(self, cmd, param);
  }
  // number of white list entries in total
  else if (    (cmdLen == strlen(CON_NOPREFIX_CMD))
            && (strncmp(CON_NOPREFIX_CMD, cmd, cmdLen)==0))
  {
    doNumPrefixes(self, cmd, param);
  }
  // number of proxy clients in total
  else if (    (cmdLen == strlen(CON_NOPROXY_CMD))
            && (strncmp(CON_NOPROXY_CMD, cmd, cmdLen)==0))
  {
    doNumProxies(self, cmd, param);
  }
  // number of proxy clients in total
  else if (    (cmdLen == strlen(CON_COMMAND_QUEUE))
            && (strncmp(CON_COMMAND_QUEUE, cmd, cmdLen)==0))
  {
    doCommandQueue(self, cmd, param);
  }
  // dump the prefix cache
  else if (    (cmdLen == strlen(CON_DUMP_PCACHE_CMD))
            && (strncmp(CON_DUMP_PCACHE_CMD, cmd, cmdLen)==0))
  {
    doDumpPCache(self, cmd, param);
  }
  // dump the update cache
  else if (    (cmdLen == strlen(CON_DUMP_UCACHE_CMD))
            && (strncmp(CON_DUMP_UCACHE_CMD, cmd, cmdLen)==0))
  {
    doDumpUCache(self, cmd, param);
  }

  else
  {
    sendToConsoleClient(self, CON_UNKNOWN_CMD, true);
  }

  return retVal;
}

////////////////////////////////////////////////////////////////////////////////
// CONSOLE COMMANDS
////////////////////////////////////////////////////////////////////////////////

/**
 * Processes the help command and displays the commands available.
 *
 * @param self The Console instance
 * @param cmd The help command
 * @param param The help parameter
 *
 * @return true if the command was processed properly.
 */
static void doHelp(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "%s %s", self->clientSockFd, cmd, param);
  sendToConsoleClient(self, CON_HELP_RESP, true);
}

/**
 * Processes the help command and displays the commands available.
 *
 * @param self The Console instance
 * @param cmd The help command
 * @param param The help parameter
 *
 * @return true if the command was processed properly.
 */
static void doShowVersion(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "%s %s", self->clientSockFd, cmd, param);
  char out[256];
  memset(out, '\0', 256);
  sprintf (out, "SRx-Server Version%s\r\n", SRX_SERVER_FULL_VER);
  sendToConsoleClient(self, out, true);
}

/**
 * The console closes, send a goodbye.
 *
 * @param self The console itself
 * @param cmd The console command
 * @param param The command parameter
 */
static void doClose(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "%s %s", self->clientSockFd, cmd, param);
  sendToConsoleClient(self, CON_CLOSE_RESP, true);
}

/**
 * Checks if a shutdown is allowed. If so the return value is true, otherwise it
 * if false. In case a shutdown is allowed the shutdown flag of the console
 * instance is set to true.
 *
 * @param self The console instance.
 * @param cmd The shutdown command
 * @param param The password that must match the configuration password.
 *
 * @return true if a shutdown can be performed.
 */
static bool doShutdown(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "%s %s", self->clientSockFd, cmd, param);
  bool retVal = true;
  char* pwd = self->sysConfig->console_password == NULL
        ? "\0" : self->sysConfig->console_password;

  if (   (strlen(param) == strlen(pwd))
      && (strncmp(param, pwd, strlen(pwd)) == 0))
  {
    if (self->shutDown != NULL)
    {
      LOG(LEVEL_DEBUG, "Initiate server shutdown");
      // Just line bread, no new prompt
      sendToConsoleClient(self, CON_CLOSE_RESP, false);
      self->shutDown();
    }
    else
    {
      RAISE_ERROR("No shutdown method registered.");
      sendToConsoleClient(self, "Error: Cannot shutdown, no "
                          "shutdown method registered!\r\n",true);
      retVal = false;
    }
  }
  else
  {
    LOG(LEVEL_INFO, "Invalid password provided, system shutdown aborted!");
    // Spread some fear ;-)
    sendToConsoleClient(self, "Warning: Insufficient "
                              "privileges to shutdown the server!\r\n"
                              "         Incident is logged!\r\n", true);
    retVal = false;
  }

  return retVal;
}

/**
 * Change or display the current log-level of the SRx server.
 *
 * @param self The console itself.
 * @param cmd the console command.
 * @param param The parameter of the command.
 */
static void doChangeLogLevel(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "%s %s", self->clientSockFd, cmd, param);
  char* changed    = "LogLevel changed to %u!\r\n%s";
  char* invalid    = "Invalid LogLevel '%s'!\r\n%s";
  char* current    = "Current Level: %u - %s\r\n%s";
  char* legend     = "  [3=ERROR, 4=WARNING, 5=NOTICE, 6=INFO, 7=DEBUG]\r\n";

  char buffer[256];
  memset(buffer, '\0', 256);

  if (strlen(param) > 0)
  {
    switch (*param)
    {
      case '3': // ERROR
      case '4': // WARNING
      case '5': // NOTICE
      case '6': // INFO
      case '7': // DEBUG
        setLogLevel((LogLevel)(*param-'0'));// translate the char number to int
        sprintf(buffer, changed, getLogLevel(), legend);
        break;
      default:
        sprintf(buffer, invalid, param, legend);
    }
  }
  else
  {
    char* levelStr = NULL;
    LogLevel ll = getLogLevel();
    switch (ll)
    {
      case LEVEL_ERROR:
        levelStr = "ERROR";
        break;
      case LEVEL_WARNING:
        levelStr = "WARNING";
        break;
      case LEVEL_NOTICE:
        levelStr = "NOTICE";
        break;
      case LEVEL_INFO:
        levelStr = "INFO";
        break;
      case LEVEL_DEBUG:
        levelStr = "DEBUG";
        break;
      default:
        levelStr = "**INVALID**";
    }

    sprintf(buffer, current, ll, levelStr, legend);
  }
  sendToConsoleClient(self, buffer, true);
}

/**
 * Send a reset query to the validation cache.
 *
 * @param self The console
 * @param cmd the rpki-clear command
 * @param param zero length/
 */
static void doValCacheReset(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "%s %s", self->clientSockFd, cmd, param);
  char* message = NULL;
  if (strlen(param) > 0)
  {
    message = "Error: \'rpki-reset\' does not take parameters\r\n";
  }
  else if (sendResetQuery(&self->rpkiHandler->rrclInstance))
  {
    message = "Reset query successfully send to RPKI validation cache!\r\n";
  }
  else
  {
    message = "ERROR: Could not send reset query to RPKI validation cache!\r\n";
  }
  sendToConsoleClient(self, message, true);
}

/**
 * This method initiates the reset of prefix cache. After the reset the cache
 * is empty.
 *
 * @param self The console
 * @param cmd the console command
 * @param param The command parameter.
 */
static void doClearPrefixCache(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "%s %s", self->clientSockFd, cmd, param);
  //cmdNotSupportedYet(self);

  sendToConsoleClient(self, "Start resetting the complete rpki cache!\r\n",
                      false);
  emptyCache(self->rpkiHandler->prefixCache);
  sendToConsoleClient(self, "Reset of RPKI prefix cache done.!\r\n",
                      true);
}

/**
 * Send a synchronization request to all attached router/proxy clients.
 *
 * @param self THe console itself
 * @param cmd The command parameter
 * @param param The parameter itself.
 */
static void doRtrSync(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "%s %s", self->clientSockFd, cmd, param);
  ServerSocket srvSock = self->commandHandler->svrConnHandler->svrSock;

  SListNode*      cnode;
  ServerClient**  clientPtr;

  if (self->commandHandler->svrConnHandler->clients.size > 0)
  {
    // Walk through the list of proxies
    FOREACH_SLIST(&self->commandHandler->svrConnHandler->clients, cnode)
    {
      clientPtr = (ServerClient**)getDataOfSListNode(cnode);
      if (clientPtr != NULL)
      {
        if (!sendSynchRequest(&srvSock, clientPtr, false))
        {
          LOG(LEVEL_DEBUG, "Could not send packet to proxy!");
        }
      }
    }
    sendToConsoleClient(self, "Send out synchronization request to all "
                        "clients!\r\n", true);
  }
  else
  {
    sendToConsoleClient(self, "No routers are connected, sync aborted!\r\n",
                        true);
  }
}

/**
 * Disconnect the proxy client.
 *
 * @param self The console itself.
 * @param cmd The command.
 * @param param the command parameter.
 */
static void doRtrGoodbye(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "goodbye %s", self->clientSockFd, param);

  // Will be disabled due to BUG, scheduled for 0.3.1 see BZ290
  sendToConsoleClient(self, "Disabled in this version!!\r\n", true);
  return;


  ServerSocket srvSock = self->commandHandler->svrConnHandler->svrSock;

  SListNode*      cnode;
  ServerClient**  clientPtr;

 if (self->commandHandler->svrConnHandler->clients.size > 0)
  {
    // Walk through the list of proxies
    FOREACH_SLIST(&self->commandHandler->svrConnHandler->clients, cnode)
    {
      clientPtr = (ServerClient**)getDataOfSListNode(cnode);
      if (clientPtr != NULL)
      {
        sendGoodbye(&srvSock, *clientPtr, false);
      }
    }
    sendToConsoleClient(self, "Send out goodbye request to all"
                        "clients!\r\n", true);
  }

  //cmdNotSupportedYet(self);
}

/**
 * Get update information for the given AS and display it.
 *
 * @param self The console instance
 * @param asn The as number all updates have to be displayed for.
 */
static void doShowUpdateAS(SRXConsole* self, uint32_t asn)
{
  cmdNotSupportedYet(self);
}

/**
 * Get update information for the given prefix and displays it.
 *
 * @param self The console instance
 * @param prefixStr The prefix all updates have to be displayed for.
 */
static void doShowUpdatePrefix(SRXConsole* self, char* prefixStr)
{
  cmdNotSupportedYet(self);
}

/**
 * This method looks for all (max) number of ROAS that render this update
 * valid.  Check all parent nodes plus this one for covering roa's until roa
 * match number is met.
 *
 * @param msgPtr The message string where to write the data into.
 * @param updAS The origin as of the update.
 * @param prefixLen The length of the prefix.
 * @param currentPrefix The current pc-prefix to examine for roas that cover the
 *                      given prefix length.
 * @param missingROAs The number of remaining ROAs that cover the prefix.
 * @param noLines the number of lines to be printed.
 *
 * @return The msgPtr
 */
static char* _showROACoverage_VALID(char* msgPtr, uint32_t updAS,
                                    uint8_t prefixLen, PC_Prefix* currentPrefix,
                                    uint16_t missingROAs, int noLines)
{
  SListNode* asListNode;
  SListNode* roaListNode;

  PC_AS*  pcAS;
  PC_ROA* pcROA;

  // Check each as in the current prefix.
  FOREACH_SLIST(&currentPrefix->asn, asListNode)
  {
    if ((missingROAs * noLines) == 0)
    {
      // No more information needed / available!
      break;
    }
    else
    {
      pcAS = (PC_AS*)asListNode->data;
      // Check if the As contains ROAs and if the ROAs cover this update
      FOREACH_SLIST(&pcAS->roas, roaListNode)
      {
        // Check if this ROA covers any update
        pcROA = (PC_ROA*)roaListNode->data;
        if (pcROA->update_count > 0)
        {
          // Check each roa if the max length covers the update
          if (prefixLen <= pcROA->max_len)
          {
            msgPtr += sprintf(msgPtr, "                   AS(%i), "
                             "Prefix (%s/%u-%u), ROACount %i\r\n", updAS,
                             ipOfPrefix_tToStr(currentPrefix->treeNode->prefix),
                             currentPrefix->treeNode->prefix->bitlen,
                             pcROA->max_len, pcROA->roa_count);
            missingROAs -= pcROA->roa_count;
            noLines--;
          }
        }
      }
      //asListNode->data
    }
  }

  if ((missingROAs * noLines) > 0)
  {
    currentPrefix = getParent(currentPrefix->treeNode);
    if (currentPrefix != NULL)
    {
      msgPtr = _showROACoverage_VALID(msgPtr, updAS, prefixLen, currentPrefix,
                                      missingROAs, noLines);
    }
  }
  else if (missingROAs > 0)
  {
    msgPtr += sprintf(msgPtr, "                  %u additional ROA's do "
                              "cover this prefix!\r\n",  missingROAs);

  }

  return msgPtr;
}

/**
 * This method looks for all (max) number of ROAS that render this update
 * invalid.  Check all parent nodes plus this one for covering roa's until roa
 * match number is met.
 *
 * @param self The Console itself
 * @param pcUpdate The Update.
 *
 * @return The msgPtr
 */
static char* _showROACoverage_INVALID(char* msgPtr, uint8_t prefixLen,
                                      PC_Prefix* currentPrefix, int noLines)
{
  SListNode* asListNode;
  SListNode* roaListNode;

  PC_AS*  pcAS;
  PC_ROA* pcROA;

  if (currentPrefix->state_of_other == SRx_RESULT_NOTFOUND)
  {
    // This as well as all prefixes above are not covered by any prefix.
    return msgPtr;
  }
  // Check each as in the current prefix.
  FOREACH_SLIST(&currentPrefix->asn, asListNode)
  {
    // Check if more output lines are permitted.
    if (noLines == 0)
    {
      // No more information needed or available!
      break;
    }
    else
    {
      pcAS = (PC_AS*)asListNode->data;
      // First Check if the current prefix covers any updates
      // Check if the As contains ROAs and if the ROAs cover this update
      FOREACH_SLIST(&pcAS->roas, roaListNode)
      {
        // Check if this ROA covers any update
        pcROA = (PC_ROA*)roaListNode->data;
        // Check each roa if the max length covers the update
        msgPtr += sprintf(msgPtr, "                   AS(%i), "
                         "Prefix (%s/%u-%u), ROACount %i\r\n", pcROA->as,
                         ipOfPrefix_tToStr(currentPrefix->treeNode->prefix),
                         currentPrefix->treeNode->prefix->bitlen,
                         pcROA->max_len, pcROA->roa_count);
        noLines--;
      }
      //asListNode->data
    }
  }

  // If more lines are allowed, go up to parent prefix
  if (noLines > 0)
  {
    currentPrefix = getParent(currentPrefix->treeNode);
    if (currentPrefix != NULL)
    {
      msgPtr = _showROACoverage_INVALID(msgPtr, prefixLen, currentPrefix,
                                        noLines);
    }
  }
  else
  {
    msgPtr += sprintf(msgPtr, "                   More covered ROA's"
                      " might exist...\r\n");
  }

  return msgPtr;
}

/**
 * This method scans through the prefix tree and gathers all ROA information
 * related to the given update.
 *
 * @param self The console itself
 * @param msg The message
 * @param update the Update.
 * @param resultType The ROA result of the update.
 * @param noLines Determine how many distinct ROAs (max) should be displayed!
 */
static void _showRoaCoverage(SRXConsole* self, SRxUpdateID updateID,
                             SRxValidationResultVal roaResultType,
                             uint16_t noLines)
{
  uint32_t msgLen = 1024;
  char  msg[msgLen];
  memset(msg, '\0', msgLen);
  char* msgPtr = msg;
  PC_Update* pcUpdate = NULL;

  msgPtr += sprintf(msgPtr, " -ROA Coverage...: ");

  // Get the Update
  PrefixCache* pCache = self->rpkiHandler->prefixCache;
  SListNode* node = pCache->updates.root;

  // Not very efficient but to be changed in version 0.3
  while ((node != NULL) && (pcUpdate == NULL))
  {
    pcUpdate = (PC_Update*)node->data;
    if (pcUpdate->updateID != updateID)
    {
      node = node->next;
      pcUpdate = NULL;
    }
  }
  if (pcUpdate == NULL)
  {
    msgPtr += sprintf(msgPtr, "ERROR: No data found in prefix cache!\r\n");
  }
  else
  {
    PC_Prefix* pcPrefix = NULL;
    // depending on update validation state, check for covering ROA's or
    // Non Covering ROA's.
    switch (roaResultType)
    {
      case SRx_RESULT_NOTFOUND:
        //No ROA's to match
        msgPtr += sprintf(msgPtr, "No ROA's cover this update!\r\n");
        break;
      case SRx_RESULT_UNDEFINED:
        msgPtr += sprintf(msgPtr, "No information available at this "
                                  "point!\r\n");
        break;
      case SRx_RESULT_VALID:
        // Check all parent nodes plus this one for covering roa's until roa
        // match number is met.
        msgPtr += sprintf(msgPtr, "ROAs that render the update VALID...\r\n");
        pcPrefix = (PC_Prefix*)pcUpdate->treeNode->data;
        msgPtr = _showROACoverage_VALID(msgPtr, pcUpdate->as,
                                        pcPrefix->treeNode->bit, pcPrefix,
                                        pcUpdate->roa_match, noLines);
        break;
      case SRx_RESULT_INVALID:
        // Show all ROA's that render invalid.
        msgPtr += sprintf(msgPtr, "ROAs that render the update INVALID...\r\n");
        pcPrefix = (PC_Prefix*)pcUpdate->treeNode->data;
        _showROACoverage_INVALID(msgPtr, pcPrefix->treeNode->bit, pcPrefix,
                                 noLines);
        break;
      default:
        msgPtr += sprintf(msgPtr, "??? Invalid validation result %u\r\n",
                          roaResultType);
    }
  }
  sendToConsoleClient(self, msg, true);
}

/**
 * Get update information for the given AS and display it.
 *
 * @param self The console instance
 * @param id The id of the update to be displayed.
 * @param noLines
 */
static void doShowUpdateID(SRXConsole* self, SRxUpdateID* updateID,
                           uint16_t noLines)
{
  if (*updateID == 0)
  {
    sendToConsoleClient(self, "Error: Update ID other than 0 required!\r\n",
                        true);
  }
  else
  {
    UC_UpdateStatistics stat;
    SRxUpdateID uID = *updateID;
    stat.updateID = updateID;
    uint32_t maxNumPrexix = 10;

    uint32_t msgLen = 2048;
    char  msg[msgLen];
    memset(msg, '\0', msgLen);

    if (getUpdateData(self->commandHandler->updCache, &stat))
    {

      char* msgPtr = msg;
      char prefixStr[MAX_PREFIX_STR_LEN_V6];
      uint8_t clients[self->commandHandler->updCache->minNumberOfClients];
      memset(clients, 0, self->commandHandler->updCache->minNumberOfClients);
      int numClients = getClientIDsOfUpdate(self->commandHandler->updCache,
                            updateID, clients,
                            self->commandHandler->updCache->minNumberOfClients);
      int idx = 0;

      ipPrefixToStr (&(stat.prefix), prefixStr, MAX_PREFIX_STR_LEN_V6);

      sendToConsoleClient(self, "---------------------------------\r\n", false);

      msgPtr += sprintf(msgPtr, "UpdateID.........: 0x%08X (%u)\r\n", uID, uID);

      // Also add the list of clients:
      msgPtr += sprintf(msgPtr, " -Clients........: %s",
                                (numClients > 0 ? "" : "none\r\n"));
      for (idx = 0; idx < numClients; idx++)
      {
        msgPtr += sprintf(msgPtr, "0x%02X%s", clients[idx],
                                 (idx < (numClients-1) ? ", " : "\r\n"));
      }

      msgPtr += sprintf(msgPtr, " -AS.............: %u\r\n", stat.asn);
      msgPtr += sprintf(msgPtr, " -Prefix.........: %s\r\n", prefixStr);
      msgPtr += sprintf(msgPtr, " -ROA Count......: %u\r\n", stat.roa_count);
      msgPtr += sprintf(msgPtr, " -Prefix Origin..: ");
      if (stat.result.roaResult == SRx_RESULT_UNDEFINED)
      {
        msgPtr += sprintf(msgPtr, "%s (default)\r\n",
                          getSRxResultStr(stat.defResult.result.roaResult));
      }
      else
      {
        msgPtr += sprintf(msgPtr, "%s\r\n",
                          getSRxResultStr(stat.result.roaResult));
      }
      msgPtr += sprintf(msgPtr, "  * Default......: %s\r\n",
                      getSRxResultStr(stat.defResult.result.roaResult));
      msgPtr += sprintf(msgPtr, "  * Source.......: %s\r\n",
                      getSRxResultSrcStr(stat.defResult.resSourceROA));
      msgPtr += sprintf(msgPtr, " -Path...........: ");
      if (stat.result.bgpsecResult == SRx_RESULT_UNDEFINED)
      {
        msgPtr += sprintf(msgPtr, "%s (default)\r\n",
                          getSRxResultStr(stat.defResult.result.bgpsecResult));
      }
      else
      {
        msgPtr += sprintf(msgPtr, "%s\r\n",
                        getSRxResultStr(stat.result.bgpsecResult));
      }
      msgPtr += sprintf(msgPtr, "  * Default......: %s\r\n",
                      getSRxResultStr(stat.defResult.result.bgpsecResult));
      msgPtr += sprintf(msgPtr, "  * Source.......: %s\r\n",
                      getSRxResultSrcStr(stat.defResult.resSourceBGPSEC));

      sendToConsoleClient(self, msg, false);
      _showRoaCoverage(self, uID, stat.result.roaResult, maxNumPrexix);
    }
    else
    {
      sprintf(msg, "Update [0x%08X] (%u) not found!\r\n", uID, uID);
      sendToConsoleClient(self, msg, true);
    }
  }
}

/**
 * Get update information for the given AS and display it.
 *
 * @param self The console instance
 * @param param The parameter indicating what as to be counted.
 * @param type Determines which cache to examine, update cache or prefix cache.
 */
static void doShowCount(SRXConsole* self, char* param, ConsoleShowType type)
{
    if (strlen(param) == 0)
    {
      doNumUpdates(self, "num-updates", "");
      doNumPrefixes(self, "num-updates", "");
    }
    else
    {
      cmdNotSupportedYet(self);
    }

}

/**
 * Process the show-update .... command
 *
 * @param self The console instance
 * @param cmd The command "show-update"
 * @param param The parameter used.
 */
static void doShowUpdate(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "%s %s", self->clientSockFd, cmd, param);

  char* strPtr = param;
  char* strStart = NULL;
  int   strLength = 0;
  int   strPos = 0;

  if (strlen(param) == 0)
  {
    sendToConsoleClient(self, "Error: sub command missing! See Help!\r\n",
                        true);

    return;
  }

  // move chPtr to first character
  while ((*strPtr == ' ') || (*strPtr == '\t'))
  {
    strPtr++;
    strPos++;
  }
  strStart  = strPtr;
  strLength = 0;

  while ((strLength < strlen(param)) && (*strPtr != ' ') && (*strPtr != '\t'))
  {
    strPtr++;
    strLength++;
  }
  char showCmd[strLength+1];
  memset (showCmd, 0, strLength+1);
  memcpy(showCmd, strStart, strLength);

  // now skip blanks between command and parameter
  while ((*strPtr == ' ') || (*strPtr == '\t'))
  {
    strPtr++;
    strPos++;
  }
  strStart  = strPtr;
  strLength = strlen(param)-strPos;

  char showParam[strLength+1];
  memset (showParam, 0, strLength+1);
  memcpy(showParam, strStart, strLength);

  if (strncmp(showCmd, "as", strlen(showCmd)) == 0)
  {
    doShowUpdateAS(self, (uint32_t)atoll(showParam));
  }
  else if (strncmp(showCmd, "prefix", strlen(showCmd)) == 0)
  {
    doShowUpdatePrefix(self, showParam);

  }
  else if (strncmp(showCmd, "id", strlen(showCmd)) == 0)
  {
    //SRxUpdateID updateID = atoll(showParam);
    SRxUpdateID updateID = hexToInt(showParam);
    doShowUpdateID(self, &updateID, MAX_ROAS_TO_DIPLAY);
  }
  else if (strncmp(showCmd, "count", strlen(showCmd)) == 0)
  {
    //SRxUpdateID updateID = atoll(showParam);
    SRxUpdateID updateID = hexToInt(showParam);
    doShowUpdateID(self, &updateID, MAX_ROAS_TO_DIPLAY);
  }
  else
  {
    sendToConsoleClient(self, "Error: Show what ? (as, prefix, id, count)\r\n",
                        true);
  }
}

/** Process the show-rpki command
 *
 * @param self The console itself
 * @param cmd The command given
 * @param param The commands parameters
 *
 */
static void doShowRPKI(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "%s %s", self->clientSockFd, cmd, param);
  int as = strcmp(param, "as");
  printf("%i\n", as);
  if (strcmp(param, "as") == 0)
  {
    cmdNotSupportedYet(self);
  }
  else if (strcmp(param, "prefix") == 0)
  {
    cmdNotSupportedYet(self);
  }
  else if (strcmp(param, "id") == 0)
  {
    if (strlen(param) == 0)
    {
      sendToConsoleClient(self, "Error: Update ID required!\r\n", true);
    }
    else
    {
      cmdNotSupportedYet(self);
    }
  }
  else if (strcmp(param, "count") == 0)
  {
    if (strlen(param) == 0)
    {
      cmdNotSupportedYet(self);
    }
    else
    {
      cmdNotSupportedYet(self);
    }
  }
  else
  {
    sendToConsoleClient(self, "Error: Show what ? (as, prefix, id, count)\r\n",
                        true);
  }
}

static void doShowSRX(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "%s %s", self->clientSockFd, cmd, param);

  Configuration* cfg = self->commandHandler->sysConfig;

  char  str[1024];
  char* strPtr = str;
  // produce a \0 terminated string
  memset(str,'\0',1024);

  strPtr += sprintf(strPtr, "\r\nConfiguration:\r\n==============\r\n");
  strPtr += sprintf(strPtr, "port..................: %u\r\n", cfg->server_port);
  strPtr += sprintf(strPtr, "loglevel..............: %u\r\n", cfg->loglevel);
  strPtr += sprintf(strPtr, "sync..................: %s\r\n",
                            cfg->syncAfterConnEstablished ? "true" : "false");
  strPtr += sprintf(strPtr, "rpki.host.............: %s\r\n", cfg->rpki_host);
  strPtr += sprintf(strPtr, "rpki.port.............: %u\r\n", cfg->rpki_port);
  strPtr += sprintf(strPtr, "bgpsec.host...........: %s\r\n", cfg->bgpsec_host);
  strPtr += sprintf(strPtr, "bgpsec.port...........: %u\r\n", cfg->bgpsec_port);
  strPtr += sprintf(strPtr, "console.port..........: %u\r\n",cfg->console_port);
  strPtr += sprintf(strPtr, "mode.no-sendque.......: %s\r\n",
                       cfg->mode_no_sendqueue ? "true  (send queue turned off)"
                                              : "false (send queue turned on)");
  strPtr += sprintf(strPtr, "mode.no-receivequeue..: %s\r\n",
                 cfg->mode_no_receivequeue ? "true  (receive queue turned off)"
                                           : "false (receive queue turned on)");
  strPtr += sprintf(strPtr, "\r\n");
  sendToConsoleClient(self, str, true);
}

/**
 * Process the show-proxies command.
 *
 * @param self The console itself
 * @param cmd The command
 * @param param The command parameters.
 */
static void doShowProxies(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "%s %s", self->clientSockFd, cmd, param);

  char str[256];
  // produce a \0 terminated string
  memset(str,'\0',256);

  int idx = 0;
  int mappings = self->commandHandler->svrConnHandler->noMappings;
  bool active  = false;
  bool precnf  = false;
  __time_t crashed = 0;
  uint32_t updates = 0;
  int noClientsFound = 0;
  sendToConsoleClient(self, "Display proxy mappings:\r\n", false);
  sendToConsoleClient(self, "=======================\r\n", false);
  uint32_t proxyID = 0;

  while (idx < MAX_PROXY_CLIENT_ELEMENTS)
  {
    if (self->commandHandler->svrConnHandler->proxyMap[idx].proxyID != 0)
    {
      noClientsFound++;
      proxyID = self->commandHandler->svrConnHandler->proxyMap[idx].proxyID;
      active  = self->commandHandler->svrConnHandler->proxyMap[idx].isActive;
      precnf  = self->commandHandler->svrConnHandler->proxyMap[idx].preDefined;
      crashed = self->commandHandler->svrConnHandler->proxyMap[idx].crashed;
      updates = self->commandHandler->svrConnHandler->proxyMap[idx].updateCount;
      sprintf(str, "* %sClient[0x%02X](%3u): Proxy ID %03u.%03u.%03u.%03u "
                   "[0x%08X](%010u) (%s/%s) - #updates=%u\r\n",
                   (mappings-- > 0 ? "" : "INVALID "), idx, idx,
                   (proxyID >> 24) & 0xFF,  (proxyID >> 16) & 0xFF,
                   (proxyID >> 8) & 0xFF, proxyID & 0xFF, proxyID, proxyID,
                   (active ? " active" : crashed == 0 ? "-------"
                                                     : "crashed"),
                   (precnf ? "pre-conf" : "dynamic "),
                   updates);
      sendToConsoleClient(self, str, false);
      memset(str,'\0',256);
    }
    idx++;
  }
  if (noClientsFound == 0)
  {
    sendToConsoleClient(self, "No proxy mappings registered!\r\n", false);
  }
  sendToConsoleClient(self, "", true);
}

/**
 * Process the show-update .... command
 *
 * @param self The console instance
 * @param cmd The command "show-update"
 * @param param The parameter used.
 * @param type The console show type (UPDATE or RPKI)
 */
static void doShow(SRXConsole* self, char* cmd, char* param,
                   ConsoleShowType type)
{
  switch (type)
  {
    case CST_UPDATES:
      doShowUpdate(self, cmd, param);
      break;
    case CST_RPKI:
      doShowRPKI(self, cmd, param);
      break;
    case CST_SRXCFG:
      doShowSRX(self, cmd, param);
      break;
    case CST_PROXIES:
      doShowProxies(self, cmd, param);
      break;
    case CST_VERSION:
      doShowVersion(self, cmd, param);
      break;
    default:
      break;
  }
}

/**
 * Show the number of updates stored in the update cache and how many updates
 * are referenced in the prefix cache.
 *
 * @param self the console itself
 * @param cmd the console command
 * @param param the command parameter
 */
static void doNumUpdates(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "%s %s", self->clientSockFd, cmd, param);
  int elements = 0;
  char str[256];
  // produce a \0 terminated string
  memset(str,'\0',256);

  elements = self->commandHandler->updCache->allItems.size;
  sprintf(str, "Update Cache: %u updates stored.\r\n", elements);
  sendToConsoleClient(self, str, false);
  elements = self->commandHandler->rpkiHandler->prefixCache->updates.size;
  sprintf(str, "Prefix Cache: %u update shadows stored.\r\n", elements);
  sendToConsoleClient(self, str, true);
}

/**
 * Display the number of prefixes stored in the prefix tree.
 *
 * @param self the console itself/
 * @param cmd The console command
 * @param param the console command parameter
 */
static void doNumPrefixes(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "%s %s", self->clientSockFd, cmd, param);
  int elements = 0;
  char str[256];
  // produce a \0 terminated string
  memset(str,'\0',256);

  elements = self->rpkiHandler->prefixCache->prefixTree->num_active_node;
  sprintf(str, "Prefix Cache: %u entries.\r\n", elements);
  sendToConsoleClient(self, str, true);
}

/**
 * Return the number of proxies attached to the server
 *
 * @param self the console application
 * @param cmd the console command
 * @param param the command parameter
 */
static void doNumProxies(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "%s %s", self->clientSockFd, cmd, param);
  int elements = 0;
  char str[256];
  // produce a \0 terminated string
  memset(str,'\0',256);

  elements = self->commandHandler->svrConnHandler->clients.size;

  sprintf(str, "Currently active: %u Proxies\r\n", elements);
  sendToConsoleClient(self, str, true);
}

/**
 * This method gathers the number of elements stored in the command queue.
 *
 * @param self Pointer to the console
 * @param cmd The command
 * @param param the parameters (empty)
 */
static void doCommandQueue(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "%s %s", self->clientSockFd, cmd, param);
  char str[256];
  int total = getTotalQueueSize(self->commandHandler->queue);
  int unprocessed = getUnprocessedQueueSize(self->commandHandler->queue);
  // produce a \0 terminated string
  memset(str,'\0',256);

  // Get the number of elements from the command queue. Here is is for display
  // only, synchronizing is not necessary
  sprintf(str, "Command handler:\r\n"
               "====================================\r\n"
               "Total commands........: %06u\r\n"
               "Unprocessed commands..: %06u\r\n"
               "====================================\r\n", total, unprocessed);
  sendToConsoleClient(self, str, true);
}

/**
 * Dump the prefix cache into a file/console on the server side.
 * Use parameter '-' to dump it on the console of the server.
 *
 * @param self The console itself
 * @param cmd The dump command
 * @param param parameters
 */
static void doDumpPCache(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "%s %s", self->clientSockFd, cmd, param);
  int elements = 0;
  char str[256];
  // produce a \0 terminated string
  memset(str,'\0',256);

  char ch = (strlen(param) == 0) ? CON_STDOUT : param[0];
  char* fileName = (ch == CON_STDOUT) ? "standard out" : param;
  // Get the number of elements from the command queue. Here is is for display
  // only, synchronizing is not necessary
  elements = self->rpkiHandler->prefixCache->prefixTree->num_active_node;
  sprintf(str, "Prefix Cache has %u items. Start export into %s!\r\n",
          elements, fileName);
  sendToConsoleClient(self, str, true);

  FILE* out = (ch == CON_STDOUT) ? stdout : NULL;
  if (out != NULL)
  {
    outputPrefixCacheAsXML(self->rpkiHandler->prefixCache, stdout);
  }
  sprintf(str, "Export of prefix cache into %s done.!\r\n", param);
  sendToConsoleClient(self, str, true);
}

/**
 * Dump the update cache into a file/console on the server side.
 * Use parameter '-' to dump it on the console of the server.
 *
 * @param self The console itself
 * @param cmd The dump command
 * @param param parameters
 */
static void doDumpUCache(SRXConsole* self, char* cmd, char* param)
{
  LOG(LEVEL_DEBUG, CP1 CP2 "%s %s", self->clientSockFd, cmd, param);
  int elements = 0;
  char str[256];
  // produce a \0 terminated string
  memset(str,'\0',256);

  char ch = (strlen(param) == 0) ? CON_STDOUT : param[0];
  char* fileName = (ch == CON_STDOUT) ? "standard out" : param;
  // Get the number of elements from the command queue. Here is is for display
  // only, synchronizing is not necessary
  elements = self->commandHandler->updCache->allItems.size;
  sprintf(str, "Update Cache has %u items. Start export into %s!\r\n",
          elements, fileName);
  sendToConsoleClient(self, str, true);

  FILE* out = (ch == CON_STDOUT) ? stdout : NULL;
  if (out != NULL)
  {
    outputUpdateCacheAsXML(self->commandHandler->updCache, stdout, -1);
  }
  sprintf(str, "Export of prefix cache into %s done.!\r\n", param);
  sendToConsoleClient(self, str, true);
}

////////////////////////////////////////////////////////////////////////////////
// Some utility function
////////////////////////////////////////////////////////////////////////////////
/**
 * This function converts an hex string 0x00000000 of 00000000 into an unsigned
 * integer.
 *
 * @param hex The hex string. Leading 0x is optional
 * @return the unsigned integer. in case of an error 0 will be returned.
 */
static uint32_t hexToInt(char* hex)
{
  // Determine start position in case the hex number was passed using 0x
  int idx = (hex[0] == '0' && (hex[1]=='x' || hex[1]=='X')) ? 2 : 0;
  // The return value;
  uint32_t retVal = 0;
  // the number of processed characters
  int character = 1;
  // Go until the end of the string is reached or the maximum number of
  // characters (8)
  while (hex[idx] != '\0')
  {
    if (character > 8)
    {
      RAISE_SYS_ERROR("Given hex number [%s] is too large!!", hex);
      retVal = 0;
      break;
    }
    else if (hex[idx] >= '0' && hex[idx] <= '9')
    {
      retVal = retVal * 16 + (hex[idx] - '0');
    }
    else if (hex[idx] >= 'A' && hex[idx] <= 'F')
    {
      retVal = retVal * 16 + ((hex[idx] - 'A') + 10);
    }
    else if (hex[idx]>='a' && hex[idx] <= 'f')
    {
      retVal = retVal * 16 + ((hex[idx] - 'a') + 10);
    }
    else
    {
      RAISE_SYS_ERROR("Given hex number [%s] contains invalid characters!!",
                      hex);
      retVal = 0;
      break;
    }
    idx++;
  }
  return retVal;
}
