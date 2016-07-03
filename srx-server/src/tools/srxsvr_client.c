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
 * This program allows to test the SRX server implementation.
 *
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/10 - oborchert
 *            * Added initialization of variables in runScript
 *            * Removed unused variables from doVerify
 * 0.3.0.6  - 2014/04/03 - oborchert
 *            * Fixed formating error in printout ($i -> %i)
 * 0.3.0    - 2013/03/05 - oborchert
 *            * Fixed logLevel management
 *            * Fixed initial creation of proxy by passing the communication 
 *              management handler.
 *          - 2013/02/27 - oborchert
 *            * Removed debug printf statements
 *            * Updated to reflect changes in error management made in srx_api.
 *            * fixed doDisconnect.
 *          - 2013/02/21 - oborchert
 *            * Relabeled bgpsec to path and rpki to origin.
 *          - 2013/02/20 - oborchert
 *            * Fixed bug in doConnect() where host name was overwritten by 
 *              port number.
 *            * Fixed bug in runScript where the script mode was not turned off 
 *              at the end.
 *          - 2013/02/15 - oborchert
 *            * Added prompt after printout of receiving validation result.
 *            * Changed delete command. 0 as updateID cancels the request!
 *          - 2013/02/12 - oborchert
 *            * Fixed bug (BZ278) in non blocking socket mode. 
 *            * Do not add commands from a script to history.
 *          - 2013/02/06 - oborchert
 *            * Removed polling sleep time. Not needed anymore using select() for
 *              non-blocking socket.
 *          - 2013/01/28 - oborchert
 *            * Moved method IPtoINT into prefix.h
 *          - 2013/01/23 - oborchert
 *            * Added command to exit automatically when stat-mark is reached!
 *            * added function promptBool.
 *            * Added command "code completion" to console.
 *            * Fixed runtime error when attempting to open non existing script.
 *          - 2013/01/15 - oborchert
 *            * Allow the usage of non blocking sockets.
 *          - 2013/01/04 - oborchert
 *            * Removed calculation of average processing time from statistics
 *              framework.
 *          - 2013/01/04 - oborchert
 *            * Fixed some bugs in statistics framework
 *            * Added Error Management.
 *          - 2013/01/03 - oborchert
 *            * Fixed help output in verify command
 *            * Changed default proxyID from 1234 to 10.0.0.1
 *            * Added statistics framework for validation requests
 *            * Moved all commands into defines for easier handling
 *          - 2012/12/31 - oborchert
 *            * BZ256 Added capability to enter both, integer or IPv4 as proxy 
 *              id
 *            * Fixed a minor display issue.
 *          - 2012/12/11 - oborchert
 *            * Added proxy id to connect command
 *            * Internally changed verify update to new API
 *            * Added reconnect command "doReConnect"
 *            * Changed parameter input for connect "doConnect"
 * 0.2.0    - 2011/01/07 - oborchert
 *            * Changelog added with version 0.2.0 and date 2011/01/07
 *            * Version tag added
 *            * Fixed some output to be less confusing.
 *            * Trimmed all input.
 * 0.0.0    - 2010/05/11 - pgleichm
 *            * Code Created
 * -----------------------------------------------------------------------------
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/select.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "client/srx_api.h"
// This include is only needed for some program version defines. Not needed 
// otherwise.
#include "server/srx_server.h"
#include "shared/srx_packets.h"
#include "util/log.h"
#include "util/prefix.h"
#include "util/str.h"
#include "util/socket.h"

#define DEFAULT_SERVER    "localhost"
#define DEFAULT_PORT      17900
#define DEFAULT_PROXY_ID  "10.0.0.1"
#define DEFAULT_PEERAS    50
#define DEFAULT_MARKER    100
#define HISTORY_FILENAME  ".user_srx_api.history"

#define PROMPT            ">> "

#define CMD_QUIT       "quit"
#define CMD_EXIT       "exit"
#define CMD_HELP       "help"
#define CMD_CREDITS    "credits"
#define CMD_CONNECT    "connect"
#define CMD_DISCONNECT "disconnect"
#define CMD_RECONNECT  "reconnect"
#define CMD_ADD_PEER   "addPeer"
#define CMD_DEL_PEER   "delPeer"
#define CMD_VERIFY     "verify"
#define CMD_SIGN       "sign"
#define CMD_DELETE     "delete"
#define CMD_RUN        "run"

#define CMD_STAT_START             "stat-start"
#define CMD_STAT_STOP              "stat-stop"
#define CMD_STAT_INIT              "stat-init"
#define CMD_STAT_MARK_NO_RECEIPT   "stat-mark-nr"
#define CMD_STAT_MARK_WITH_RECEIPT "stat-mark"
#define CMD_STAT_EXIT_ON_MARK      "stat-exit-on-mark"
#define CMD_STAT_PRINT             "stat-print"

#define CMD_LOG_LEVEL                    "LOG_LEVEL"
#define CMD_RESET_PROXY                  "RESET_PROXY"
#define CMD_USE_NON_BLOCKING_SOCKET_TYPE "NON_BLOCKING_SOCKET"

// For readline Code Completion
// since 0.3.0
static char* cmd_code[] = {
             CMD_QUIT, CMD_EXIT, CMD_HELP, CMD_CREDITS,
             CMD_CONNECT, CMD_DISCONNECT, CMD_RECONNECT,
             CMD_ADD_PEER, CMD_DEL_PEER, CMD_VERIFY, CMD_SIGN, CMD_DELETE, 
             CMD_RUN, 
             CMD_STAT_START, CMD_STAT_STOP, CMD_STAT_INIT, 
             CMD_STAT_MARK_NO_RECEIPT, CMD_STAT_MARK_WITH_RECEIPT, 
             CMD_STAT_EXIT_ON_MARK, CMD_STAT_PRINT, 
             CMD_LOG_LEVEL, CMD_RESET_PROXY, CMD_USE_NON_BLOCKING_SOCKET_TYPE
};
static uint32_t cmd_code_len = 23; // 23 commands in the array above

// Indicates the socket type of the proxy
static bool isBlocking = true;


/** See writeLog. */
static bool keepGoing    = true;
static SRxProxy* proxy   = NULL;
static LogLevel logLevel = LEVEL_ERROR;

// Forward declaration
void doDisconnect(bool log);
bool processLine(bool log, char* line);
void addToHistory(const char* fmt, ...);
uint32_t promptU32(char** argPtr, const char* msg);
bool promptBool(char** argPtr, const char* msg, bool* value, bool* defValue);
void fstatGetStatistics(bool addHistory);
void fstatStopStatisitcs(bool addHistory);

// During script mode, no history will be added. - since 0.3.0
static bool     scriptMode = false;

////////////////////////////////////////////////////////////////////////////////
// Statistics framework - Since 0.3.0
////////////////////////////////////////////////////////////////////////////////
static bool     stat_started = false;
static bool     stat_silent = false;
static uint32_t stat_requests_send = 0;
static uint32_t stat_notify_received = 0;
static uint32_t stat_receipts_received = 0;
static uint32_t stat_mark_notify = 0;
static uint32_t stat_mark_inclRec = false;
static bool     stat_need_init = true;
static bool     stat_exit_on_mark = false;
static struct timespec stat_startTime;
static struct timespec stat_stopTime;

/**
 * Increments the notification counter. This number contains the notifications
 * of type receipt.
 * 
 * @since 0.3.0
 */
void fstatIncNotify()
{
  stat_notify_received++;
  LOG(LEVEL_DEBUG, "++ stat_notify_received: %i\n", stat_notify_received);
  if (stat_mark_notify >  0)
  { 
    if (stat_mark_inclRec)
    {
      // Print statistics when the requested number of notifications regardless
      // of type are received.
      if (stat_notify_received == stat_mark_notify)
      {
        fstatGetStatistics(false);
        stat_mark_notify = 0;
      }
    }
    else
    {
      // Print statistics when the requested notifications except receipts 
      // are received.
      if ((stat_notify_received - stat_receipts_received) == stat_mark_notify)
      {
        fstatGetStatistics(false);
        stat_mark_notify = 0;
        if (stat_exit_on_mark)
        {
          // write quit into STDIN to end the program
          fprintf(stdin, "quit\n");
        }
      }      
    }    
  }
}

/**
 * This counter contains only the receipt notifications.
 * 
 * @since 0.3.0
 */
void fstatIncReceipt()
{
  stat_receipts_received++;
  LOG(LEVEL_DEBUG, "** stat_receipts_received: %i\n", stat_receipts_received);
}

/** 
 * Initializes the statistics framework. 
 * 
 * @param addHistory if set this call will be added to the history file.
 * 
 * @since 0.3.0
 */
void fstatInitializeStatistics(bool addHistory)
{
  if (stat_started)
  {
    printf("Statistics are already started, stop statistics first!!\n");
  }
  else
  {
    stat_silent  = false;
    stat_requests_send = 0;
    stat_notify_received = 0;
    stat_receipts_received = 0;
    stat_mark_notify = 0;
    stat_mark_inclRec = false;
    stat_startTime.tv_sec = 0;
    stat_startTime.tv_nsec = 0;
    stat_stopTime.tv_sec  = stat_startTime.tv_sec;
    stat_stopTime.tv_nsec = stat_startTime.tv_nsec;
    stat_need_init = false;
  }
  if (addHistory)
  {
    addToHistory(CMD_STAT_INIT);
  }
}

/** 
 * Initializes the statistics, silence output and start the clock! 
 * 
 * @since 0.3.0
 */
void fstatStartStatistics()
{   
  addToHistory(CMD_STAT_START);
  if (!stat_need_init)
  {
    if (stat_started)
    {
      printf("Statistics are already started!!\n");
    }
    else
    {
      stat_silent = true;
      stat_started = true;
      clock_gettime(CLOCK_MONOTONIC, &stat_startTime);
      stat_stopTime.tv_sec  = stat_startTime.tv_sec;
      stat_stopTime.tv_nsec = stat_startTime.tv_nsec;
    }    
  }
  else
  {
    printf ("Statistics framework needs to be initialized!\n");
  } 
}

/** 
 * Stop gathering the statistics.
 * 
 * @param addHistory if set this call will be added to the history file.
 * 
 * @since 0.3.0
 */
void fstatStopStatistics(bool addHistory)
{
  if (stat_started)
  {
    stat_started = false;
    stat_silent = false;
    stat_mark_notify = 0;
    stat_need_init = true;
  }
  else
  {
    printf ("Statistics need to be started first!!\n");
  }
  if (addHistory)
  {
    addToHistory(CMD_STAT_STOP);
  }
}

/**
 * Retrieve the statistics. This method also stops the data collection.
 * 
 * @param addHistory if set this call will be added to the history file.
 * 
 * @since 0.3.0
 */
void fstatGetStatistics(bool addHistory)
{ 
  if (stat_started)
  {
    clock_gettime(CLOCK_MONOTONIC, &stat_stopTime);
  }
  time_t   elapsedTimeSec  = stat_stopTime.tv_sec - stat_startTime.tv_sec;
  
  char buffer[512];
  memset(buffer,'\0',512);
  char* buffPtr = buffer;

  
  long int elapsedTimeNSec = 0;
  if (elapsedTimeSec == 0)
  {
    elapsedTimeNSec = stat_stopTime.tv_nsec - stat_startTime.tv_nsec;
  }
  else
  {
    elapsedTimeNSec = (1000000000 - stat_startTime.tv_nsec) 
                      + stat_stopTime.tv_nsec;
    elapsedTimeSec--;
  }            
  double totalElapsedTimeSec = (double)elapsedTimeSec 
                               + ((double)elapsedTimeNSec/(double)1000000000);
  
  buffPtr += sprintf (buffPtr, "Statistics:");
  if (stat_started)
  {
    buffPtr += sprintf(buffPtr, " * running *\n");
  }
  else
  {
    buffPtr += sprintf(buffPtr, " * stopped *\n");
  }
  
  buffPtr += sprintf(buffPtr, "\tTest harness polled using a %sblocking "
                              "socket\n", isBlocking ? "" : "non ");
    
  if (stat_mark_notify > 0)
  {
    buffPtr += sprintf (buffPtr, "\tMarker set at %u notifications %s %s\n", 
                        stat_mark_notify, 
                        stat_mark_inclRec ? "including" : "without", 
                        "receipts");

  }
  else
  {
    buffPtr += sprintf (buffPtr, "\tNo marker set!\n");    
  }
  buffPtr += sprintf (buffPtr, "\tTotal number of requests: %u\n", 
                     stat_requests_send);
  buffPtr += sprintf (buffPtr, "\tTotal number of notifications received: %u\n", 
                     stat_notify_received);
  buffPtr += sprintf (buffPtr, "\tTotal number of receipts received: %u\n", 
                     stat_receipts_received);
  buffPtr += sprintf (buffPtr, "\tTotal processing time: %f sec.\n", 
                     totalElapsedTimeSec);
  printf("%s", buffer);
        
  if (addHistory)
  {
    addToHistory(CMD_STAT_PRINT);
  }
}

/**
 * Mark the statistics generator to auto-generate the statistics once the 
 * provided number of notifications are received.
 * 
 * @param argPtr The console input that should contain the marker value.
 * @param incReceipt indicates if the number of received notifications contains
 *                   receipt notifications.
 * 
 * @since 0.3.0
 */
void fstatMarkNotifications(char** argPtr, bool inclReceipt)
{
  uint32_t defaultVal = stat_requests_send > 0 ? stat_requests_send 
                                               : DEFAULT_MARKER;
  uint32_t notifyMarker = 0;
  char label[256];  
  
  memset(label, 0, 256);
  sprintf(label, "Set marker value [%d]: ", defaultVal);
  notifyMarker = promptU32(argPtr, label);
  
  if (notifyMarker == 0)
  {
    notifyMarker = defaultVal;
  }
  
  uint32_t alreadyReceived = stat_notify_received 
                             - inclReceipt ? 0 : stat_receipts_received;
  
  if (alreadyReceived < notifyMarker)
  {
    stat_mark_notify  = notifyMarker;
    stat_mark_inclRec = inclReceipt;    
  }
  else
  {
    printf("Invalid marker; The value is to low, marker will be ignored!\n");
  }
  
  addToHistory("%s %d", inclReceipt ? CMD_STAT_MARK_NO_RECEIPT 
                                    : CMD_STAT_MARK_NO_RECEIPT, notifyMarker);
}

/**
 * Specify if the program should be ended when the statistics marker is reached!
 * 
 * @param argPtr The console input that should contain true or false.
 * 
 * @since 0.3.0
 */
void fstatSetExitOnMark(char** argPtr)
{
  if (stat_started)
  {
    printf("The command \"" CMD_STAT_EXIT_ON_MARK "\" cannot be set once the "
           "statistics are started!\n");
  }
  else if (stat_need_init)
  {
    printf("Initialize the statistics framework prior calling the command "
           "\"" CMD_STAT_EXIT_ON_MARK "\"!\n");
  }
  else
  {
    bool def = false;
    if (promptBool(argPtr, "Exit on mark (true|*false)? ", &stat_exit_on_mark, 
                   &def))
    {
      addToHistory(CMD_STAT_EXIT_ON_MARK " %s\n", stat_exit_on_mark ? "true" 
                                                                    : "false");
    }
  }
    
}

////////////////////////////////////////////////////////////////////////////////
// For code completion - readline
////////////////////////////////////////////////////////////////////////////////
char* code_generator(const char* text, int state)
{
  static int list_index, len;
  char* code = NULL;
  
  if (!state)
  {
    list_index = 0;
    len = strlen(text);
  }
  
//  for (list_index = 0; list_index < cmd_code_len; list_index++)
//  {
  while (list_index < cmd_code_len)
  {
    code = cmd_code[list_index];
    list_index++;
    if (strncmp(code, text, len) == 0)
    {
      char* code_copy = (char*)malloc(strlen(code)+1);
      if (!code_copy)
      {
        printf ("Not enough memory available - Exit application!\n");
        exit(1);
      }
      memset(code_copy, '\0', strlen(code)+1);
      strcpy(code_copy, code);
      return code_copy;
      //code = cmd_code[list_index];
      //break;
    }
  }
  
  // If no names matched, then return NULL
  //return code;
  return NULL;
}

static char** code_completion(const char* text, int start, int end)
{
  char** matches;
  matches = (char**)NULL;
  
  if (start == 0)
  {    
    matches = rl_completion_matches((char*)text, &code_generator);      
  }
  else
  {
    // TODO: When determined if run is called keep going, otherwise 
    // '\t' rl_abort in this case always set '\t', rl_complete
  }
  
  return matches;
}


/**
 * Print the given text to standard output is not silenced!
 *
 * @param format The formated text
 * @param ... parameters to be formated.
 * 
 * @since 0.3.0
 */
void PRINTF(char* format, ...)
{
  if (!stat_silent || logLevel == LEVEL_DEBUG)
  {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
  }
}

/**
 * Convert the integer number into an IP string
 * 
 * @param number the integer number
 * 
 * @return a string buffer
 */
char* intToIP(uint32_t number)
{
  static char buffer[16];
  memset(buffer, '\0', 16);
  
  sprintf(buffer, "%u.%u.%u.%u", (number >> 24) & 0xFF,  (number >> 16) & 0xFF,  
                                 (number >> 8) & 0xFF, number & 0xFF);
  return buffer;
  
}

////////////////////////////////////////////////////////////////////////////////
// Thread handling for proxy poller
////////////////////////////////////////////////////////////////////////////////
// Will be set true by doConnect
static bool freshConnected = false;

/**
 * The polling thread
 * 
 * @param threadid
 */
void* pollProxy(void* threadid)
{
  // Used to timeout select
  struct timeval timeout; 
  // needed in case non blocking socket with listen is used.
  fd_set read_fd_set;
  // will be other than -1 if non blocking is used
  int fd = -1;  
  bool useSelect = false;
  bool goodToGo  = false;
  
  while (keepGoing)
  {    
    if (freshConnected)
    {
      freshConnected = false;
      fd = getInternalSocketFD(proxy, true);
      useSelect = (fd != -1);
      goodToGo = true;
    }
    else if (goodToGo)
    {        
      if(isConnected(proxy))
      {
        if (fd != -1)
        {
          // the following needs to be executed each time prior to a select call
          // to initialize the system. The select will update the timeout variable
          // with the remaining time to the timeout, the socket set needs to be 
          // initialized as well to feed the sockets to check.


          // non blocking is used, register the file descriptor.
          FD_ZERO(&read_fd_set);
          FD_SET(fd, &read_fd_set);

          // 2.5 seconds timeout for non blocking sockets
          timeout.tv_sec      = 2;
          timeout.tv_usec     = 5000;
        }
        else
        {
          useSelect = false;        
        }
        // if newly connected, this will be run in second turn.
        if (useSelect && fd != -1)
        {
          // Timeout every 2.5 seconds
          int num = select(fd+1, &read_fd_set, NULL, NULL, &timeout);

          if (num == -1)
          {
            // Something went wrong
            printf("Error[%i] reading the socket!\n", errno);
          }
          else if (num == 0)
          {
            // timeout
            continue;
          }
          if(FD_ISSET(fd, &read_fd_set))
          {
            if (!processPackets(proxy)) // poll for new packets.   
            {
              int error = getLastRecvError();
              if (error != 0)
              {
                printf("Error receiving packets, errno=%i, close "
                       "connection!\n", error);
                disconnectFromSRx(proxy, 0);
                close(fd);
                fd = -1;
                goodToGo = false;
              }
            }
          }
          else
          {
            // Again something went wrong
            if (getInternalSocketFD(proxy, true) == -1)
            {
              // lost socket, can be an error or just disconnect. if error the
              // error management should react on it. therefore we just close it
              fd = getInternalSocketFD(proxy, false);
              close(fd);
              fd = -1;
              goodToGo = false;
              continue;            
            }
          }
        }
        else
        {       
          processPackets(proxy); // poll for new packets. 
        }
      }
      else
      {
        if (fd != -1)
        {
          // Lost Connection, close socket
          close(fd);
          goodToGo = false;
          fd = -1;
        }
      }
    }
    else
    {
      sleep(1); // Sleep for 1 second, not connected
    }
  }
  if (fd != -1)
  {
    // Close the socket.
    close(fd);
  }
  pthread_exit(0);
}

////////////////////////////////////////////////////////////////////////////////
// User input
////////////////////////////////////////////////////////////////////////////////

/**
 * Read data from either the argument pointer or a user input using stdandard 
 * input.
 * 
 * @param argPtr Contains arguments to be read
 * @param msg The message printed in case for command line input.
 * 
 * @return The string read from either the parameters or console
 */
char* prompt(char** argPtr, const char* msg)
{
  #define BUFFER_SIZE 80
  static char buffer[BUFFER_SIZE];
  memset(buffer, '\0', BUFFER_SIZE);
  
  char* input;

  // Already a value
  if (*argPtr != NULL)
  {
    return strsep(argPtr, " \t");
  }

  // Get a value from the user
  do
  {
    input = readline(msg);
  } while (input == NULL);
  
  strncpy(buffer, trim(input), BUFFER_SIZE);
  free(input);
  
  return buffer;
}

/**
 * prompt for the input of an integer in either integer or IPv4 format.
 * 
 * @param argPtr The argument string
 * @param msg the prompt message
 * 
 * @return the provided value as unsigned 4 byte integer
 * 
 * @since 0.3.0
 */
uint32_t promptIPv4Int(char** argPtr, const char* msg)
{
  char* buffer = prompt(argPtr, msg);  
  return IPtoInt(buffer);
}

/**
 * Read data from either the argument pointer or a user input using standard
 * input.
 *
 * @param argPtr Contains arguments to be read
 * @param msg The message printed in case for command line input.
 *
 * @return a 32 bit value or 0
 */
uint32_t promptU32(char** argPtr, const char* msg)
{
  const char* input;
  uint32_t    num;

  do
  {
    input = trim(prompt(argPtr, msg));
    if (*input == '\0')
    {
      num = 0;
      break;
    }
    errno = 0;
    num = strtoul(input, NULL, 0);
  } while (errno != 0);

  return num;
}

/**
 * Read data from either the argument pointer or a user input using standard
 * input.
 *
 * @param argPtr Contains arguments to be read
 * @param msg The message printed in case for command line input.
 * @param value Pointer to the bool variable that will be set.
 * @param defValue Pointer to the default value to be used, if NULL no default 
 *                 value is used. Default value is only used for no entry (\0)
 * 
 * @return true if the given input was valid, false for an invalid entry. This 
 *              return value does not reflect the input!!
 */
bool promptBool(char** argPtr, const char* msg, bool* value, bool* defValue)
{
  bool retValue = true;
  char* input = trim(prompt(argPtr, msg));
  
  if (*input == '\0')
  {
    if (defValue != NULL)
    {
      *value = *defValue;
    }
  }  
  else if (strcasecmp(input, "true") == 0)
  {
    *value = true;    
  }
  else if (strcasecmp(input, "false") == 0)
  {
    *value = false;
  }
  else
  {
    printf("Invalid entry: '%s'\n", input);
    retValue = false;
  }
  
  return retValue;
}

/**
 * Add the given parameter to the statistics - only if not provided by a script.
 * 
 * @param fmt The formated string
 * @param ... possible parameters
 */
void addToHistory(const char* fmt, ...)
{
  if (!scriptMode)
  {
    char* line;

    va_list ap;
    va_start(ap, fmt);
    vasprintf(&line, fmt, ap);
    va_end(ap);

    add_history(line);
    free(line);
  }
}

////////////////////////////////////////////////////////////////////////////////
// Event handlers
////////////////////////////////////////////////////////////////////////////////

/**
 * REceive errors from the proxy. 
 * 
 * @param error The error code
 * @param subcode The subCode of the error.
 * @param userPtr will be NULL because nothing is provided to the proxy
 */
void commManagement(SRxProxyCommCode mainCode, int subCode, void* userPtr)
{
  if (isErrorCode(mainCode))
  {
    switch (mainCode)
    {
      // Currently undefined error.
      case COM_ERR_PROXY_UNKNOWN:
        printf ("SRx-Error: Unknown error with sub code %i.\n", subCode);
        break;

      // Error while assigning the proxy id - connecting to srx server. */
      case COM_ERR_PROXY_DUPLICATE_PROXY_ID:
        printf ("SRx-Error: Duplicate Proxy ID reported!\n");
        break;

      // The requested algorithm is unknown - path validation. */
      case COM_ERR_PROXY_UNKNOWN_ALGORITHM:
        printf ("SRx-Error: Algorithm not supported!\n");
        break;      

      // The specified update is unknown - delete/sign request. */
      case COM_ERR_PROXY_UNKNOWN_UPDATE:
        printf ("SRx-Error: Update for the requested operation not found.\n");
        break;

      // This error code specifies a lost connection. */
      case COM_ERR_PROXY_CONNECTION_LOST:
        doDisconnect(false); // do not log this call
        printf ("SRx-Error: Lost connection to SRx-server.\n");      
        break;

      // This error specifies problems sending messages to the srx-server. This
      // Error provides the sockets errno as subcode. */
      case COM_ERR_PROXY_COULD_NOT_SEND:
        printf ("SRx-Error: The request could not be send to the server."
                "See socket error code (0x%08X - %i).\n", subCode, subCode);
        break;

      // This erorr specifies a SERVER error. */
      case COM_ERR_PROXY_SERVER_ERROR:
        printf ("SRx-Error: SRx server reports internal error!\n");
        break;

      default:
        printf ("Invalid Error Code error:%u subcode:%i.\n", mainCode, subCode);
        break;
    }
  }
  else
  {
    printf ("Received a communication code [%u] subcode:%i.\n", mainCode, 
                                                                subCode);    
  }
}

/**
 * @param updateID The updateID provided by the srx-server to communicate
 *                 the validation result.
 * @param localID  The local "update-id" used temporarily by the user of this
 *                 API when called a validation. (see more detailed above)
 * @param valType  Specifies which of the validation results contains actual
 *                 result values.
 * @param roaResult The result of the update validation only in regards to
 *                 prefix-origin validation.
 * @param bgpsecResult The result of the update validation only in regards to
 *                 path validation validation. (This does not include RPKI
 *                 validation)
 * @param usrPtr Pointer to SRxProxy.userPtr provided by router / user of the
 *               API.
 */
bool handleValidationResult(SRxUpdateID          updateID,
                            uint32_t	           localID,
                            ValidationResultType valType,
                            uint8_t              roaResult,
                            uint8_t              bgpsecResult,
                            void* userPtr)
{
  bool retVal = true;
  bool isReceipt    = localID != 0;
  bool printROA     = (valType & SRX_PROXY_RESTYPE_ROA) != 0;
  bool printBGPSEC  = (valType & SRX_PROXY_RESTYPE_BGPSEC) != 0;
  char* resultStr;  
  
  PRINTF("=> Received validation result for update [uid=0x%08X;lid:0x%08X]: ",
         updateID, localID);  
  if (stat_started)
  {
    if (isReceipt)
    {
      fstatIncReceipt();
    }
    fstatIncNotify();
  }
  
  if (printROA)
  {
    switch (roaResult)
    {
      case SRx_RESULT_UNDEFINED:
        resultStr = "NOT DEFINED";
        break;
      case SRx_RESULT_VALID:
        resultStr = "VALID";
        break;
      case SRx_RESULT_NOTFOUND:
        resultStr = "NOTFOUND";
        break;
      case SRx_RESULT_INVALID:
        resultStr = "INVALID";
        break;
      case SRx_RESULT_DONOTUSE:
        resultStr = "DONOTUSE <- SHOULD NOT BE HERE - SRx INTERNAL ONLY, "
                    "NEVER PROXY";
        break;        
      default:
        resultStr = "???????";
    }
    PRINTF(" ROA=%s", resultStr);
  }

  if (printBGPSEC)
  {
    switch (bgpsecResult)
    {
      case SRx_RESULT_UNDEFINED:
        resultStr = "NOT DEFINED";
        break;
      case SRx_RESULT_VALID:
        resultStr = "VALID";
        break;
      case SRx_RESULT_NOTFOUND:
        resultStr = "NOTFOUND <- INVALID VALUE HERE!";
        break;
      case SRx_RESULT_INVALID:
        resultStr = "INVALID";
        break;
      case SRx_RESULT_DONOTUSE:
        resultStr = "DONOTUSE <- SHOULD NOT BE HERE - SRx INTERNAL ONLY, "
                    "NEVER PROXY";
        break;        
      default:
        resultStr = "???????";
    }
    PRINTF("%s BGPSEC=%s", (printROA ? "; " : ""), resultStr);
  }

  if (!(printROA || printBGPSEC))
  {
    PRINTF("ERROR - no ROA or BGPSEC information!!!");
    retVal=false;
  }

  PRINTF("\n%s", PROMPT);
  fflush(stdout);
  return retVal;
}

/**
 * Used to return the calculated signatures.
 *
 * @todo Parameters have yet to be defined
 *
 * @param updateID The update id the signature is calculated for
 * @param userPtr data the data containing the signature (structure TBD)
 */
void handleSignatures(SRxUpdateID updateID, BGPSecCallbackData* bgpsecCallback, 
                      void* usrPtr)
{
  int i;
  PRINTF("Received a handle signature for update [0x%08X]\n", updateID);
  PRINTF("Data (%u bytes): ", bgpsecCallback->length);
  for (i = 0; i < bgpsecCallback->length; i++)
  {
    PRINTF("%c", (unsigned char)bgpsecCallback->data[i]);
  }
  PRINTF("\n");
}

/*-------------
 * Call the API
 */
/**
 * Connect to the SRx server using the global configures proxy instance.
 * Since version 0.3 this method also starts a server thread for polling the
 * srx proxy API.
 *
 * @param log indicates if the method logs the connection request.
 * @param argPtr The arguments for the SRx server, Host and Port. Can be kept
 *               empty, then it will be read from standard in
 */
void doConnect(bool log, char** argPtr)
{
  const char* input;
  char*       host = NULL;
  uint32_t    port;

  int         noPeers      = 0;
  int         peerLocation = 0;
  int         size = sizeof(uint32_t);
  uint32_t*   peerAS  = malloc(size); // space for one peer
  uint32_t    peer = 0;
  uint32_t    proxyID = IPtoInt(DEFAULT_PROXY_ID);

  bool        connected;

  char label[256]; // A 256 byte long buffer used as string buffer.
  
  // First check if the proxy is already connected.
  if (isConnected(proxy))
  {
    printf("Disconnect first before calling connect!\n");
    return;
  }

  memset(label, 0, 256);
  sprintf(label, "Host [default: '%s'] ? ", DEFAULT_SERVER);
  // Get the parameters
  input = prompt(argPtr, label);
  if (strlen(input) > 0)
  {
    host = malloc(strlen(input)+1);   
    memset(host, '\0', strlen(input)+1);
    strcpy(host, input);
  }
    
  memset(label, 0, 256);
  sprintf(label, "Port [default: %d] ? ", DEFAULT_PORT);
  port = promptU32(argPtr, label);
  if (port == 0)
  {
    port = DEFAULT_PORT;
  }

  memset(label, 0, 256);
  sprintf(label, "Proxy-id [default: %s] ? ", intToIP(proxy->proxyID));
  proxyID = promptIPv4Int(argPtr, label);
  if (proxyID == 0)
  {
    proxyID = proxy->proxyID;
  }

  memset(label, 0, 256);
  sprintf(label, "PeerAS [default: %d] ? ", DEFAULT_PEERAS);
  peer = promptU32(argPtr, label);
  while (peer != 0)
  {
    noPeers++;
    if (size < (noPeers * 4))
    {
      size = noPeers * 4;
      peerAS = realloc(peerAS, size);
    }

    peerAS[peerLocation] = peer;
    peerLocation++;
    peer = promptU32(argPtr, "PeerAS (enter for stop) ? ");
  }
  if ((noPeers == 0) && (peer == 0))
  {
    peerAS[0] = DEFAULT_PEERAS;
    noPeers++;
  }

  addPeers(proxy, noPeers, peerAS);

  if (log)
  {
    // Only the first peer is in history
    if (noPeers > 0)
    {
      addToHistory("connect %s %u %u %u", host == NULL ? DEFAULT_SERVER : host, 
                                          port, proxyID, peerAS[0]);
    }
    else
    {
      addToHistory("connect %s %u %u %u 0", host == NULL ? DEFAULT_SERVER 
                                                         : host, 
                                            port, proxyID, peerAS[0]);
    }
  }

  if (proxy->proxyID != proxyID)
  {
    proxy->proxyID = proxyID;
  }
  connected = connectToSRx(proxy, host == NULL ? DEFAULT_SERVER : host, port, 
                           SRX_DEFAULT_HANDSHAKE_TIMEOUT, !isBlocking);
  printf ("Connection to %s %s\n", 
           host == NULL ? DEFAULT_SERVER : host,
           connected ? "is successfully established!" : "failed!");
  if (host != NULL)
  {
    free(host);
    host=NULL;
  }
  freshConnected = connected;
}

/**
 * Request to disconnect from the SRx server instance
 * @param log indicates if the disconnect will be logged.
 */
void doDisconnect(bool log)
{
  if (disconnectFromSRx(proxy, SRX_DEFAULT_KEEP_WINDOW))
  {
    LOG(LEVEL_INFO, "Disconnected\n");
  }
  else
  {
    LOG(LEVEL_INFO, "Proxy is not connected, can not disconnect!\n");
  }
  if (log)
  {
    addToHistory("disconnect");
  }
}

/**
 * Connect to the SRx server using the global configures proxy instance.
 * Since version 0.3 this method also starts a server thread for polling the
 * srx proxy API.
 *
 * @param log indicates if the method logs the connection request.
 */
void doReConnect(bool log)
{
  if (isConnected(proxy))
  {
    bool reconnected = reconnectWithSRx(proxy);
    if (!reconnected)
    {
      doDisconnect(log);
    }

    printf("%s with SRx-Server%s!\n", reconnected ? "Successfully reconnected"
                                                  : "Reconnect",
                                      reconnected ? "" : " failed" );
  }
  else
  {
    printf("You first have to connect to the SRx-server!!\n");
  }
  
  addToHistory("reconnect");  
}


/**
 * Maintains the number of peers to the proxy. This method does not require an
 * active proxy connection.
 * 
 * @param log indicates if the method loggs the connection request.
 * @param argPtr The arguments for the SRx server, Host and Port. Can be kept
 * empty, then it will be read from standard in
 *
 * @param add it true the peer will be added, otherwise deleted.
 */
void doMaintainPeer(bool log, char** argPtr, bool add)
{
  uint32_t peerNr = 0;
  uint32_t newPeer = 0;
  uint32_t size   = sizeof(uint32_t);
  uint32_t* peerAS = malloc(size);

  do {
    newPeer = promptU32(argPtr, "Peer AS (0=end): ");
    if (newPeer > 0)
    {
      if (size <= (peerNr * sizeof(uint32_t)))
      {
        size = peerNr * sizeof(uint32_t);
        peerAS = realloc(peerAS, size);
      }
      peerAS[peerNr] = newPeer;
      peerNr++;
    }
  } while (newPeer > 0);
  
  if (peerNr > 0)
  {
    if (add)
    {
      addPeers(proxy, peerNr, peerAS);
    }
    else
    {
      removePeers(proxy, peerNr, peerAS);
    }
  }
  free (peerAS);
}

/**
 * Indicates to execute a verification request.
 * @param log
 * @param argPtr
 */
void doVerify(bool log, char** argPtr)
{
  uint32_t         localID;
  uint32_t         as32;
  const char*      prefixInput;
  const char*      bgpsecInput;
  IPPrefix         prefix;

  uint8_t          method;


  BGPSecData       bgpsec;

  char ipString[255];
  char* ipStringPtr = ipString;
  memset(ipString,'\0',255);
  
  if (!isConnected(proxy))
  {
    printf ("Connect to SRx server prior verification request!\n");
    return;
  }
  
  ////////////////////////////////////////
  /// READ PARAMETERS EITHER FROM COMMAND PATAMETER OR COMMAND LINE
  ///////////////////////////////////////
  // Receipt
  localID = (uint32_t)promptU32(argPtr, "(Verify) Local ID: "
                                        "[0=disable receipt] ? ");
  // Method
  method = (uint8_t)promptU32(argPtr, "(Verify) Method: "
                                   "[0=just store, 1=Origin only, "
                                   "2=Path only, 3=both] ? ");
  if (method > 3)
  {
    printf ("Invalid Method %u\n", method);
    return;
  }

  // Header data
  as32  = promptU32(argPtr, "(Verify) AS number ? ");

  // Prefix
  prefixInput = prompt(argPtr, "(Verify) IP Prefix [] ? ");
  if (!strToIPPrefix(prefixInput, &prefix))
  {
    printf("Error: Prefix [%s] is invalid\n", prefixInput);
    return;
  }
  sprintf(ipStringPtr, "%s", prefixInput);


  // Default result
  SRxDefaultResult defResult;
  defResult.result.roaResult = (uint8_t)promptU32(argPtr,
                 "(Verify) DefOriginVal: [0=VALID, 1=UNKNOWN, 2=INVALID, "
                 "3=Not Defined] ? ");
  if (defResult.result.roaResult > 3)
  {
    printf("Error: Default origin validation result [%u] is invalid\n",
           defResult.result.roaResult);
    return;
  }

  defResult.result.bgpsecResult = (uint8_t)promptU32(argPtr,
                         "(Verify) DefPathVal [0=VALID, 2=INVALID, "
                         "3=Not Defined] ? ");
  if (   (defResult.result.bgpsecResult > 3)
      || (defResult.result.bgpsecResult == 1))
  {
    printf("Error: Default path validation result [%u] is invalid\n",
           defResult.result.bgpsecResult);
    return;
  }

  defResult.resSourceROA = SRxRS_UNKNOWN;
  defResult.resSourceBGPSEC = SRxRS_UNKNOWN;

  // @TODO: Generate some test data for input
  bgpsecInput = prompt(argPtr, "(Verify) BGPSEC some string ? ");

  if (bgpsecInput == '\0')
  {
    bgpsec.numberHops = 0;
    bgpsec.asPath = NULL;
    bgpsec.attr_length = 0;
    bgpsec.bgpsec_path_attr = NULL;
  }
  else
  {
    bgpsec.numberHops = 0;
    bgpsec.asPath = NULL;
    bgpsec.attr_length = strlen(bgpsecInput)+1;
    bgpsec.bgpsec_path_attr = (uint8_t*)bgpsecInput;
  }
  
  if (log)
  {
    if (bgpsec.attr_length == 0)
    {
      addToHistory("verify %d %u %u %s %u %u %c" ,
                   localID, method, as32, ipStringPtr,
                   defResult.result.roaResult, defResult.result.bgpsecResult,
                   '\0');
    }
    else
    {
      addToHistory("verify %u %u %u %s %u %u %s" ,
                   localID, method, as32, ipStringPtr,
                   defResult.result.roaResult, defResult.result.bgpsecResult,
                   bgpsecInput);
    }
  }

  //////////////////////////////////////////////////////////
  //  Now send the message
  //////////////////////////////////////////////////////////

  if (localID != 0)
  {
    method = method | SRX_FLAG_REQUEST_RECEIPT;
  }
  
  if (stat_started)
  {
    stat_requests_send++;
  }

  // The method verifyUpdate will go into wait mode if receipt is requested.
  verifyUpdate(proxy, localID,
               (method & SRX_FLAG_ROA) == SRX_FLAG_ROA,
               (method & SRX_FLAG_BGPSEC) == SRX_FLAG_BGPSEC,
               &defResult, &prefix, as32, &bgpsec);
}

void doSign(bool log, char** argPtr)
{
  uint32_t    updateID       = 0;
  uint32_t    prependCounter = 0;
  uint32_t    peerAS         = DEFAULT_PEERAS;

  if (!isConnected(proxy))
  {
    LOG(LEVEL_INFO, "Proxy is not connected, can not request signatures!\n");
    return;
  }

  while (updateID == 0)
  {
    updateID = promptU32(argPtr, "Update ID 1..n (not 0) ? ");
  }

  while (prependCounter == 0)
  {
    prependCounter = promptU32(argPtr, "Prepend Counter 1..m (not 0) ? ");
  }

  peerAS = promptU32(argPtr, "Peer AS ? ");

  if (!signUpdate(proxy, updateID, false, 0, prependCounter, peerAS))
  {
    LOG(LEVEL_INFO, "The signature request could not be send!");
  }
  else
  {
    LOG(LEVEL_INFO, "The signature request successful send!");
  }
}

/**
 * This callback function allows the SRx to send a synchronization request to
 * the proxy.
 */
void handleSyncRequest()
{
  char* buff = malloc(46);
  memset(buff, '\0', 46);
  sprintf(buff, "verify 0 3 65500 10.10.0.0/16 0 0 MyUpdateNo1");
  processLine(false, buff);
  sprintf(buff, "verify 0 3 65501 10.20.0.0/17 0 2 MyUpdateNo2");
  processLine(false, buff);
  sprintf(buff, "verify 0 3 65502 10.30.0.0/18 1 2 MyUpdateNo3");
  processLine(false, buff);
  sprintf(buff, "verify 0 1 65503 10.40.0.0/19 2 3 MyUpdateNo4");
  processLine(false, buff);
  sprintf(buff, "verify 0 1 65504 10.50.0.0/20 3 3 MyUpdateNo5");
  processLine(false, buff);
  LOG(LEVEL_DEBUG, "This update expects back a notification because SRx assumes"
                  " that the update might be stored using the new default"
                  " value. A notification is necessary to guarantee consistency"
                  " between SRx and ALL proxies!");
  sprintf(buff, "verify 0 1 65504 10.50.0.0/20 0 0 MyUpdateNo5");
  processLine(false, buff);
  sprintf(buff, "verify 0 1 65504 10.60.0.0/21 3 3 MyUpdateNo6");
  processLine(false, buff);
  LOG(LEVEL_DEBUG, "This update expects back a notification because proxy "
                  " requested receipt!");
  sprintf(buff, "verify 0 1 65504 10.60.0.0/21 0 0 MyUpdateNo6");
  processLine(false, buff);
  free(buff);
}

/**
 * Send delete request to the server
 * 
 * @param log
 * @param argPtr
 */
void doDelete(bool log, char** argPtr)
{
  uint32_t    updateID    = 0;
  uint16_t    keep_window = 0;

  if (!isConnected(proxy))
  {
    printf ("Proxy is not connected, can not request update "
                    "deletion!\n");
    LOG(LEVEL_INFO, "Proxy is not connected, can not request update "
                    "deletion!\n");
    return;
  }

  keep_window = promptU32(argPtr, "Keep Window in seconds (Default 0)? ");

  updateID = promptU32(argPtr, "Update ID 1..n (0 = Abort) ? ");
  
  if (updateID != 0)
  {
    deleteUpdate(proxy, keep_window, updateID);
  }
  else
  {
    PRINTF("delete operation aborted!\n");
  }
}

/*-----
 * Main
 */

/**
 * Display version information.
 */
void showVersion()
{
  printf("SRX - Proxy for SRx Server Version " SRX_SERVER_VERSION "\n");
}

/**
 * Display credits information.
 */
void showCredits()
{
  showVersion();  
  printf(SRX_CREDITS);
}

/**
 * Display the help
 */
void showHelp()
{
  printf("Note that all arguments are optional\n"
         "------------------------------------\n"
         CMD_HELP "\n"
         "      This screen!\n"
         CMD_CREDITS "\n"
         "      Display the program credits!\n"
         CMD_QUIT ", \\q, " CMD_EXIT "\n"
         "      Quit this program.\n"
         CMD_CONNECT " <host> <port> <proxy-id> <peerAS> [<peerAS>*]\n"
         "      Connect to this SRx server.\n"
         CMD_DISCONNECT "\n"
         "      Disconnect from SRx.\n"
         CMD_RECONNECT "\n"
         "      Disconnect from SRx and reconnect to SRx using same proxy.\n"
         CMD_ADD_PEER " <peerAS> [<peerAS>*]\n"
         "      Adds a peer to the configuration.\n"
         CMD_DEL_PEER " <peerAS> [<peerAS>*]\n"
         "      Removed a peer from the configuration.\n"
         CMD_VERIFY " <requestID(0=disabled)> <method(0=Stopre Only, 1=RPKI, "
                "2=BGPSec, 3=Both)>\n"
         "      <as> <prefix> <defaultROAVal(0-Valid, 1=Unknown, 2=Invalid, "
                "3=Not Defined)>\n"
      "      <defaultBGPSECVal(0-Valid, 1=Unknown, 2=Invalid, 3=Not Defined)>\n"
         "      [bgpsec hex]\n"
         "      Initiates a verification request. This method waits \n"
         "      for SRx to return a receipt if receipt is requested!\n"
         CMD_SIGN " <updateID hex>\n"
         "      Initiate a signing request!\n"
         CMD_DELETE " <keep-window> <update-id>\n"
         "      Send a delete request for the given update to the srx server\n"
         CMD_RUN " <filename>\n"
         "      Execute a script with commands in it.\n\n"
         "Statistics Framework Commands:\n"    
         "------------------------------\n"
         " The statistics framework should only be used in combination with\n"
         " scripts. The verify command DOES NOT function using the command \n"
         " prompt due to the deactivated standard out!\n"
         CMD_STAT_INIT "\n"
         "      Initializes the statistics framework!"
         CMD_STAT_START "\n"
         "      Activate the collection mode. During this mode printouts for\n"
         "      notifications are suppressed to not influence the time "
                "measurements.\n"
         "      During this mode all print operations are suppressed to not\n"
         "      uneccessary waste processing time.\n"
         CMD_STAT_MARK_NO_RECEIPT " <marker>\n"
         "      Mark the framework to automatically print the statistics as\n"
         "      soon as the requested number of notifications is received.\n"
         "      only notifications without the receipt flag set can trigger\n"
         "      the report\n"
         CMD_STAT_MARK_WITH_RECEIPT " <marker>\n"
         "      Mark the framework to automatically print the statistics as\n"
         "      soon as the requested number of notifications is received.\n"
         CMD_STAT_EXIT_ON_MARK " <true|false>\n"
         "      Stop the program automatically when the marker is reached.\n"
         "      The program will be stopped using the \"quit\" command!\n"
         CMD_STAT_PRINT "\n"
         "      Print the statistics - need the statistics to be started!!\n"
         CMD_STAT_STOP "\n"
         "      Ends the statistics data collections.\n\n"
         "Extended Commands:\n"    
         "------------------\n"
         CMD_LOG_LEVEL " <level(0=CANCEL)>\n"
         "      Change the log level of the application.\n"
        "      Valid levels are: 0=CANCEL, 3=ERROR, 5=NOTICE, 6=INFO, 7=DEBUG\n"
         CMD_RESET_PROXY "<proxyID(0=cancel)>\n"
         "      Release the current proxy and instantiate a new one.\n"
         "      The id can be scripted as integer or in IPv4 format.\n"        
         CMD_USE_NON_BLOCKING_SOCKET_TYPE " <true|false>\n"
         "      Determines the type of proxy to be generated. By default the \n"
         "      socket used is blocking.\n"
         "\n\n");
}

/**
 * Change the log level of the application
 *
 * @param argPtr the possible argument.
 */
void processLogLevel(char** argPtr)
{
  uint32_t newLevel = 0;
  bool levelOK = false;

  while (!levelOK)
  {
    newLevel = promptU32(argPtr, "LOG_LEVEL (0=CANCEL, 3=ERROR, 5=NOTICE, "
                                 "6=INFO, 7=DEBUG) : ");
    switch(newLevel)
    {
      case LEVEL_ERROR  :
      case LEVEL_NOTICE :
      case LEVEL_INFO   :
      case LEVEL_DEBUG  :
        logLevel = newLevel;
        setLogLevel(logLevel);
      case 0 : // cancel
        levelOK = true;
        break;
      default:
        printf("The provided level [%u] is invalid!\n", newLevel);
    }
    if (newLevel == 0)
    {
      printf("Level not changed!\n");
    }
    else
    {
      printf("Changed log level to %u!\n", logLevel);      
    }
  }
}

/**
 * Reset the proxy.
 *
 * @param argPtr Contains the proxy ID
 */
void resetProxy(char** argPtr)
{
  uint32_t proxyID = promptIPv4Int(argPtr, "ProxyID: ");
  if (proxyID == 0)
  {
    printf ("Reset canceled!\n");
  }
  else
  {
    if (proxy != NULL)
    {
      int fd = getInternalSocketFD(proxy, false);
      bool currentModeBlocking = isConnected(proxy) ? fd == -1 : isBlocking;
      
      printf("Release current proxy %s [0x%08X] (%u); mode: %sblocking\n", 
             intToIP(proxy->proxyID),  proxy->proxyID,  proxy->proxyID,
             currentModeBlocking ? "" : "non-");      
      releaseSRxProxy(proxy); // Also disconnects if necessary
      
      printf("Create new proxy %s [0x%08X] (%u); mode: %sblocking...",
             intToIP(proxyID),  proxyID,  proxyID, isBlocking ? "" : "non-");
      if (fd != -1)
      {
        close(fd);
      }
      proxy = createSRxProxy(handleValidationResult, handleSignatures,
                             handleSyncRequest, commManagement,
                             proxyID,
                             50, // ProxyAS
                             NULL);
      if (proxy == NULL)
      {
        printf("failed!\n");
        RAISE_SYS_ERROR("Proxy Could not be created!");
      }
      else
      {
        printf("done!\n");
      }
    }
  }
  addToHistory("%s %u", CMD_RESET_PROXY, proxyID);
}

/**
 * Set the socket type.
 *
 * @param argPtr Contains the socket type
 * 
 * @since 0.3.0
 */
void setSocketType(char** argPtr)
{
  bool oldBlocking = isBlocking;
  bool useNonBlocking = !isBlocking;
  
  if(isConnected(proxy))
  {
    printf("Proxy MUST NOT be connected\n");
    return;
  }
  
  if (promptBool(argPtr, "Use Non-Blocking (true|false)? ", &useNonBlocking, 
                 NULL))
  {
    isBlocking = !useNonBlocking;
    if (oldBlocking != isBlocking)
    {
      printf("Switch from %sblocking to %sblocking%s\n", 
             oldBlocking ? "" : "non-", isBlocking ? "" : "non-", 
             isConnected(proxy) ? " for the next proxy" : "");
    }
    else
    {
      printf ("Keep socket state as is: %sblocking\n", 
              oldBlocking ? "" : "non-");
    }

    addToHistory("%s %s", CMD_USE_NON_BLOCKING_SOCKET_TYPE, 
                 isBlocking ? "true" : "false");
  }
}

/**
 * Load a script and executes line by line.
 * 
 * @param log it true the commands will be added to the history.
 *
 * @param argPtr contains the script filename
 */
void runScript(bool log, char** argPtr)
{
  #define SCRIPT_BUF_SIZE 1024

  char* fname = NULL;
  FILE* fh = NULL;
  char  buf[SCRIPT_BUF_SIZE];
  int   pos = 0;

  fname = prompt(argPtr, "Script filename ? ");
  fh = fopen(fname, "rt");
  if (fh == NULL)
  {
    int error = errno;
    switch (error)
    {
      case ENOENT: 
        printf("Error: file '%s' not found!\n", fname);
        break;
      default:
        printf("Error: Attempt top open file '%s' returned error [%d]\n", 
               fname, error);      
    }    
    return;
  }

  if (log)
  {
    addToHistory("run %s", fname);
  }
  
  // Turn off history
  scriptMode = true;

  while (fgets(buf, SCRIPT_BUF_SIZE, fh))
  {
    // Strip the line ending and space
    chomp(buf);

    // An empty line or comment
    if ((pos < 0) || (*buf == '#'))
    {
      continue;
    }

    (void)processLine(false, buf);
  }

  fclose(fh);
  
  // Turn history back on.
  scriptMode = false;
}

/**
 * Process and execute the given line.
 *
 * @param log it ture the line will be added to the history
 * @param line The line to be processed
 *
 * @return returns if the program has to be ended.
 */
bool processLine(bool log, char* line)
{
  char* cmd, *arg;


  if ((line == NULL) || (*line == '\0'))
  {
    return false;
    
  }
    
  // Split into command and (optional) arguments
  arg = line;
  cmd = strsep(&arg, " \t");

  // Execute the command
  #define IF_EQ_DO(LONG, CMD) \
    if (!strcmp(cmd, LONG))   \
    {                         \
      CMD;                    \
    }

  IF_EQ_DO(CMD_QUIT, return true)
  else IF_EQ_DO("\\q", return true)
  else IF_EQ_DO(CMD_EXIT, return true)
  else IF_EQ_DO(CMD_HELP, showHelp())
  else IF_EQ_DO(CMD_CREDITS, showCredits())
  else IF_EQ_DO(CMD_CONNECT, doConnect(log, &arg))
  else IF_EQ_DO(CMD_DISCONNECT, doDisconnect(log))
  else IF_EQ_DO(CMD_RECONNECT, doReConnect(log))
  else IF_EQ_DO(CMD_ADD_PEER, doMaintainPeer(log, &arg, true))
  else IF_EQ_DO(CMD_DEL_PEER, doMaintainPeer(log, &arg, false))
  else IF_EQ_DO(CMD_VERIFY, doVerify(log, &arg))
  else IF_EQ_DO(CMD_SIGN, doSign(log, &arg))
  else IF_EQ_DO(CMD_DELETE, doDelete(log, &arg))
  else IF_EQ_DO(CMD_RUN, runScript(log, &arg))  
  else IF_EQ_DO(CMD_STAT_INIT, fstatInitializeStatistics(true))
  else IF_EQ_DO(CMD_STAT_START, fstatStartStatistics(true))
  else IF_EQ_DO(CMD_STAT_MARK_WITH_RECEIPT, fstatMarkNotifications(&arg, true))
  else IF_EQ_DO(CMD_STAT_MARK_NO_RECEIPT, fstatMarkNotifications(&arg, false))
  else IF_EQ_DO(CMD_STAT_EXIT_ON_MARK, fstatSetExitOnMark(&arg))    
  else IF_EQ_DO(CMD_STAT_PRINT, fstatGetStatistics(true))     
  else IF_EQ_DO(CMD_STAT_STOP, fstatStopStatistics(true))     
  else IF_EQ_DO(CMD_LOG_LEVEL, processLogLevel(&arg))
  else IF_EQ_DO(CMD_RESET_PROXY, resetProxy(&arg))
  else IF_EQ_DO(CMD_USE_NON_BLOCKING_SOCKET_TYPE, setSocketType(&arg))
    
  else
  {
    printf("Unknown command!\n");
  }
  
  bool stop = proxy == NULL;

  return stop;
}

/** The main program.*/
int main(int argc, char* argv[])
{
  char* line;
  bool  stop;

  // Set the target for the logging.
  setLogMethodToFile(stderr);  
  setLogLevel(logLevel);
  // initialize the statistics framework
  fstatInitializeStatistics(false);
  uint32_t proxyID = IPtoInt(DEFAULT_PROXY_ID);
  // Create instance
  proxy = createSRxProxy(handleValidationResult, handleSignatures,
                         handleSyncRequest, commManagement,
                         proxyID,
                         50, // ProxyAS
                         NULL);

  if (proxy == NULL)
  {
    RAISE_ERROR("Proxy could not be created. Abort program!\n");
    return -1;
  }

  printf ("SRX API Test Harness Version 0.3\n");

  // Main user-input loop
  using_history();
  read_history(HISTORY_FILENAME);

  // Create the proxy poller thread
  pthread_t pollThread;
  int retVal = pthread_create(&pollThread, NULL, pollProxy, NULL);
  if (retVal)
  {
    printf ("ERROR poll-thread could not be created. return code %d\n", retVal);
    exit(1);
  }
  
  rl_attempted_completion_function = code_completion;
  rl_bind_key('\t', rl_complete);    
  
  do
  {
    line = readline(PROMPT);
    stop = processLine(true, trim(line));
    free(line);
  } while (!stop);

  write_history(HISTORY_FILENAME);

  // Destroy the instance
  if (proxy != NULL)
  {
    printf("Release proxy %s [0x%08X] (%u)\n", intToIP(proxy->proxyID), 
           proxy->proxyID, proxy->proxyID);
    
    releaseSRxProxy(proxy);
  }

  printf ("Goodbye!\n\n");

  keepGoing = false;
  usleep(1000); // wait one milli second to proceed
  // Release the thread
  pthread_join(pollThread, NULL);

  return 0;
}

