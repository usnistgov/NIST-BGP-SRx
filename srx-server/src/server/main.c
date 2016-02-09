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
 * SRx Server - main program file.
 *
 * In this version the SRX server only can connect to once RPKI VALIDATION CACHE
 * MULTI CACHE will be part of a later release.
 *
 * @version 0.3.0.10
 *
 * EXIT Values:
 *
 *   0 OK - System performed just fine!
 *   1 System could not be configures.
 *   2 Caches could not be created.
 *   3 Handlers could not be created.
 *   4 Queues could not be created.
 *
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/10 - oborchert
 *            * Removed unused static colsoleLoop
 * 0.3.0.7  - 2015/04/21 - oborchert
 *            * Modified version output.
 * 0.3.0.0  - 2014/11/17 - oborchert
 *            * Removed constant value for configuration file and replaced it
 *              with a defined one in config.h. Also modified the determination
 *              process on how to figure out which configuration file to load.
 *          - 2013/02/05 - oborchert
 *            * Fixed parameter processing when help is requested
 *          - 2012/11/23 - oborchert
 *            * Extended version handling. - F for full version
 *            * Added capability to pass configuration file as parameter (-f)
 * 0.2.0.0  - 2011/01/07 - oborchert
 *            * Changelog added with version 0.2.0 and date 2011/01/07
 *            * Version tag added
 *            * Added handling of SIGKILL to allow a clean shutdown when killing
 *              the server. this helps saving time especially during debugging
 *            * Added documentation.
 * 0.1.0.0  - 2010/04/26 - pgleichm
 *            * Code Created
 * -----------------------------------------------------------------------------
 *
 */
#include <stdio.h>
#include <signal.h>
#include "server/bgpsec_handler.h"
#include "server/command_handler.h"
#include "server/command_queue.h"
#include "server/configuration.h"
#include "server/console.h"
#include "server/key_cache.h"
#include "server/prefix_cache.h"
#include "server/rpki_handler.h"
#include "server/server_connection_handler.h"
#include "server/srx_server.h"
#include "server/srx_packet_sender.h"
#include "server/update_cache.h"
#include "util/directory.h"
#include "util/log.h"

// Some defines needed for east
#define SETUP_RPKI_HANDLER         1
#define SETUP_BGPSEC_HANDLER       2
#define SETUP_COMMAND_HANDLER      4
#define SETUP_CONNECTION_HANDLER   8
#define SETUP_ALL_HANDLERS        15

#define SETUP_KEY_CACHE            1
#define SETUP_PREFIX_CACHE         2
#define SETUP_UPDATE_CACHE         4
#define SETUP_ALL_CACHES           8

#define HDR "([0x%08X] Main): "

///////////////////
// Global variables
///////////////////

/** Contains the server configuration. */
static Configuration config;
/** The cache that manages updates. */
static UpdateCache   updCache;
/** The cache that manages roa's. */
static PrefixCache   prefixCache;
/** The cache that manages keys for bgpsec. */
static KeyCache      keyCache;
/** The server console. */
static SRXConsole    console;



/** Handles ROA validation requests              - Currently only one cache. **/
static RPKIHandler              rpkiHandler;

/** Handles BGPSEC path validation requests.     - Currently only one cache. **/
static BGPSecHandler            bgpsecHandler;



/** Queues commands to be processed.  */
static CommandQueue             cmdQueue;
/** Handles the commands that are to be processed.  */
static CommandHandler           cmdHandler;
/** Manages the server connections.  */
static ServerConnectionHandler  svrConnHandler;

static bool cleanupRequired = false;


// To allow to use it already ;-)
static void doCleanupHandlers(int handler);

////////////////////
// Server Call backs
////////////////////

/** This method handles changes of previously processed updates. Here the new
 * results are broadcasted to the SRX clients connected to the srx server.
 * @param updateId The update whose validation result changed
 * @params newRes The new validation result.
 */
static void handleUpdateResultChange (SRxValidationResult* valResult)
{
  broadcastResult (&cmdHandler, valResult);
}

////////////////////////
// Server Implementation
////////////////////////

/*----------------
 * This method reads the program parameters as well as the configuration file
 * to configure the application. The configuration file used is
 *
 * @param argc Contains the number of arguments passed
 * @param argv The array containing the parameters
 *
 * @return 1 if the configuration is created succesful, 0 if errors occured,
 *         -1 if the configuration was manually stopped (example: -h).
 *
 * @see initConfiguration, parseProgramArgs
 */
static int setupConfiguration (int argc, const char* argv[])
{
  int params;

  // Set to defaults
  //initConfiguration(&config, DEFAULT_CONFIG_FILE);
  initConfiguration(&config);
  // check if a user specific configuration file is requested!
  params = parseProgramArgs(&config, argc, argv, true);
  if (params != 1)
  {
    return params;
  }

  // Try to read only if the file exists
  if (fileIsReadable(config.configFileName))
  {
    if (!readConfigFile(&config, config.configFileName))
    {
      printf("Cannot apply configuration \'%s\'\n", config.configFileName);
      return 0;
    }
  }
  else
  {
    // Check if configuration file is located in installed etc folder

    printf("Cannot access \'%s\'\n", config.configFileName);
    return 0;
  }

  // Handle the command-line
  params = parseProgramArgs(&config, argc, argv, false);
  if (params != 1)
  {
    // If needed, error message already generated in method parseProgramArgs
    return params;
  }

  // Stop if the configuration is not complete
  if (!isCompleteConfiguration(&config))
  {
    RAISE_ERROR("Not all necessary configuration options are set!");
    return 0;
  }

  if ( !config.verbose )
  {
    // If verbose is turned off, at least set ERROR output.
    setLogLevel(LEVEL_ERROR);
  }
  else
  {
    // Set log level for verbose output
    setLogLevel(config.loglevel);
  }

  if (config.msgDest == MSG_DEST_SYSLOG)
  {
    setLogMethodToSyslog();
  }

  LOG(LEVEL_INFO, "- Configuration processed");
  return 1;
}

/**
 * Setup the internal caches. The program consists of 3 caches, the update
 * cache, the prefix cache (for roa validation) and the key cache (for bgpsec
 * validation).
 * @return true if the caches could be creates, otherwise false.
 */
static bool setupCaches()
{
  if (   !createUpdateCache(&updCache, handleUpdateResultChange,
                            config.expectedProxies, &config)
      || !initializePrefixCache(&prefixCache, &updCache)
      || !createKeyCache(&keyCache, &updCache, NULL, NULL))
  { ///< TODO Set KeyInvalidated, KeyNotFound
    RAISE_ERROR("Failed to setup a cache - stopping");
    return false;
  }

  LOG(LEVEL_INFO, "- Caches created");
  return true;
}

/**
 * Create the handlers for the different validation caches and server
 * connections.
 * @return true if all caches could be setup properly.
 */
static bool setupHandlers()
{
  uint8_t handlers = 0;
  bool retVal = true;

  if (!createRPKIHandler (&rpkiHandler, &prefixCache,
                          config.rpki_host, config.rpki_port))
  {
    RAISE_ERROR("Failed to create RPKI Handler.");
  }
  else
  {
    handlers |= SETUP_RPKI_HANDLER;
    if (!createBGPSecHandler (&bgpsecHandler, &keyCache,
                              config.bgpsec_host, config.bgpsec_port))
    {
      RAISE_ERROR("Failed to create BGPSEC Handler.");
    }
    else
    {
      handlers |= SETUP_BGPSEC_HANDLER;
      if (!createServerConnectionHandler (&svrConnHandler, &updCache, &config))
      {
        RAISE_ERROR("Failed to create Server Connection Handler.");
      }
      else
      {
        handlers |= SETUP_CONNECTION_HANDLER;
        if (!initializeCommandHandler (&cmdHandler, &config, &svrConnHandler,
                                       &bgpsecHandler, &rpkiHandler, &updCache))
        {
          RAISE_ERROR("Failed to create Command Handler.");
        }
        else
        {
          handlers |= SETUP_COMMAND_HANDLER;
        }
      }
    }
  }

  if (handlers == SETUP_ALL_HANDLERS)
  {
    LOG(LEVEL_INFO, "- All Handlers created");
  }
  else
  {
    doCleanupHandlers(handlers);
    retVal = false;
  }

  return retVal;
}

/**
 * Setup the program - command queue.
 *
 * @return true if the queue could be created successfully, otherwise false.
 */
static bool setupQueues()
{
  bool cont = true;

  if (!config.mode_no_sendqueue)
  {
    cont = false;
    if (createSendQueue())
    {
      if (startSendQueue())
      {
        // Send queue successfully started
        cont = true;
      }
      else
      {
        RAISE_ERROR("Failed to start Send Queue!");
        releaseSendQueue();
      }
    }
  }

  if (cont)
  {
    if (!initializeCommandQueue(&cmdQueue))
    {
      stopSendQueue();
      releaseSendQueue();
      RAISE_ERROR("Failed to initialize Command Queue!");
      cont = false;
    }
    else
    {
      LOG(LEVEL_INFO, "- Command Queue created!");
    }
  }

  return cont;
}

/**
 * Callback function for the signal handler. This signals are usually program
 * termination signals. This function provides a clean shutdown of the srx
 * server.
 * @param _sig The signal received.
 */
static void signalReceived(int _sig)
{
  LOG(LEVEL_INFO, "Signal (%u) received - stopping", _sig);

  // First stop the command handler b/c there won't be any socket to send
  // result back
  stopProcessingCommands(&cmdHandler);

  // Disconnect all clients
  stopProcessingRequests(&svrConnHandler);

  releaseConsole(&console);

  // Stopps, clears and releases all memory used by the send queue
  releaseSendQueue();
}

/**
 * The main server thread loop.
 * @see startProcessingCommands, startProcessingRequests
 */
static void run()
{
  // Install the interrupt and 'hup' callback
  signal(SIGINT, &signalReceived);
  signal(SIGHUP, &signalReceived);
  signal(SIGKILL, &signalReceived);

  // Let the command handler threads wait for commands
  if (startProcessingCommands(&cmdHandler, &cmdQueue))
  {
    // Receive commands (block)
    LOG(LEVEL_INFO, "SRX server running, control via telnet on port %u",
        config.console_port);
    startProcessingRequests(&svrConnHandler, &cmdQueue);
    LOG(LEVEL_INFO, "SRX server stopped");
  }
}

/**
 * Release the memory for each handler defined in the handler variable.
 *
 * @param handler Contains the information which handlers to clean up.
 */
static void doCleanupHandlers(int handler)
{
  if ((handler & SETUP_CONNECTION_HANDLER) > 0)
  {
    releaseServerConnectionHandler(&svrConnHandler);
  }
  if ((handler & SETUP_COMMAND_HANDLER) > 0)
  {
    releaseCommandHandler(&cmdHandler);
  }
  if ((handler & SETUP_BGPSEC_HANDLER) > 0)
  {
    releaseBGPSecHandler(&bgpsecHandler);
  }
  if ((handler & SETUP_RPKI_HANDLER) > 0)
  {
    releaseRPKIHandler(&rpkiHandler);
  }
}

/**
 * Release all caches specified in the bit coded parameter cache
 *
 * @param cache Bit coded value that specifies which caches have to be released.
 */
static void doCleanupCaches(int cache)
{
  if ((cache & SETUP_KEY_CACHE) > 0)
  {
    releaseKeyCache(&keyCache);
  }
  if ((cache & SETUP_PREFIX_CACHE) > 0)
  {
    releasePrefixCache(&prefixCache);
  }
  if ((cache & SETUP_UPDATE_CACHE) > 0)
  {
    releaseUpdateCache(&updCache);
  }
}

/**
 * Provides the functionality of a clean shutdown. This function releases all
 * caches, handlers, etc.
 */
static void doCleanup()
{
  // First disconnects the server console.
  releaseConsole(&console);

  // Queues
  releaseCommandQueue(&cmdQueue);
  releaseSendQueue();

  // Handlers
  doCleanupHandlers(SETUP_ALL_HANDLERS);

  // Caches
  doCleanupCaches(SETUP_ALL_CACHES);

  // Configuration
  releaseConfiguration(&config);
}

/**
 * Stop the server by cleaning up all handlers. This method calls raise(15) to
 * stop the process.
 */
void shutDown()
{
  LOG(LEVEL_DEBUG, HDR "Received Shutdown request!", pthread_self());

  // Set the shutdown flag
  markConnectionHandlerShutdown(&svrConnHandler);

  SRXPROXY_GOODBYE pdu;
  uint32_t length = sizeof(SRXPROXY_GOODBYE);
  pdu.type = PDU_SRXPROXY_GOODBYE;
  pdu.keepWindow = 0;
  pdu.zero = 0;
  pdu.length = htonl(length);
  broadcastPacket(cmdHandler.svrConnHandler, &pdu, length);

    // First stop the command handler b/c there won't be any socket to send
  // result back
  stopProcessingCommands(&cmdHandler);

  // Disconnect all clients
  stopProcessingRequests(&svrConnHandler);

  cleanupRequired = false;

  doCleanup();
  LOG(LEVEL_DEBUG, HDR "Shutdown performed!", pthread_self());
  raise(15);
}

/**
 * The main program entry point. This function starts the server program.
 *
 * @param argc The number of arguments passed.
 * @param argv The array of arguments passed to the server
 *
 * @return the exit code.
 */
int main(int argc, const char* argv[])
{
  //bool cleanupRequired = false;
  int exitCode = 0;
  int passedConfig;
  bool printGoodbye = true;
  FILE* fp=NULL;

  // By default all messages go to standard error
  setLogMethodToFile(stderr);
  setLogLevel(LEVEL_ERROR);

  printf ("Start %s Version%s (%s)\n", SRX_SERVER_NAME, SRX_SERVER_VERSION,
          __TIME__);
  passedConfig = setupConfiguration(argc, argv);

  if(config.msgDestFilename)
  {
    fp = fopen(config.msgDestFilename, "wt");
    if(fp)
      setLogMethodToFile(fp);
    else
      LOG(LEVEL_ERROR, "Could not set log file.");
  }

  LOG(LEVEL_DEBUG, "([0x%08X]) > Start Main SRx server thread.", pthread_self());

  if ( passedConfig != 1)
  {
    printGoodbye=false;
    if (passedConfig == 0)
    {
      LOG(LEVEL_ERROR, "Failure loading configuration, exit program (1)");
      exitCode = 1;
    }
    else
    {
      exitCode = 0;
    }
  }
  // Setup all necessary instances
  else if ( !setupCaches() )
  {
    LOG(LEVEL_ERROR, "Failure setting up caches, exit program (2)");
    // So far only the Configuration is created .
    releaseConfiguration(&config);
    exitCode = 2;
  }
  else if ( !setupHandlers() )
  {
    LOG(LEVEL_ERROR, "Failure setting up handlers, exit program (3)");
    // So far Caches and the Configuration are created .
    doCleanupCaches(SETUP_ALL_CACHES);
    releaseConfiguration(&config);
    exitCode = 3;
  }
  else if ( !setupQueues() )
  {
    LOG(LEVEL_ERROR, "Failure setting up queues, exit program (4)");
    // So far Handlers, Caches and the Configuration are created .
    doCleanupHandlers(SETUP_ALL_HANDLERS);
    doCleanupCaches(SETUP_ALL_CACHES);
    releaseConfiguration(&config);
    exitCode = 4;
  }
  else if (!createConsole(&console, config.console_port, shutDown,
                          &config, &rpkiHandler, &cmdHandler))
  {
    LOG(LEVEL_ERROR, "Failure setting up the console, exit program (5)");
    // So far Handlers, Caches and the Configuration are created .
    releaseCommandQueue(&cmdQueue);
    doCleanupHandlers(SETUP_ALL_HANDLERS);
    doCleanupCaches(SETUP_ALL_CACHES);
    releaseConfiguration(&config);
    exitCode = 5;
  }
  else
  {
    // Ready for requests
    cleanupRequired = true;
    run();
  }

  // End the program
  if(cleanupRequired)
  {
    doCleanup();
  }

  if (printGoodbye)
  {
    printf ("Goodbye!\n");
  }

  LOG(LEVEL_DEBUG, "([0x%08X]) < Stop Main SRx server thread.", pthread_self());
  if(fp)
    fclose(fp);
  return exitCode;
}
