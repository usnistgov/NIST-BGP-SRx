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
 * @version 0.6.0.0
 *
 * EXIT Values:
 *
 *   0 OK - System performed just fine!
 *   1 System could not be configured.
 *   2 Caches could not be created.
 *   3 Handlers could not be created.
 *   4 Queues could not be created.
 *   5 Could not create the console thread.
 *
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.6.0.0  - 2021/03/30 - oborchert
 *            * Changed SRXPROXY_GOODBYE->zero to SRXPROXY_GOODBYE->zero32
 * 0.5.1.1  - 2020/07/22 - oborchert
 *            * Fixed a speller
 *            * Fixed error message when unknown parameter is provided.
 * 0.5.0.1  - 2017/08/29 - oborchert
 *            * Fixed compiler warning in define SETUP_ALL_HANDLERS
 * 0.5.0.0  - 2017/07/08 - oborchert
 *            * Added getBGPsecHandler
 *          - 2017/07/05 - oborchert
 *            * Modified how SETUP_ALL_HANDLERS is calculated
 *          - 2017/07/03 - oborchert
 *            * Modified the flow of the main method - added all into a switch/
 *              case block.
 *            * Added cleanup of CAPI
 *          - 2017/06/29 - oborchert
 *            * Added rpkiQueue and skiCache
 *          - 2017/06/21 - oborchert
 *            * Added main.h to resolve compiler warning for getSrxCAPI()
 *          - 2017/06/16 - kyehwanl
 *            * Added SRxCryproAPI
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
#include "server/main.h"
#include "server/rpki_handler.h"
#include "server/rpki_queue.h"
#include "server/server_connection_handler.h"
#include "server/ski_cache.h"
#include "server/srx_server.h"
#include "server/srx_packet_sender.h"
#include "server/update_cache.h"
#include "server/aspath_cache.h"
#include "server/aspa_trie.h"
#include "util/directory.h"
#include "util/log.h"

// Some defines needed for east
#define SETUP_RPKI_HANDLER         1
#define SETUP_BGPSEC_HANDLER       2
#define SETUP_COMMAND_HANDLER      4
#define SETUP_CONNECTION_HANDLER   8
#define SETUP_ALL_HANDLERS         (   SETUP_RPKI_HANDLER \
                                     | SETUP_BGPSEC_HANDLER \
                                     | SETUP_COMMAND_HANDLER \
                                     | SETUP_CONNECTION_HANDLER )

#define SETUP_KEY_CACHE            1
#define SETUP_PREFIX_CACHE         2
#define SETUP_UPDATE_CACHE         4
#define SETUP_SKI_CACHE            8
#define SETUP_ALL_CACHES          SETUP_KEY_CACHE \
                                  | SETUP_PREFIX_CACHE \
                                  | SETUP_UPDATE_CACHE \
                                  | SETUP_SKI_CACHE

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
/** The cache that manages bgpsec update and key registrations. 
 *  @since 0.5.0.0 */
static SKI_CACHE*    skiCache  = NULL;
/** The RPKI queue that is used to manage changes in the RPKI.
 * @since 0.5.0.0 */
static RPKI_QUEUE*   rpkiQueue = NULL;

static AspathCache  aspathCache;
static TrieNode     aspaTrie;
static ASPA_DBManager aspaDBManager;

/** The cache that manages keys for bgpsec. 
 * @deprecated  MIGHT BE NOT USED
 */
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

/** Holds the SRxCryptoAPI */
SRxCryptoAPI* g_capi = NULL;

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
 * @return 1 if the configuration is created successful, 0 if errors occurred,
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
    if (params == -2)
    {
      params = -1;
    }
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
 * Setup the internal caches. The program consists of 4 caches, the update
 * cache, the prefix cache (for roa validation) and the key cache (for bgpsec
 * validation - deprecated) and the skiCache for bgpsec key and update 
 * management.
 * 
 * @return true if the caches could be creates, otherwise false.
 */
static bool setupCaches()
{
  rpkiQueue = rq_createQueue();
  skiCache  = ski_createCache(rpkiQueue);
  if (   !createUpdateCache(&updCache, handleUpdateResultChange,
                            config.expectedProxies, &config)
      || !initializePrefixCache(&prefixCache, &updCache)
      || !createKeyCache(&keyCache, &updCache, NULL, NULL)
      || (skiCache == NULL))
  { ///< TODO Set KeyInvalidated, KeyNotFound
    if (skiCache != NULL)
    {
      ski_releaseCache(skiCache);
      skiCache = NULL;
    }
    if (rpkiQueue != NULL)
    {
      rq_releaseQueue(rpkiQueue);
      rpkiQueue = NULL;
    }
    RAISE_ERROR("Failed to setup a cache - stopping");    
    return false;
  }
  initializeAspaDBManager(&aspaDBManager, &config);    // ASPA: ASPA object DB
  createAspathCache(&aspathCache, &aspaDBManager); // ASPA: AS path DB 

  LOG(LEVEL_INFO, "- SRx Caches and RPKI Queue created");
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

  if (!createRPKIHandler (&rpkiHandler, &prefixCache, &aspathCache, &aspaDBManager,
                          config.rpki_host, config.rpki_port, 
                          config.rpki_router_protocol))
  {
    RAISE_ERROR("Failed to create RPKI Handler.");
  }
  else
  {
    handlers |= SETUP_RPKI_HANDLER;
    if (!createBGPSecHandler (&bgpsecHandler, &keyCache))
    {
      RAISE_ERROR("Failed to create BGPSEC Handler.");
    }
    else
    {
      handlers |= SETUP_BGPSEC_HANDLER;
      if (!createServerConnectionHandler (&svrConnHandler, &updCache, &aspathCache, &config))
      {
        RAISE_ERROR("Failed to create Server Connection Handler.");
      }
      else
      {
        handlers |= SETUP_CONNECTION_HANDLER;
        if (!initializeCommandHandler (&cmdHandler, &config, &svrConnHandler,
                                       &bgpsecHandler, &rpkiHandler, &updCache, &aspathCache))
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

  // Stops, clears and releases all memory used by the send queue
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
    LOG(LEVEL_DEBUG, "Release Server Connection Handler");
    releaseServerConnectionHandler(&svrConnHandler);
  }
  if ((handler & SETUP_COMMAND_HANDLER) > 0)
  {
    LOG(LEVEL_DEBUG, "Release Command Handler");
    releaseCommandHandler(&cmdHandler);
  }
  if ((handler & SETUP_BGPSEC_HANDLER) > 0)
  {
    LOG(LEVEL_DEBUG, "Release BGPSEC Handler");
    releaseBGPSecHandler(&bgpsecHandler);
  }
  if ((handler & SETUP_RPKI_HANDLER) > 0)
  {
    LOG(LEVEL_DEBUG, "Release RPKI Handler");
    releaseRPKIHandler(&rpkiHandler);
  }
}

/**
 * Release all caches specified in the bit coded parameter cache. The SKI_CACHE 
 * also cleans up the RPKI QUEUE.
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
  // Added with 0.5.0.0
  if ((cache & SETUP_SKI_CACHE) > 0)
  {
    ski_releaseCache(skiCache);    
    skiCache  = NULL;
    rq_releaseQueue(rpkiQueue);
    rpkiQueue = NULL;
  }
}

/**
 * Provides the functionality of a clean shutdown. This function releases all
 * caches, handlers, etc.
 */
static void doCleanup()
{
  // First disconnects the server console.
  // BZ1006: disconnects the server console - Only if this is not the console 
  //         itself.
  if (pthread_self() != console.consoleThread)
  {
    releaseConsole(&console);  
  }

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
  pdu.zero32 = 0;
  pdu.length = htonl(length);
  broadcastPacket(cmdHandler.svrConnHandler, &pdu, length);

  cleanupRequired = true;
  
    // First stop the command handler b/c there won't be any socket to send
  // result back
  stopProcessingCommands(&cmdHandler);

  // Disconnect all clients
  stopProcessingRequests(&svrConnHandler);

//  LOG(LEVEL_DEBUG, "HERE I AM - shutdown");
  
//  cleanupRequired = false;

//  doCleanup();
  LOG(LEVEL_DEBUG, HDR "Shutdown performed!", pthread_self());
//  raise(15);
}

/**
 * Return the pointer to CAPI
 *
 * @return the pointer to CAPI
 * 
 * @since 0.5.0.0
 */
SRxCryptoAPI* getSrxCAPI()
{
  return g_capi;
}

/**
 * Return the pointer to the SKI CACHE
 * 
 * @return the pointer to the SKI CACHE
 * 
 * @since 0.5.0.0
 */
SKI_CACHE* getSKICache()
{
  return skiCache;
}

/**
 * Return the pointer to the RPKI Queue
 * 
 * @return the pointer to the RPKI Queue
 * 
 * @since 0.5.0.0
 */
RPKI_QUEUE* getRPKIQueue()
{
  return rpkiQueue;
}

/**
 * Return the BGPsecHandler instance
 * 
 * @return the BGPsecHandler instance
 * 
 * @since 0.5.0.0
 */
BGPSecHandler* getBGPsecHandler()
{
  return &bgpsecHandler;
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
  sca_status_t sca_status = API_STATUS_OK;

  // By default all messages go to standard error
  setLogMethodToFile(stderr);
  setLogLevel(LEVEL_ERROR);

  printf ("Start %s Version%s (%s)\n", SRX_SERVER_NAME, SRX_SERVER_VERSION,
          __TIME__);
  passedConfig = setupConfiguration(argc, argv);

  switch (passedConfig)
  {
    case -1: 
    case 0: 
      // Error
      printGoodbye=false;
      if (passedConfig == 0)
      {
        LOG(LEVEL_ERROR, "Failure loading configuration, exit program (1)");
        exitCode = 1;
      }
      else
      {
        // HELP ONLY
        exitCode = 0;
      }
      break;
    case 1:
      // All OK

      // Try to set a log file.
      if(config.msgDestFilename)
      {
        fp = fopen(config.msgDestFilename, "wt");
        if(fp)
          setLogMethodToFile(fp);
        else
          LOG(LEVEL_ERROR, "Could not set log file.");
      }

      LOG(LEVEL_DEBUG, "([0x%08X]) > Start Main SRx server thread.", 
                       pthread_self());

      // srxcryptoapi INIT
      g_capi = malloc(sizeof(SRxCryptoAPI));
      if (g_capi != NULL)
      {
        memset (g_capi, 0, sizeof(SRxCryptoAPI));
        g_capi->configFile = config.sca_configuration;
      }
      
      // split the initialization of SCA into two phases to allow an immediate
      // setting of the debug level if necessary
      bool sca_INIT = srxCryptoInit(g_capi, &sca_status) == API_SUCCESS;
      if (sca_INIT)
      {
        // set CAPI log level
        if (config.sca_sync_logging)
        {
          if (g_capi->setDebugLevel(config.loglevel) == -1)
          {
            LOG(LEVEL_WARNING, "The loaded srx-crypto-api plug-in does not"
                    " support remote control of LOGING configuration - Use API"
                    " configuration to do so!");
          }
        }
      }
             
      if (!sca_INIT)
      {
        LOG(LEVEL_DEBUG, "[BGPSEC] SRxCryptoAPI not initialized (0x%X)!", 
                         sca_status);
        free(g_capi);
        g_capi = NULL;
      }
      else if ( !setupCaches() )
      {
        // Setup all necessary instances        
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

      if (g_capi != NULL)
      {
        // cleanup SCA
        if (g_capi->release(&sca_status) == API_FAILURE)
        {
          LOG(LEVEL_ERROR, "SRx Crypto API reported an error %i during release",
                            sca_status);
        }
        free(g_capi);
        g_capi = NULL;
      }      
      
      if (printGoodbye)
      {
        printf ("Goodbye!\n");
      }

      LOG(LEVEL_DEBUG, "([0x%08X]) < Stop Main SRx server thread.", 
                       pthread_self());
      if (fp)
      {
        fclose(fp);
      }
      break;
    default :
      // Should not have happened!
      break;
  }
  return exitCode;
}
