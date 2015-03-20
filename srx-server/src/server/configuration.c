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
 * @version 0.3.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 *   0.3.0 - 3014/11/17 - oborchert
 *           * Modified the function signature of initConfiguration
 *           * Added mechanism to detect the location of the configuration file
 *             in case it is not specified.
 *         - 2013/02/19 - oborchert
 *           * Fixed parameter processing when version/full-version is requested
 *         - 2013/02/05 - oborchert
 *           * Fixed parameter processing when help is requested
 *         - 2013/01/28 - oborchert
 *           * Added experimental mode parameters
 *           * Added mapping configuration
 *   0.2.0 - 2011/11/01 - oborchert
 *           * Extended.
 *   0.1.0 - 2009/12/23 - pgleichm
 *           * Code Created
 * -----------------------------------------------------------------------------
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <libconfig.h>
#include "configuration.h"
#include "srx_server.h"  // For server name and version number
#include "shared/srx_packets.h" // For Protocol Version number
#include "util/log.h"
#include "util/prefix.h"
#include "shared/srx_defs.h"
#include "util/directory.h"

#define CFG_PARAM_CREDITS 1

#define CFG_PARAM_VERSION 2
#define CFG_PARAM_FULL_VERSION 3

#define CFG_PARAM_LOGLEVEL  4
#define CFG_PARAM_SYSLOG    5

#define CFG_PARAM_RPKI_HOST 6
#define CFG_PARAM_RPKI_PORT 7

#define CFG_PARAM_BGPSEC_HOST 8
#define CFG_PARAM_BGPSEC_PORT 9

#define CFG_PARAM_MODE_NO_SEND_QUEUE 10
#define CFG_PARAM_MODE_NO_RCV_QUEUE  11

#define HDR "([0x%08X] Configuration): "

#ifndef SYSCONFDIR
#define SYSCONFDIR               "/etc"
#endif // SYSCONFDIR

#define CFG_FILE_NAME           "srx_server.conf"
#define SYS_CFG_FILE SYSCONFDIR "/" CFG_FILE_NAME
#define LOC_CFG_FILE            "./" CFG_FILE_NAME

// Forward declaration
static bool _copyString(char** dest, char* var, const char* desc);

/** Supported short options */
static const char* _SHORT_OPTIONS = "hf:v:::sl:CkpcP::::::";

/** The commandline options (\c getopt_long format) */
static const struct option _LONG_OPTIONS[] = {
  { "help",         no_argument, NULL, 'h'},
  { "config",       required_argument, NULL, 'f'},
  
  { "credits",      no_argument, NULL, CFG_PARAM_CREDITS},  
  
  { "verbose",      no_argument, NULL, 'v'},
  
  { "version",      no_argument, NULL, CFG_PARAM_VERSION},
  { "full-version", no_argument, NULL, CFG_PARAM_FULL_VERSION},  
  { "loglevel",     required_argument, NULL, CFG_PARAM_LOGLEVEL},
  
  { "sync",         no_argument, NULL, 's'},
  { "log",          required_argument, NULL, 'l'},
  
  { "syslog",       no_argument, NULL, CFG_PARAM_SYSLOG},
  
  { "proxy-clients", required_argument, NULL, 'C'},
  { "keep-window", required_argument, NULL, 'k'},
  
  { "port",             required_argument, NULL, 'p'},
  { "console.port",     required_argument, NULL, 'c'},
  { "console.password", required_argument, NULL, 'P'},
  
  { "rpki.host",    required_argument, NULL, CFG_PARAM_RPKI_HOST},
  { "rpki.port",    required_argument, NULL, CFG_PARAM_RPKI_PORT},
  
  { "bgpsec.host",  required_argument, NULL, CFG_PARAM_BGPSEC_HOST},
  { "bgpsec.port",  required_argument, NULL, CFG_PARAM_BGPSEC_PORT},

  { "mode.no-sendqueue", no_argument, NULL, CFG_PARAM_MODE_NO_SEND_QUEUE},
  { "mode.no-receivequeue", no_argument, NULL, CFG_PARAM_MODE_NO_RCV_QUEUE},

  { NULL, 0, NULL, 0}
};

/** Commandline help text */
static const char* _USAGE_TEXT =
  "[--options|-hvlspcP]\n\n"
  "Options:\n"
  "  -h, --help                   Display this help and exit\n"
  "  -f, --file                   Specify a configuration file\n"
  "      --credits                Displays the developers information\n"
  "      --version                Displays the version number\n"
  "      --full-version           Displays the full version number\n"
  "  -v, --verbose                Enable verbode output\n"
  "      --loglevel               The log level for the verbose output\n"
  "                               (3)=ERROR, (4)=WANRING, (5)=NOTICE,\n"
  "                               (6)=INFO, (7)=DEBUG\n"
  "  -l, --log <file>             Write all messages to a file\n"
  "      --syslog                 Send all messages to syslog\n"
  "  -C  --proxy-clients          Minimum expected number of proxy clients\n"
  "  -s  --sync                   Send synchronization request each time a\n"
  "                               proxy connection is established!\n"
  "  -k  --keep-window <sec>      The default keepWindow in seconds. Zero "
  "                               deactivates this feature\n"
  "  -p, --port <no>              Use a different listening port (def.: 17900)\n"
  "  -c, --console.port <no>      Use a different console port (def.: 17901)\n"
  "  -P, --console.password <pwd> Password for remote shutdown\n"
  "      --rpki.host <name>       RPKI/Router protocol server host name\n"
  "      --rpki.port <no>         RPKI/Router protocol server port number\n"
  "      --bgpsec.host <name>     BGPSec/Router protocol server host name\n"
  "      --bgpsec.port <no>       BGPSec/Router protocol server port number\n\n"
  " Experimental Options:\n=====================\n"
  "      --mode.no-sendqueue      Disable send queue for immediate results.\n"
  "                               This is experimental.\n"
  "      --mode.no-receivequeue   Disable the receive queue. This queue allows"
  "\n                               to push the processing of packets into\n"
  "                                its own thread. This is experimental.\n"
;

/**
 * Initialize the configuration with default values
 * 
 * @param self the configuration instance
 * 
 * @param defaultConfigFile The default name of a configuration file.
 */
void initConfiguration(Configuration* self)
//void initConfiguration(Configuration* self, char* defaultConfigFile)
{
  //_copyString(&self->configFileName, defaultConfigFile, 
  //            "Configuration filename");
  self->configFileName = fileIsReadable(LOC_CFG_FILE) ? LOC_CFG_FILE 
                         : fileIsReadable(SYS_CFG_FILE) ? SYS_CFG_FILE : NULL;
  self->verbose  = false;
  self->loglevel = LEVEL_ERROR;
  self->syncAfterConnEstablished = false;
  self->msgDest = MSG_DEST_STDERR;
  self->msgDestFilename = NULL;
  
  self->server_port  = 17900;
  self->console_port = 17901;
  self->console_password = NULL;
  
  self->rpki_host = NULL;
  self->rpki_port = -1;
  
  self->bgpsec_host = NULL;
  self->bgpsec_port = -1;
  self->expectedProxies = 1;
  
  self->mode_no_sendqueue = false;
  self->mode_no_receivequeue = false;
  
  self->defaultKeepWindow = SRX_DEFAULT_KEEP_WINDOW; // from srx_defs.h 
  memset(self->mapping_routerID, 0, MAX_PROXY_MAPPINGS);
}

void releaseConfiguration(Configuration* self)
{
  LOG(LEVEL_DEBUG, HDR "Release configuration object", pthread_self());
  if (self != NULL)
  {
    if (self->msgDestFilename != NULL)
    {
      free(self->msgDestFilename);
    }
    if (self->rpki_host != NULL)
    {
      free(self->rpki_host);
    }
    if (self->bgpsec_host != NULL)
    {
      free(self->bgpsec_host);
    }
  }
  LOG(LEVEL_DEBUG, HDR "Configuration objects released", pthread_self());
}

static bool _copyString(char** dest, char* var, const char* desc)
{
  if (*dest != NULL)
  {
    free(*dest);
  }
  *dest = strdup(var);
  if (*dest == NULL)
  {
    RAISE_SYS_ERROR("Not enough memory for %s", desc);
    return false;
  }
  return true;
}

/**
 * Parse the given command line parameters. This function also is allowed to 
 * only parse for the specification of a configuration file. This is -f/--file
 * 
 * @param self The configuration object itself
 * @param argc The command line arguments.
 * @param argv The command line parameters.
 * @param onlyCfgFileName only parse for the configuration file.
 * 
 * @return 1 = successful, 0 = invalid parameters found, -1 exit silent (for 
 *         example -h)
 */
int parseProgramArgs(Configuration* self, int argc, const char** argv, 
                     bool onlyCfgFileName)
{
  int optc;
  int processed = 0; 
  
  optind = 0; // Reset
  // parameters that do not have "-" set are ignored in the while loop. we do
  // not allow parameters without "-"
  while ((optc = getopt_long(argc, (char* const*)argv, 
                             _SHORT_OPTIONS, _LONG_OPTIONS, NULL)) != -1)
  {
    // Process the first one
    processed++;
    // process possible argument
    if (optarg != NULL)
    {
      processed++;
    }
    
    if (onlyCfgFileName)
    {
      switch (optc)
      {
        case 'f': // The filename
        case 'h': // get help
        case CFG_PARAM_VERSION:      // --version
        case CFG_PARAM_FULL_VERSION: // --full-version
          break;
        default:
          optc = -1; 
      }
    }
    
    switch (optc)
    {
      case -1 : 
        // Skip because this is a parse for 'f', 'h', --version, --full-version 
        // only
        break;
      case 'f':
        if (optarg == NULL)
        {
          RAISE_ERROR("Name for configuration file is missing!");
          return 0;
        }
        _copyString(&self->configFileName, optarg, "Configuration filename");
        break;
      case 'v':
        self->verbose = true;
        break;
      case 's' :
        self->syncAfterConnEstablished = true;
        break;
      case 'C' :
        self->expectedProxies = (uint32_t)strtol(optarg, NULL, 10);
        break;
      case'k' :
        self->defaultKeepWindow = (uint16_t)strtol(optarg, NULL, 
                                                   SRX_DEFAULT_KEEP_WINDOW);
        break;
      case 'l':
        self->msgDest = MSG_DEST_FILENAME;
        if (optarg == NULL)
        {
          RAISE_ERROR("Log filename missing!");
          return 0;
        }
        if (!_copyString(&self->msgDestFilename, optarg, "Log filename"))
        {
          return 0;
        }
        break;
      case CFG_PARAM_LOGLEVEL:
        if (optarg == NULL)
        {
          RAISE_ERROR("Log level number missing!");
          return 0;
        }
        self->loglevel = strtol(optarg, NULL, 10);
        if ((self->loglevel < LEVEL_ERROR) || (self->loglevel > LEVEL_DEBUG))
        {
          RAISE_SYS_ERROR("Invalid log level ('%s')", optarg);
          return 0;
        }
        break;
      case CFG_PARAM_SYSLOG:
        self->msgDest = MSG_DEST_SYSLOG;
        break;
      case 'p':
        if (optarg == NULL)
        {
          RAISE_ERROR("Server port number missing!");
          return 0;
        }
        self->server_port = strtol(optarg, NULL, 10);
        if (self->server_port == 0)
        {
          RAISE_SYS_ERROR("Invalid server port number ('%s')", optarg);
          return 0;
        }
        break;
      case 'c':
        if (optarg == NULL)
        {
          RAISE_ERROR("Console port number missing!");
          return 0;
        }
        self->console_port = strtol(optarg, NULL, 10);
        if (self->console_port == 0)
        {
          RAISE_SYS_ERROR("Invalid SRx console port ('%s')", optarg);
          return 0;
        }
        break;                
      case 'P':
        if (optarg == NULL)
        {
          RAISE_ERROR("Console password missing!");
          return 0;
        }
        if (!_copyString(&self->console_password, optarg, 
                        "Console remote shutdown password"))
        {
          return 0;
        }
        break;
      case CFG_PARAM_RPKI_HOST:
        if (optarg == NULL)
        {
          RAISE_ERROR("Validation cache host name missing !");
          return 0;
        }
        if (!_copyString(&self->rpki_host, optarg, "Validation cache host "
                                                   "name"))
        {
          return 0;
        }
        break;
      case CFG_PARAM_RPKI_PORT:
        if (optarg == NULL)
        {
          RAISE_ERROR("Validation cache port number missing!");
          return 0;
        }
        self->rpki_port = strtol(optarg, NULL, 10);
        if (self->rpki_port == 0)
        {
          RAISE_SYS_ERROR("Invalid validation cache server port ('%s')",
                          optarg);
          return 0;
        }
        break;
      case CFG_PARAM_BGPSEC_HOST:
        if (optarg == NULL)
        {
          RAISE_ERROR("BGPSEC certificate cache host name missing!");
          return 0;
        }
        if (!_copyString(&self->bgpsec_host, optarg,
                         "BGPSec certificate cache host name"))
        {
          return 0;
        }
        break;
      case CFG_PARAM_BGPSEC_PORT:
        if (optarg == NULL)
        {
          RAISE_ERROR("BGPSEC certificate cache port number missing!");
          return 0;
        }
        self->bgpsec_port = strtol(optarg, NULL, 10);
        if (self->bgpsec_port == 0)
        {
          RAISE_SYS_ERROR("Invalid BGPSec certificate cache server port "
                          "(\'%s\')", optarg);
          return 0;
        }
        break;
      case CFG_PARAM_CREDITS:
        printf ("%s\n", SRX_CREDITS);
        printf("%s Version %s\n", SRX_SERVER_NAME, SRX_SERVER_VERSION);          
        return -1;
        break;
      case 'h':
        printf("Usage: %s %s", argv[0], _USAGE_TEXT);
        printf("%s proxy protocol version %i\n", SRX_SERVER_NAME, 
               SRX_PROTOCOL_VER);          
        return -1;
        break;
      case CFG_PARAM_VERSION:
        printf("%s Version %s\n", SRX_SERVER_NAME, SRX_SERVER_VERSION);      
        return -1;
        break;
      case CFG_PARAM_FULL_VERSION:
        printf("%s Version %s\n", SRX_SERVER_NAME, SRX_SERVER_FULL_VER);      
        return -1;
        break;
      case CFG_PARAM_MODE_NO_SEND_QUEUE:
        self->mode_no_sendqueue = true;
        printf("Turn off send queue!\n");      
        break;
      case CFG_PARAM_MODE_NO_RCV_QUEUE:
        self->mode_no_receivequeue = true;
        printf("Turn off receive queue!\n");      
        break;
      default:        
        RAISE_ERROR("Usage: %s %s", argv[0], _USAGE_TEXT);          
        return 0;
    }
  }

  // Processed is always one less than argc because the first parameter is the 
  // file name itself.
  if ((processed+1) != argc)
  {
    RAISE_ERROR("Usage: %s %s", argv[0], _USAGE_TEXT);
    return 0;
  }
  
  return 1;
}

bool readConfigFile(Configuration* self, const char* filename)
{
  bool ret = false; // By default something went wrong
  config_t cfg;
  config_setting_t* sett;
  const char* strtmp;
  bool useSyslog;
  int boolVal;

  // Initialize libconfig
  config_init(&cfg);

  // Try to parse the configuration file
  if (!config_read_file(&cfg, filename))
  {
    RAISE_ERROR("Unknown or invalid configuration file: %s (line %d) - %s",
                config_error_file(&cfg), config_error_line(&cfg),
                config_error_text(&cfg));
    goto free_config;
  }

  // Global & server settings
  (void)config_lookup_bool(&cfg, "verbose", (int*)&boolVal);
        self->verbose = (bool)boolVal;
  (void)config_lookup_int(&cfg, "port", &self->server_port);
  (void)config_lookup_bool(&cfg, "sync", (int*)&boolVal);
        self->syncAfterConnEstablished = (bool)boolVal;

  (void)config_lookup_int(&cfg, "keep-window", (int*)&self->defaultKeepWindow);  
  
  // Global - message destination
  (void)config_lookup_bool(&cfg, "syslog", (int*)&boolVal);
        useSyslog = (bool)boolVal;
  (void)config_lookup_int(&cfg, "loglevel", &self->loglevel);
  if (config_lookup_string(&cfg, "log", &strtmp) == CONFIG_TRUE)
  {
    if (useSyslog)
    {
      RAISE_ERROR("Conflicting 'log' and 'syslog' specified");
      goto free_config;
    }
    self->msgDest = MSG_DEST_FILENAME;
    if (!_copyString(&self->msgDestFilename, (char*)strtmp, "log. filename"))
    {
      goto free_config;
    }
  }
  else if (useSyslog)
  {
    self->msgDest = MSG_DEST_SYSLOG;
  }

  // Console
  sett = config_lookup(&cfg, "console");
  if (sett != NULL)
  {
    if (config_setting_lookup_string(sett, "password", &strtmp))
    {
      if (!_copyString(&self->console_password, (char*)strtmp,
                       "Console password"))
      {
        goto free_config;
      }
    }
    (void)config_setting_lookup_int(sett, "port", &self->console_port);
  }
  
  
  // RPKI
  sett = config_lookup(&cfg, "rpki");
  if (sett != NULL)
  {
    if (config_setting_lookup_string(sett, "host", &strtmp))
    {
      if (!_copyString(&self->rpki_host, (char*)strtmp,
                       "RPKI/Router host name"))
      {
        goto free_config;
      }
    }
    (void)config_setting_lookup_int(sett, "port", &self->rpki_port);
  }

  // BGPSec
  sett = config_lookup(&cfg, "bgpsec");
  if (sett != NULL)
  {
    if (config_setting_lookup_string(sett, "host", &strtmp))
    {
      if (!_copyString(&self->bgpsec_host, (char*)strtmp,
                       "BGPSec/Router host name"))
      {
        goto free_config;
      }
    }
    (void)config_setting_lookup_int(sett, "port", &self->bgpsec_port);
  }

  // Experimental
  sett = config_lookup(&cfg, "mode");
  if (sett != NULL)
  {
    (void)config_setting_lookup_bool(sett, "no-sendqueue", (int*)&boolVal);
          self->mode_no_sendqueue = (bool)boolVal;
    (void)config_setting_lookup_bool(sett, "no-receivequeue", (int*)&boolVal);
          self->mode_no_receivequeue - (bool)boolVal;
  }
  
  // mapping configuration
  sett = config_lookup(&cfg, "mapping");
  if (sett != NULL)
  {
    uint32_t routerID;
    char buff[256];
    int clientID = 0;
    
    for (clientID=1; clientID < MAX_PROXY_MAPPINGS; clientID++)
    {
      memset(buff, '\0', 256);
      sprintf(buff, "client_%d", clientID);
      if (config_setting_lookup_string(sett, buff, &strtmp))
      {
        routerID = IPtoInt(strtmp);
        self->mapping_routerID[clientID] = routerID;  
      }
    }
  }
  
  // No errors
  ret = true;

  // Release the config structure
  free_config:
  config_destroy(&cfg);

  return ret;
}

bool isCompleteConfiguration(Configuration* self)
{
#define ERROR_IF_TRUE(COND, FMT, ...) \
    if (COND) { \
      RAISE_ERROR(FMT, ## __VA_ARGS__); \
      return false; \
    }

  ERROR_IF_TRUE(self->msgDest == MSG_DEST_FILENAME
                && self->msgDestFilename == NULL,
                "Logfile not specified given!");
  ERROR_IF_TRUE(self->console_port <= 0,
                "Invalid console port '%d'!", self->console_port);
  ERROR_IF_TRUE(self->console_password == NULL,
                "Console password is not set!");
  ERROR_IF_TRUE(self->server_port <= 0,
                "Invalid server port '%d'!", self->server_port);
  ERROR_IF_TRUE(self->rpki_host == NULL,
                "Host name of validation cache is not set!");
  ERROR_IF_TRUE(self->rpki_port <= 0,
                "Port number of validation cache is not set or invalid!");
  ERROR_IF_TRUE(self->bgpsec_host == NULL,
                "Host name of BGPSec certificate cache is not set!");
  ERROR_IF_TRUE(self->bgpsec_port <= 0,
                "Port number of BGPSec certificate cache is not set or "
                "invalid!");
  ERROR_IF_TRUE(self->defaultKeepWindow <= 0,
                "The keep-window time can not be negative!");
  ERROR_IF_TRUE(self->defaultKeepWindow > 0xFFFF,
                "The keep-window time more than 65535 seconds!");

  return true;
}
