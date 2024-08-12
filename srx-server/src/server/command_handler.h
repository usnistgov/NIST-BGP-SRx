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
 * @version 0.6.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
  * 0.6.0.0  - 2021/03/30 - oborchert
 *            * Added missing version control. Also moved modifications labeled 
 *              as version 0.5.2.0 to 0.6.0.0 (0.5.2.0 was skipped)
 *          - 2021/02/26 - kyehwanl
 *            * Added AspathCache to CommandHandler structure.
 *            * Modified appropriate functions to include ASPA processing.
 *            * Added function validateASPA(...)
 *          - 2020/09/27 - oborchert
 *            * Synchronized the documentation of broadcastResult with the 
 *              the implementation ".c" file.
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 * 0.3.0    - 2013/01/28 - oborchert
 *            * Changed a log entry from INFO to WARNING
 *            * Added Version Control
 * 0.2.0    - 2011/11/01 - oborchert
 *            * Rewritten
 * 0.1.0    - 2012/05/15 - pgleichm
 *            * Code Created.
 */
#ifndef __COMMAND_HANDLER_H__
#define __COMMAND_HANDLER_H__

#include "server/bgpsec_handler.h"
#include "server/configuration.h"
#include "server/command_queue.h"
#include "server/rpki_handler.h"
#include "server/server_connection_handler.h"
#include "server/update_cache.h"
#include "server/aspath_cache.h"
#include "shared/srx_packets.h"
#include "util/packet.h"
#include "util/server_socket.h"

/**
 * Number of parallel threads.
 */
#define NUM_COMMAND_HANDLER_THREADS 1
// #define NUM_COMMAND_HANDLER_THREADS 2

/**
 * A single Command Handler.
 */
typedef struct {
  // Arguments (create)
  ServerConnectionHandler*  svrConnHandler;
  BGPSecHandler*            bgpsecHandler;
  RPKIHandler*              rpkiHandler;
  UpdateCache*              updCache;
  AspathCache*              aspathCache;

  // The system configuration.
  Configuration*            sysConfig;

  // Argument (start)
  CommandQueue*             queue;

  // Internal
  pthread_t                 threads[NUM_COMMAND_HANDLER_THREADS];
  int                       numThreads;
#ifdef USE_GRPC
  bool                      grpcEnable;
#endif
} CommandHandler;

/**
 * Registers a BGPSec Handler, RPKI Handler and Update Cache.
 *
 * @param self Variable that should be initialized
 * @param cfg The system configuration.
 * @param bgpsecHandler Existing BGPSec Handler instance
 * @param rpkiHandler Existing RPKI Handler instance
 * @param updCache Existing Update Cache instance
 * 
 * @return true if the command handler was initialized successful
 */
bool initializeCommandHandler(CommandHandler* self, Configuration* cfg,
                              ServerConnectionHandler* svrConnHandler,
                              BGPSecHandler* bgpsecHandler, 
                              RPKIHandler* rpkiHandler, UpdateCache* updCache,
                              AspathCache* aspathCache);

/**
 * Frees all allocated resources.
 *
 * @param self Instance
 */
void releaseCommandHandler(CommandHandler* self);

/**
 * Handles all commands in the given queue.
 * 
 * @note Spawns a threads, i.e. is non-blocking
 *
 * @param self Instance
 * @param cmdQueue An existing Command Queue
 * @return \c true Waiting for commands, or \c false Failed to spawn threads
 */
bool startProcessingCommands(CommandHandler* self, CommandQueue* cmdQueue);

/**
 * Stops handling the commands found in the queue.
 *
 * @note Terminates all threads
 *
 * @param self Instance
 */
void stopProcessingCommands(CommandHandler* self);

/**
 * Sends a (new) result to all connected clients of the provided update.
 * The UpdateID is embedded in the SRxValidationResult data.
 *
 * @param self Instance
 * @param valResult The validation result including the UpdateID the result
 *                  is for.
 * @return true if at least one broadcast could be successfully send to any
 *              registered client
 */
bool broadcastResult(CommandHandler* self, SRxValidationResult* valResult);
bool _isSet(uint32_t bitmask, uint32_t bits);


/**
 * This function performs the ASPA validation.
 * 
 * @param asPathList
 * @param length
 * @param asType
 * @param direction
 * @param afi
 * @param aspaDBManager
 * 
 * @return the ASPA validation result
 * 
 * @since 0.6.0.0
 */
uint8_t validateASPA (PATH_LIST* asPathList, uint8_t length, AS_TYPE asType, 
                      AS_REL_DIR direction, uint8_t afi, 
                      ASPA_DBManager* aspaDBManager);
#endif // !__COMMAND_HANDLER_H__

