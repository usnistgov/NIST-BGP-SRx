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
 * AS-Path Cache.
 *
 * Version 0.6.0.0
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.6.0.0  - 2021/02/26 - kyehwanl
 *          - Created source
 */
#ifndef __ASPATH_CACHE_H__
#define __ASPATH_CACHE_H__ 

#include <stdio.h>
#include "server/configuration.h"
#include "shared/srx_defs.h"
#include "shared/srx_packets.h"
#include "util/mutex.h"
#include "util/rwlock.h"
#include "util/slist.h"
#include "server/update_cache.h"
#include "server/aspa_trie.h"

typedef uint32_t as_t;
typedef uint32_t PATH_LIST;

// AS Path List structure
typedef struct {
  uint32_t      pathID;
  uint8_t       asPathLength;
  PATH_LIST*    asPathList;
  uint8_t       aspaValResult;
  AS_TYPE       asType;
  AS_REL_DIR    asRelDir;
  uint16_t      afi;
  time_t        lastModified;
} AS_PATH_LIST;



typedef struct {
  uint16_t              hops;
  PATH_LIST*            asPathList;
} AC_PathListData;

// TODO: 


/**
 * A single Update Cache.
 */
typedef struct {  

  UpdateCache       *linkUpdateCache;
  void              *aspathCacheTable;
  RWLock            tableLock;
  ASPA_DBManager    *aspaDBManager;
} AspathCache;


bool createAspathCache(AspathCache* self, ASPA_DBManager* aspaDBManager);
void releaseAspathCache(AspathCache* self);
void emptyAspathCache(AspathCache* self);
AS_PATH_LIST* newAspathListEntry (uint32_t length, uint32_t* pathData, uint32_t pathId, 
                                  AS_TYPE asType, AS_REL_DIR asRelDir, uint16_t afi, bool bBigEndian);
int storeAspathList (AspathCache* self, SRxDefaultResult* defRes, uint32_t pathId, AS_TYPE, AS_PATH_LIST* pathlistEntry);
AS_PATH_LIST* getAspathListFromAspathCache (AspathCache* self, uint32_t pathId, SRxResult* srxRes);
void printAsPathList(AS_PATH_LIST* aspl);
uint32_t makePathId (uint8_t asPathLength, PATH_LIST* asPathList, AS_TYPE asType, bool bBigEndian);
bool modifyAspaValidationResultToAspathCache(AspathCache *self, uint32_t pathId,
                      uint8_t modAspaResult, AS_PATH_LIST* pathlistEntry);

bool deleteAspathListEntry (AS_PATH_LIST* aspl);
void printAllAsPathCache(AspathCache *self);










#endif // __ASPATH_CACHE_H__ 
