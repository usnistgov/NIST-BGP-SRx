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
 * This file contains the AS-Path Cache.
 *
 * Version 0.6.1.0
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.6.1.0 - 2021/08/27 - kyehwanl
 *           * Added additional error condition
 * 0.6.0.0 - 2021/03/31 - oborchert
 *           * Modified loops to be C99 compliant 
 *         - 2021/02/26 - kyehwanl
 *           * Created source
 */
#include <uthash.h>
#include <stdbool.h>
#include "server/aspath_cache.h"
#include "shared/crc32.h"
#include "util/log.h"

#define HDR "([0x%08X] AspathCache): "

typedef struct {

  UT_hash_handle    hh;            // The hash table where this entry is stored
  uint32_t          pathId;
  AC_PathListData   data;
  uint8_t           aspaResult;
  AS_TYPE           asType;
  AS_REL_DIR        asRelDir;
  uint16_t          afi;
  time_t            lastModified;
} PathListCacheTable;


//
// To let main call this function to generate UT hash
bool createAspathCache(AspathCache* self, ASPA_DBManager* aspaDBManager)
{
  LOG(LEVEL_INFO, FILE_LINE_INFO " AS path cache instance :%p", self);
  
  if (!createRWLock(&self->tableLock))
  {
    RAISE_ERROR("Unable to setup the hash table r/w lock");
    return false;
  }
  // By default keep the hashtable null, it will be initialized with the first
  // element that will be added.
  self->aspathCacheTable = NULL;
  self->aspaDBManager = aspaDBManager;
 
  return true;
}


void releaseAspathCache(AspathCache* self)
{

  if (self != NULL)
  {
    releaseRWLock(&self->tableLock);
    emptyAspathCache(self);
  }

}

void emptyAspathCache(AspathCache* self)
{
  acquireWriteLock(&self->tableLock);
  self->aspathCacheTable = NULL;
  unlockWriteLock(&self->tableLock);

}

static void add_AspathList (AspathCache *self, PathListCacheTable *cacheTable)
{

  acquireWriteLock(&self->tableLock);
  HASH_ADD (hh, *((PathListCacheTable**)&self->aspathCacheTable), pathId, sizeof(uint32_t), cacheTable);
  unlockWriteLock(&self->tableLock);

}

static bool find_AspathList (AspathCache* self, uint32_t pathId, PathListCacheTable **p_cacheTable)
{
  acquireReadLock(&self->tableLock);
  HASH_FIND(hh, (PathListCacheTable*)self->aspathCacheTable, &pathId, sizeof(uint32_t), (*p_cacheTable));
  unlockReadLock(&self->tableLock);

  return (*p_cacheTable != NULL);
}


static void del_AspathList (AspathCache* self, PathListCacheTable *cacheTable)
{
  acquireWriteLock(&self->tableLock);
  HASH_DEL (*((PathListCacheTable**)&self->aspathCacheTable), cacheTable);
  unlockWriteLock(&self->tableLock);
}


AS_PATH_LIST* newAspathListEntry (uint32_t length, uint32_t* pathData, uint32_t pathId, AS_TYPE asType, 
                                  AS_REL_DIR asRelDir, uint16_t afi, bool bBigEndian)
{
  if (!length)
  {
    LOG(LEVEL_ERROR, "Error with no length");
    return NULL;
  }

  AS_PATH_LIST* pAspathList; 
  pAspathList   = (AS_PATH_LIST*)calloc(1, sizeof(AS_PATH_LIST));
  pAspathList->pathID       = pathId;
  pAspathList->asPathLength = length;
  pAspathList->asPathList   = (uint32_t*)calloc(length, sizeof(uint32_t));
  pAspathList->asType       = asType;
  pAspathList->asRelDir     = asRelDir;
  pAspathList->afi          = bBigEndian ? ntohs(afi): afi;
  pAspathList->lastModified = 0;

  int idx;
  
  for (idx = 0; idx < length; idx++)
  {
    if(bBigEndian)
    {
      pAspathList->asPathList[idx] = ntohl(pathData[idx]);
    }
    else
    {
      pAspathList->asPathList[idx] = pathData[idx];
    }
  }

  return pAspathList;
}

void printAsPathList(AS_PATH_LIST* aspl)
{
  LOG(LEVEL_INFO, FILE_LINE_INFO " called ");
  if (aspl)
  {
    LOG(LEVEL_INFO, "\tpath ID             : 0x%08X" , aspl->pathID);
    LOG(LEVEL_INFO, "\tlength              : %d "   , aspl->asPathLength);
    LOG(LEVEL_INFO, "\tValidation Result   : %d "   , aspl->aspaValResult);
    LOG(LEVEL_INFO, "\tAS Path Type        : %d "   , aspl->asType);
    LOG(LEVEL_INFO, "\tAS Relationship dir : %d "   , aspl->asRelDir);
    LOG(LEVEL_INFO, "\tafi                 : %d "   , aspl->afi);

    if(aspl->asPathList)
    {
      int idx;
      for (idx = 0; idx < aspl->asPathLength; idx++)
      {
        LOG(LEVEL_INFO, "\tPath List[%d]: %d "   , idx, aspl->asPathList[idx]);
      }
    }
  }
  else
  {
    LOG(LEVEL_INFO, "\tNo path list");
  }
}


bool deleteAspathListEntry (AS_PATH_LIST* aspl)
{
  if (!aspl)
    return false;

  if (aspl->asPathList)
  {
    free(aspl->asPathList);
  }

  free(aspl);

  return true;
}


bool modifyAspaValidationResultToAspathCache(AspathCache *self, uint32_t pathId,
                      uint8_t modAspaResult, AS_PATH_LIST* pathlistEntry)
{
  bool retVal = true;
  PathListCacheTable *plCacheTable;

  if (!find_AspathList (self, pathId, &plCacheTable))
  {
    RAISE_SYS_ERROR("Does not exist in aspath list cache, can not modify it!");
    retVal = false;
  }
  else
  {
    if(modAspaResult != SRx_RESULT_DONOTUSE)
    {
      // access time updated
      plCacheTable->lastModified = pathlistEntry->lastModified;
      LOG(LEVEL_INFO, "AspathCache entry for path ID: 0x%08X - last modfied time update: %u", pathId, plCacheTable->lastModified);

      if(modAspaResult != plCacheTable->aspaResult)
      {
        plCacheTable->aspaResult   = modAspaResult;
        LOG(LEVEL_INFO, FILE_LINE_INFO " AS path cache data modified [pathID]:0x%08X [Value]: %d [Time]: %u", 
            pathId, modAspaResult, plCacheTable->lastModified);
      }
    }
  }
  return retVal;
}

int storeAspathList (AspathCache* self, SRxDefaultResult* srxRes, 
                      uint32_t pathId, AS_TYPE asType, AS_PATH_LIST* pathlistEntry)
{
  int retVal = 1; // by default report it worked

  if(!pathlistEntry)
  {
    LOG(LEVEL_ERROR, "path list entry doesn't exist!");
    return -1;
  }

  PathListCacheTable *plCacheTable;
  
  if (find_AspathList (self, pathId, &plCacheTable))
  {
    LOG(LEVEL_WARNING, "Attempt to store an update that already exists in as path cache!");
    retVal = 0;
  }
  else
  {
    plCacheTable = (PathListCacheTable*) calloc(1, sizeof(PathListCacheTable));
    plCacheTable->pathId       = pathId;
    plCacheTable->asType       = asType;
    plCacheTable->asRelDir     = pathlistEntry->asRelDir;
    plCacheTable->afi          = pathlistEntry->afi;
    plCacheTable->lastModified = pathlistEntry->lastModified;

    uint8_t length = pathlistEntry->asPathLength;
    plCacheTable->data.hops = length;

    // copy by value, NOT by reference.  Because path list Entry should be freed later
    //
    if ( length > 0 && pathlistEntry->asPathList)
    {
      int idx;
      plCacheTable->data.asPathList = (PATH_LIST*) calloc(length, sizeof(PATH_LIST));
      for (idx = 0; idx < length; idx++)
      {
        plCacheTable->data.asPathList[idx] = pathlistEntry->asPathList[idx];
      }
    }

    if (srxRes != NULL)
    {
      plCacheTable->aspaResult = srxRes->result.aspaResult;
    }

    add_AspathList(self, plCacheTable);
    LOG(LEVEL_INFO, FILE_LINE_INFO " performed to add PathList Entry into As Path Cache");

  }

  return retVal;
}


// delete function for calling del_AspathList to remove the cache data
//
bool deleteAspathCache(AspathCache* self, uint32_t pathId, AS_PATH_LIST* pathlistEntry)
{
  bool bRet= false;
  PathListCacheTable *plCacheTable;
  
  if (find_AspathList (self, pathId, &plCacheTable))
  {
    LOG(LEVEL_INFO, FILE_LINE_INFO " Deleting PathList Cache Entry");
    del_AspathList(self, plCacheTable);
    bRet = true;
  }
  else
  {
    LOG(LEVEL_WARNING, " Attempted to find from AS path cache, But not found");
  }
  return bRet;
}


// key : path id to find AS path cache record
// return: a new AS PATH LIST structure
//
AS_PATH_LIST* getAspathListFromAspathCache (AspathCache* self, uint32_t pathId, SRxResult* srxRes)
{
  if (!pathId)
  {
    LOG(LEVEL_ERROR, "Invalid path id");
    return NULL;
  }

  AS_PATH_LIST *aspl = NULL;
  PathListCacheTable *plCacheTable;
  
  if (find_AspathList (self, pathId, &plCacheTable))
  {
    aspl = (AS_PATH_LIST*)calloc(1, sizeof(AS_PATH_LIST));
    aspl->pathID        = plCacheTable->pathId;
    aspl->asPathLength  = plCacheTable->data.hops;
    aspl->aspaValResult = plCacheTable->aspaResult;
    aspl->asType        = plCacheTable->asType;
    aspl->asRelDir      = plCacheTable->asRelDir;
    aspl->afi           = plCacheTable->afi;
    aspl->lastModified  = plCacheTable->lastModified;

    uint8_t length     = plCacheTable->data.hops;
    aspl->asPathList   = (uint32_t*)calloc(length, sizeof(uint32_t));
    if ( length > 0 && plCacheTable->data.asPathList)
    {
      int idx;
      for (idx = 0; idx < length; idx++)
      {
        aspl->asPathList[idx] = plCacheTable->data.asPathList[idx];
      }
    }

    if (srxRes->aspaResult != aspl->aspaValResult)
      srxRes->aspaResult  = aspl->aspaValResult;
  }
  else
  {
    srxRes->aspaResult = SRx_RESULT_UNDEFINED;
  }

  return aspl;
}


uint32_t makePathId (uint8_t asPathLength, PATH_LIST* asPathList, AS_TYPE asType, bool bBigEndian)
{
  uint32_t pathId=0;
  char* strBuf = NULL;
  int idx;

  if (!asPathList)
  {
    LOG(LEVEL_ERROR, "as path list is NULL, making CRC failure");
    return 0;
  }

  int strSize = asPathLength * 4 *2 + 1 + 1;  //  Path length * 4 byte, *2: hex string, 1: AS type, 1: NULL
  strBuf = (char*)calloc(strSize, sizeof(char));
  if (!strBuf)
  {
    LOG(LEVEL_ERROR, "memory allocation error");
    return 0;
  }

  for (idx=0; idx < asPathLength; idx++)
  {
    if(bBigEndian)
      sprintf(strBuf + (idx*4*2), "%08X", ntohl(asPathList[idx]));
    else
      sprintf(strBuf + (idx*4*2), "%08X", asPathList[idx]);
  }
  sprintf(strBuf+strSize-2, "%X", asType);

  pathId = crc32((uint8_t*)strBuf, strSize);
  LOG(LEVEL_INFO, "PathID: %08X strings: %s", pathId, strBuf);

  if (strBuf)
  {
    free(strBuf);
  }

  return pathId;
}

void printPathListCacheTableEntry(PathListCacheTable *cacheEntry)
{
  if (cacheEntry)
  {
    printf( "\n");
    printf( " path ID           : 0x%08X\n" , cacheEntry->pathId);
    printf( " length (hops)     : %d\n"  , cacheEntry->data.hops);
    printf( " Validation Result : %d\n"  , cacheEntry->aspaResult);
    printf( " \t(0:valid, 2:Invalid, 3:Undefined 5:Unknown, 6:Unverifiable)\n");
    printf( " AS Path Type      : %d\n"  , cacheEntry->asType);

    if (cacheEntry->data.asPathList)
    {
      int idx;
      for(idx = 0; idx < cacheEntry->data.hops; idx++)
      {
        printf( " - Path List[%d]: %d \n", idx, cacheEntry->data.asPathList[idx]);
      }
      printf( "\n");
    }
    else
    {
      printf( " Path List: Doesn't exist \n");
    }
  }
  else
  {
    printf( " No Entry exist\n");
  }
}



uint8_t getCountAsPathCache(AspathCache *self)
{
  uint8_t numRecords = 0;

  acquireWriteLock(&self->tableLock);
  numRecords = HASH_COUNT((PathListCacheTable*)self->aspathCacheTable);
  unlockWriteLock(&self->tableLock);

  return numRecords;
}

int idSort(PathListCacheTable *a, PathListCacheTable *b) 
{
  return (a->pathId - b->pathId);
}

void sortByPathId(AspathCache *self)
{
  acquireWriteLock(&self->tableLock);
  HASH_SORT(*((PathListCacheTable**)&self->aspathCacheTable), idSort);
  unlockWriteLock(&self->tableLock);
}


void printAllAsPathCache(AspathCache *self)
{
  PathListCacheTable *currCacheTable, *tmp;

  //sortByPathId(self);

  acquireWriteLock(&self->tableLock);
  HASH_ITER(hh, (PathListCacheTable*)self->aspathCacheTable, currCacheTable, tmp) 
  {
    printPathListCacheTableEntry(currCacheTable);
  }
  unlockWriteLock(&self->tableLock);
}











