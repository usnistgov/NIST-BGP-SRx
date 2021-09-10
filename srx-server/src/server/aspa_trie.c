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
 * This file contains the ASPA trie.
 *
 * Version 0.6.0.0
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.6.0.0 - 2021/03/31 - oborchert
 *           * Modified loops to be C99 compliant 
 *         - 2021/02/26 - kyehwanl
 *           * Created source
 */
#include <stdio.h> /* printf */
#include <stdlib.h> /* exit */
#include <string.h>
#include <stdbool.h>
#include "server/aspa_trie.h"
#include "server/update_cache.h"
#include "server/rpki_handler.h"
#include "server/rpki_queue.h"
#include "util/log.h"

static uint32_t countTrieNode =0;
int process_ASPA_EndOfData_main(void* uc, void* handler, uint32_t uid, uint32_t pid, time_t ct);
extern RPKI_QUEUE* getRPKIQueue();
extern uint8_t validateASPA (PATH_LIST* asPathList, uint8_t length, AS_TYPE asType, 
                    AS_REL_DIR direction, uint8_t afi, ASPA_DBManager* aspaDBManager);

// API for initialization
//
bool initializeAspaDBManager(ASPA_DBManager* aspaDBManager, Configuration* config) 
{
   aspaDBManager->tableRoot = newAspaTrie();
   aspaDBManager->countAspaObj = 0;
   aspaDBManager->config = config;
   aspaDBManager->cbProcessEndOfData = process_ASPA_EndOfData_main;
  
   if (!createRWLock(&aspaDBManager->tableLock))
   {
     RAISE_ERROR("Unable to setup the aspa object db r/w lock");
     return false;
   }

  return true;
}

// delete all db
//
static void emptyAspaDB(ASPA_DBManager* self)
{
  acquireWriteLock(&self->tableLock);
  free_trienode(self->tableRoot);
  self->tableRoot = NULL;
  self->countAspaObj = 0;
  unlockWriteLock(&self->tableLock);
}


// external api for release db
//
void releaseAspaDBManager(ASPA_DBManager* self)
{
  if (self != NULL)
  {
    releaseRWLock(&self->tableLock);
    emptyAspaDB(self);
  }
}


// generate trie node
//
static TrieNode* newAspaTrie(void) 
{
  TrieNode *rootNode = make_trienode('\0', NULL, NULL);
  return rootNode;
}


// external api for creating db object
//
ASPA_Object* newASPAObject(uint32_t cusAsn, uint16_t pAsCount, uint32_t* provAsns, uint16_t afi)
{
  ASPA_Object *obj = (ASPA_Object*)calloc(1, sizeof(ASPA_Object));
  // Index variable for loops
  int idx = 0;
  
  obj->customerAsn = cusAsn;
  obj->providerAsCount = pAsCount;
  obj->providerAsns = (uint32_t*) calloc(pAsCount, sizeof(uint32_t));
  
  if (obj->providerAsns && provAsns)
  {
    for(idx = 0; idx < pAsCount; idx++)
    {
      obj->providerAsns[idx] = provAsns[idx];
    }
  }
  obj->afi = afi;

  return obj;

}

// delete aspa object
//
bool deleteASPAObject(ASPA_DBManager* self, ASPA_Object *obj)
{
  if(obj)
  {
    if (obj->providerAsns)
    {
      free(obj->providerAsns);
    }
    free (obj);
    self->countAspaObj--;
    return true;
  }
  return false;
}


// create trie node
//
static TrieNode* make_trienode(char data, char* userData, ASPA_Object* obj) 
{
  // Index for loops
  int idx = 0;
  
  // Allocate memory for a TrieNode
  TrieNode* node = (TrieNode*) calloc (1, sizeof(TrieNode));
  if (!node)
  {
    return NULL;
  }

  for (idx = 0; idx < N; idx++)
      node->children[idx] = NULL;
  
  node->is_leaf = 0;
  node->data = data;
  node->userData = NULL;
  node->aspaObjects = NULL;
  
  return node;
}

// free node
static void free_trienode(TrieNode* node) 
{
  // Free the trienode sequence
  int idx = 0;
  for(idx = 0; idx < N; idx++) 
  {
    if (node->children[idx] != NULL) 
    {
      free_trienode(node->children[idx]);
    }
    else 
    {
      continue;
    }
  }
  free(node);
}

bool compareAspaObject(ASPA_Object *obj1, ASPA_Object *obj2)
{
  if (!obj1 || !obj2)
    return false;

  if (obj1->customerAsn != obj2->customerAsn)
    return false;

  if (obj1->providerAsCount != obj2->providerAsCount)
    return false;

  if (obj1->afi != obj2->afi)
    return false;

  int idx;
  
  for (idx = 0; idx < obj1->providerAsCount; idx++)
  {
    if(obj1->providerAsns[idx] != obj2->providerAsns[idx])
      return false;
  }
  return true;
}



bool delete_TrieNode_AspaObj (ASPA_DBManager* self, char* word, ASPA_Object* obj)
{
  bool bRet = false;
  int idx = 0;

  acquireWriteLock(&self->tableLock);
  TrieNode* temp = self->tableRoot; 
  TrieNode* parent = NULL;
  int position = 0;

  // finding
  for(idx = 0; word[idx] != '\0'; idx++)
  {
    position = word[idx] - '0';
    if (temp->children[position] == NULL)
    {
      temp = NULL;
      break;
    }
    parent = temp;
    temp = temp->children[position];
  }

  // info compare
  if (temp && temp->is_leaf == 1 && temp->aspaObjects 
      && compareAspaObject(temp->aspaObjects, obj))
  {
    deleteASPAObject(self, temp->aspaObjects);
    free_trienode(temp);
    temp = NULL;
    parent->children[position] = NULL;
    bRet = true;
  }

  unlockWriteLock(&self->tableLock);

  return bRet;
}

//  new value insert or substitution according to draft
//
TrieNode* insertAspaObj (ASPA_DBManager* self, char* word, char* userData, 
                         ASPA_Object* obj) 
{
  TrieNode* temp = self->tableRoot; // start with root node
  acquireWriteLock(&self->tableLock);
  int i;
  
  for (i=0; word[i] != '\0'; i++) 
  {
    int idx = (int) word[i] - '0';
    //printf("index: %02x(%d), word[%d]: %c  \n", idx, idx, i, word[i]);
    if (temp->children[idx] == NULL) {
        // If the corresponding child doesn't exist, simply create that child!
        temp->children[idx] = make_trienode(word[i], userData, obj);
    }
    else {
        // Do nothing. The node already exists
    }
    // Go down a level, to the child referenced by idx
    temp = temp->children[idx];
  }

  if (temp)
  {
    // At the end of the word, mark this node as the leaf node
    temp->is_leaf = 1;
    temp->userData =  userData;

    // substitution if exist
    if (temp->aspaObjects && temp->aspaObjects != obj)
    {
      deleteASPAObject(self, temp->aspaObjects);
      countTrieNode--;
    }
    temp->aspaObjects = obj;
    countTrieNode++;
    self->countAspaObj++;
  }

  unlockWriteLock(&self->tableLock);

  return temp;
}

// get total count
//
uint32_t getCountTrieNode(void)
{
  return countTrieNode;
}

// search method
//
static int search_trie(TrieNode* root, char* word)
{
    // Searches for word in the Trie
    TrieNode* temp = root;
    int i=0;
    for(i=0; word[i]!='\0'; i++)
    {
        int position = word[i] - '0';
        if (temp->children[position] == NULL)
            return 0;
        temp = temp->children[position];
    }
    if (temp != NULL && temp->is_leaf == 1)
        return 1;
    return 0;
}

// external api for searching trie
//
ASPA_Object* findAspaObject(ASPA_DBManager* self, char* word)
{
    ASPA_Object *obj;
  
    acquireWriteLock(&self->tableLock);
    TrieNode* temp = self->tableRoot; 

    int i;
    for(i=0; word[i]!='\0'; i++)
    {
        int position = word[i] - '0';
        if (temp->children[position] == NULL)
        {
          obj = NULL;
          temp = NULL;
          break;
        }
        temp = temp->children[position];
    }

    if (temp != NULL && temp->is_leaf == 1)
    {
        obj = temp->aspaObjects;
    }
    unlockWriteLock(&self->tableLock);

    return obj;
}

//
//  print all nodes
//
TrieNode* printAllLeafNode(TrieNode *node)
{
  TrieNode* leaf = NULL;
  uint8_t count=0;

  if (node->is_leaf == 1)
  {
    leaf = node;
    return leaf;
  }

  int childIdx;
  for (childIdx = 0; childIdx < N; childIdx++) 
  {
    if(node->children[childIdx])
    {
      leaf = printAllLeafNode(node->children[childIdx]);
      if (leaf)
      {
        //printf("++ count: %d i:%d digit: %c user data: %s\n", ++count, i, leaf->data, leaf->userData);
        printf("\n++ count: %d, user data: %s, ASPA object:%p \n", 
            ++count, leaf->userData, leaf->aspaObjects);

        ASPA_Object *obj = leaf->aspaObjects;
        if (obj)
        {
          printf("++ customer ASN: %d\n", obj->customerAsn);
          printf("++ providerAsCount : %d\n", obj->providerAsCount);
          printf("++ Address: provider asns : %p\n", obj->providerAsns);
          if (obj->providerAsns)
          {
            int pIdx;
            for(pIdx = 0; pIdx < obj->providerAsCount; pIdx++)
              printf("++ providerAsns[%d]: %d\n", pIdx, obj->providerAsns[pIdx]);
          }
          printf("++ afi: %d\n", obj->afi);
        }
      }
    }
  }

  return NULL;
}



void print_trie(TrieNode* root) {/*{{{*/
    // Prints the nodes of the trie
    if (!root)
        return;
    TrieNode* temp = root;
    printf("%c -> ", temp->data);
    int i=0;
    for (i=0; i<N; i++) {
        print_trie(temp->children[i]);
    }
}

void print_search(TrieNode* root, char* word) {
    printf("Searching for %s: ", word);
    if (search_trie(root, word) == 0)
        printf("Not Found\n");
    else
        printf("Found!\n");
}/*}}}*/

// 
// external API for db loopkup
//
ASPA_ValidationResult ASPA_DB_lookup(ASPA_DBManager* self, uint32_t customerAsn, 
                                     uint32_t providerAsn, uint8_t afi )
{
  LOG(LEVEL_DEBUG, FILE_LINE_INFO " ASPA DB Lookup called");

  char strCusAsn[6] = {};
  sprintf(strCusAsn, "%d", customerAsn);  

  ASPA_Object *obj = findAspaObject(self, strCusAsn);

  if (!obj) // if there is no object item
  {
    LOG(LEVEL_INFO, "[db] No customer ASN exist -- Unknown");
    return ASPA_RESULT_UNKNOWN;
  }
  else // found object
  {
    LOG(LEVEL_INFO, "[db] customer ASN: %d", obj->customerAsn);
    LOG(LEVEL_INFO, "[db] providerAsCount : %d", obj->providerAsCount);
    LOG(LEVEL_INFO, "[db] Address: provider asns : %p", obj->providerAsns);
    LOG(LEVEL_INFO, "[db] afi: %d", obj->afi);

    if (obj->providerAsns)
    {
      int idx = 0;
      
      for (idx = 0; idx < obj->providerAsCount; idx++)
      {
        LOG(LEVEL_INFO, "[db] providerAsns[%d]: %d", idx, 
                        obj->providerAsns[idx]);
        if (obj->providerAsns[idx] == providerAsn && obj->afi == afi)
        {
          LOG(LEVEL_INFO, "[db] Matched -- Valid");
          return ASPA_RESULT_VALID;
        }
      }
  
      LOG(LEVEL_INFO, "[db] No Matched -- Invalid");
      return ASPA_RESULT_INVALID;
    }
  }
  return ASPA_RESULT_UNDEFINED;

}

int process_ASPA_EndOfData_main(void* uc, void* handler, uint32_t uid, 
                                uint32_t pid, time_t ct)
{
  SRxResult        srxRes;
  SRxDefaultResult defaultRes;
  time_t lastEndOfDataTime = ct;

  UpdateCache*  uCache      = (UpdateCache*)uc;
  SRxUpdateID   updateID    = (SRxUpdateID) uid;
  uint32_t      pathId      = 0;
  RPKIHandler*  rpkiHandler = (RPKIHandler*)handler;

  LOG(LEVEL_INFO, "=== main process_main_ASPA_EndOfData UpdateCache:%p rpkiHandler:%p ctime:%u", 
      (UpdateCache*)uCache, (RPKIHandler*)rpkiHandler, ct);


  if (!getUpdateResult(uCache, &updateID, 0, NULL, &srxRes, &defaultRes, &pathId))
  {
    LOG(LEVEL_WARNING, "Update ID: 0x%08X not found ", updateID);
    return 0;
  }
  else
  {
    if (defaultRes.result.aspaResult != SRx_RESULT_INVALID)
    {
      ASPA_DBManager* aspaDBManager = rpkiHandler->aspaDBManager;
      TrieNode *root = aspaDBManager->tableRoot;

      LOG(LEVEL_INFO, "Update ID: 0x%08X  Path ID: 0x%08X", updateID, pathId);

      uint8_t old_aspaResult = srxRes.aspaResult; // obtained from getUpdateResult above
      AS_PATH_LIST *aspl = getAspathListFromAspathCache (rpkiHandler->aspathCache, pathId, &srxRes);

      if (aspl)
      {
        uint8_t afi = aspl->afi;  
        if (aspl->afi == 0 || aspl->afi > 2) // if more than 2 (AFI_IP6)
          afi = AFI_IP;                      // set default

            
        LOG(LEVEL_INFO, "Comparison End of Data time(%u) : AS cache entry updated time (%u)",
            lastEndOfDataTime, aspl->lastModified);
        // timestamp comparison
        //
        if (lastEndOfDataTime > aspl->lastModified)
        {
          // call ASPA validation
          //
          uint8_t valResult = validateASPA (aspl->asPathList, 
              aspl->asPathLength, aspl->asType, aspl->asRelDir, afi, aspaDBManager);

          LOG(LEVEL_INFO, FILE_LINE_INFO "\033[92m"" Validation Result: %d "
              "(0:v, 2:Iv, 3:Ud 4:DNU 5:Uk, 6:Uf)""\033[0m", valResult);

          // update the last validation time regardless of changed or not
          time_t cTime = time(NULL);
          aspl->lastModified = cTime;

          // modify Aspath Cache with the validation result
          modifyAspaValidationResultToAspathCache (rpkiHandler->aspathCache, pathId, valResult, aspl);

          // modify UpdateCache data and enqueue as well
          if (valResult != aspl->aspaValResult)
          {
            aspl->aspaValResult = valResult;
            srxRes.aspaResult = valResult;

            // UpdateCache change
            modifyUpdateCacheResultWithAspaVal(uCache, &updateID, &srxRes);

            // if different values, queuing
            RPKI_QUEUE*      rQueue = getRPKIQueue();
            rq_queue(rQueue, RQ_ASPA, &updateID);
            LOG(LEVEL_INFO, "rpki queuing for aspa validation [uID:0x%08X]", updateID);
          }
        }
        //
        // in case there is another update cache entry whose path id is same with the previous
        // This prevents from doing ASPA validation repeatedly with the same AS path list
        //
        else /* if else time comparison */
        {
          // update cache entry with the new value 
          if (old_aspaResult != aspl->aspaValResult)
          {
            LOG(LEVEL_INFO, FILE_LINE_INFO " ASPA validation result already set and "
                " the existed validation result [%d] in UpdateCache is being updated with a new result[%d]", 
                old_aspaResult, aspl->aspaValResult);
            srxRes.aspaResult = aspl->aspaValResult;

            // modify UpdateCache data as well
            modifyUpdateCacheResultWithAspaVal(uCache, &updateID, &srxRes);

            // if different values, queuing
            RPKI_QUEUE*      rQueue = getRPKIQueue();
            rq_queue(rQueue, RQ_ASPA, &updateID);
            LOG(LEVEL_INFO, "rpki queuing for aspa validation [uID:0x%08X]", updateID);
          }
        }

      }
      else /* no aspath list */
      {
        LOG(LEVEL_WARNING, "Update 0x%08X is registered for ASPA but the "
            "AS Path List is not found!", updateID);
      } // end of if aspl

      if (aspl)
        free (aspl);

    } // end of if defaultRes result
    else 
    {
      LOG(LEVEL_ERROR, "Update 0x%08X is not capable to do ASPA validation",
          updateID);
      return 0;
    }
  }// end of else


  return 1;
}
