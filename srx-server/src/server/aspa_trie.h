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
 * This file contains the ASPA trie header information.
 *
 * Version 0.6.0.0
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.6.0.0  - 2021/02/26 - kyehwanl
 *          - Created source
 */
#ifndef __ASPA_TRIE_H__
#define __ASPA_TRIE_H__

#include <stdint.h>
#include "shared/srx_defs.h"
#include "server/configuration.h"
#include "util/mutex.h"
#include "util/rwlock.h"

// The number of children for each node
// We will construct a N-ary tree and make it a Trie
#define N 10

typedef struct {
  uint32_t customerAsn; 
  uint16_t providerAsCount;
  uint32_t *providerAsns;
  uint16_t afi;
} ASPA_Object;


typedef struct TrieNode TrieNode;
struct TrieNode {
    // The Trie Node Structure
    // Each node has N children, starting from the root
    // and a flag to check if it's a leaf node
    char data; // Storing for printing purposes only
    TrieNode* children[N];
    int is_leaf;
    void *userData;
    ASPA_Object *aspaObjects;
};

typedef struct {
  TrieNode*         tableRoot;
  uint32_t          countAspaObj;
  Configuration*    config;  // The system configuration
  RWLock            tableLock;
  int (*cbProcessEndOfData)(void* uCache, void* rpkiHandler, 
                            uint32_t uid, uint32_t pid, time_t ct);
} ASPA_DBManager;


static TrieNode* newAspaTrie(void);
static TrieNode* make_trienode(char data, char* userData, ASPA_Object* );
static void free_trienode(TrieNode* node);
TrieNode* insertAspaObj(ASPA_DBManager* self, char* word, char* userData, ASPA_Object* obj);
static int search_trie(TrieNode* root, char* word);
void print_trie(TrieNode* root);
bool initializeAspaDBManager(ASPA_DBManager* aspaDBManager, Configuration* config);
static void emptyAspaDB(ASPA_DBManager* self);
ASPA_Object* findAspaObject(ASPA_DBManager* self, char* word);
void print_search(TrieNode* root, char* word);
bool deleteASPAObject(ASPA_DBManager* self, ASPA_Object *obj);
ASPA_Object* newASPAObject(uint32_t cusAsn, uint16_t pAsCount, uint32_t* provAsns, uint16_t afi);
ASPA_ValidationResult ASPA_DB_lookup(ASPA_DBManager* self, uint32_t customerAsn, uint32_t providerAsn, uint8_t afi);
TrieNode* printAllLeafNode(TrieNode *node);
bool delete_TrieNode_AspaObj (ASPA_DBManager* self, char* word, ASPA_Object* obj);




#endif // __ASPA_TRIE_H__ 
