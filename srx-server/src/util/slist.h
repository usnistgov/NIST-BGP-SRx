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
 * A single-linked list.
 *
 * @note Not thread-safe!
 *
 * Usage example (w/o checking for errors):
 * @code
 * SList list;
 * MyStruct* sptr;
 * SListNode* newNode;
 *
 * initSList(&list);
 * sptr = appendToSList(&list, sizeof(MyStruct));
 * :
 * newNode = (SListNode*)insertIntoSList(&list, 0, 0);
 * setDataOfListNode(newNode, "Hello");
 * :
 * releaseSList(&list);
 * @endcode
 *
 * Uses log.h to report error messages
 * 
 * 
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 *            * Added Changelog
 * 0.1.0.0  - 2009/12/23 - pgleichm
 *            * Code created
 * 
 */
// @TODO: See if it can be replaced with antd-util list implementation
#ifndef __SLIST_H__
#define __SLIST_H__

#include <stdlib.h>
#include <stdbool.h>

/**
 * A single node.
 */
typedef struct _SListNode
{
  void*               data;       ///< Allocated memory block, or \c NULL
  size_t              allocSize;  ///< Size of \c data - 0 = managed outside
  struct _SListNode*  next;       ///< Pointer to the next node
} SListNode;

/**
 * A list.
 */
typedef struct
{
  SListNode* root; ///< The first node
  SListNode* last; ///< The last node - makes appending easier
  int        size; ///< Number of nodes
} SList;

/*----------------
 * Basic functions
 */

/**
 * Initializes a list.
 *
 * @param self Variable that should be initialized
 */
extern void initSList(SList* self);

/**
 * Releases the allocated memory blocks for each entry and its and nodes.
 *
 * @param self List instance
 */ 
extern void releaseSList(SList* self);

/**
 * Adds a new node to the end of the list and returns a pointer to the 
 * allocated memory block.
 *
 * @param self List instance
 * @param dataSize Number of Bytes that should be allocated. A \c 0 
 *      means that the actual data is managed outside of the list
 * @return Either the address of the allocated memory block (\c dataSize > 0), 
 *      a SListNode* (\c dataSize = 0), or \c NULL (\c dataSize > 0) in 
 *      case there was not enough memory
 * @see insertIntoSList
 */
extern void* appendToSList(SList* self, size_t dataSize);

/**
 * Adds a new node to the end of the list and lets the internal data pointer
 * point to the given \c data block.
 *
 * @param self List instance
 * @param data Data managed outside of the list
 * @return \c true = appended successfully, \c false = out of memory
 */
extern bool appendDataToSList(SList* self, void* data);

/**
 * Inserts a new node before the given index and returns a pointer to the
 * allocated memory block.
 *
 * @param self List instance
 * @param index Index (>= 0)
 * @param dataSize Number of Bytes that should be allocated. A \c 0 
 *      means that the actual data is managed outside of the list
 * @return Either the address of the allocated memory block (\c dataSize > 0), 
 *      a SListNode* (\c dataSize = 0), or \c NULL (\c dataSize > 0) in 
 *      case there was not enough memory or the index was out of bounds
 * @see appendToSList
 */
extern void* insertIntoSList(SList* self, int index, size_t dataSize);

/**
 * Inserts a new node before a given index and lets the internal data pointer
 * point to the given \c data block.
 *
 * @param self List instance
 * @param index INdex (>= 0)
 * @param data Data managed outside of the list
 * @return \c true = appended successfully, \c false = out of memory
 */
extern bool insertDataIntoSList(SList* self, int index, void* data);

/**
 * Removes a node from the list.
 *
 * @param self List instance
 * @param data The node with this memory block should be removed
 * @return \c true = successfully removed, \c false = not found
 */
extern bool deleteFromSList(SList* self, void* data);

/**
 * Removes all nodes from the list and frees up the memory used. This method is
 * equivalent to releaseList followed by initList.
 *
 * @param self List instance
 */
extern void emptySList(SList* self);

/**
 * Removes the first node and returns the memory block.
 *
 * @note The returned pointer needs to be free'd - unless it points to
 *       a data block that is managed outside of the list
 *
 * @param self List instance
 * @return Pointer, or \c NULL in case of an empty list
 */
extern void* shiftFromSList(SList* self);

/**
 * Returns the number of nodes.
 *
 * @param self List instance
 * @return Number of nodes (>= 0)
 */
extern int sizeOfSList(SList* self);

/**
 * Checks if a certain memory block is part of the list.
 *
 * @param self List instance
 * @param data Memory block to search for
 * @return \c true = exists, \c false = not found
 */
extern bool existsInSList(SList* self, void* data);


/**
 * Returns the memory block of a specific node.
 *
 * @param self List instance
 * @param index Node-index (>= 0)
 * @return Data pointer, or \c NULL if the index was out of bounds
 */
extern void* getFromSList(SList* self, int index);

/**
 * Goes over every node in the list.
 *
 * @param self List instance 
 * @param cbFunc Function that should be called for every node
 *
 * Example:
 * @code
 * void print(void* data) {
 *   printf("Node = %s\n", (const char*)data);
 * }
 * :
 * foreachInSList(list, print);
 * @endcode
 */
extern void foreachInSList(SList* self, void (*cbFunc)(void* data));

/*--------------------
 * SListNode functions
 */
    
extern SListNode* getNodeFromSList(SList* self, int index);

/**
 * Returns the root-node of a list.
 *
 * @param self List instance
 * @return Root or \c NULL (empty list)
 */
extern SListNode* getRootNodeOfSList(SList* self);

/**
 * Returns the last node of a list.
 *
 * @param self List instance
 * @return Last node or \c NULL (empty list)
 */
extern SListNode* getLastNodeOfSList(SList* self);

/**
 * Returns the node following a node.
 *
 * @param node Current node
 * @return Next node or \c NULL (\c = last node)
 */
extern SListNode* getNextNodeOfSListNode(SListNode* node);

/** 
 * Returns the data of a node.
 *
 * @param node Current node
 * @return Data or \c NULL if an invalid node
 */
extern void* getDataOfSListNode(SListNode* node); 

/**
 * Sets the data of a node.
 * If the previous data was allocated within the list it is free'd.
 *
 * @param node A Node
 * @param data Data
 */
extern void setDataOfSListNode(SListNode* node, void* data);


/**
 * Returns the size of the data of a node.
 *
 * @param node A node
 * @return Size, or \c 0 in case the data is managed outside of the list
 */
extern size_t getDataSizeOfSListNode(SListNode* node);

/**
 * Loops over a list putting the current node in a variable.
 *
 * @note Use getDataOfListNode to get the data
 * 
 * Example:
 * @code
 * SList      mylist;
 * SListNode* currNode;
 * void*      data;
 *
 * FOREACH_SLIST(&mylist, currNode) 
 * {
 *   data = getDataOfSListNode(currNode);
 * }
 * @endcode
 *
 * @param SLISTPTR SList* 
 * @param NODEPTR SListNode*
 */
#define FOREACH_SLIST(SLISTPTR, NODEPTR) \
  if (SLISTPTR != NULL) \
    for (NODEPTR = (SLISTPTR)->root; NODEPTR; NODEPTR = NODEPTR->next)

/*--------------------
 * Copying and moving
 */

/**
 * Duplicates a list.
 * If \c to is not empty, then the nodes are appended.
 *
 * @note Deep copy, i.e. allocated data is duplicated
 *
 * @param to Destination list
 * @param from Source list
 * @return First new node, or \c NULL = not enough memory
 */
SListNode* copySList(SList* to, SList* from);

/**
 * Copies a node unto the end of a list.
 *
 * @param to Destination list
 * @param node Node that should be copied
 * @return Created node, or \c NULL in case of an error
 */
SListNode* copySListNode(SList* to, SListNode* node);

/**
 * Moves all nodes from one list to another.
 * If \c to is not empty, then the nodes are appended.
 *
 * @param to Destination list
 * @param from Source list
 * @return First moved node
 */
SListNode* moveSList(SList* to, SList* from);

/**
 * Moves a single node to the end of a different list.
 *
 * @param to Destination list
 * @param from Source list
 * @param node Node that should be moved
 * @param prevNode Node before \c node or \c NULL (= first node)
 */
void moveSListNode(SList* to, SList* from, SListNode* node, 
                   SListNode* prevNode);

#endif // !__SLIST_H__

