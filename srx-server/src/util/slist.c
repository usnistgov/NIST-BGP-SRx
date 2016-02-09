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
 *
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Added Changelog
 *            * Fixed speller in documentation header
 * 0.1.0    - 2009/12/23 -pgleichm
 *            * Code created. 
 */
#include "util/slist.h"
#include "util/log.h"

void initSList(SList* self)
{
  self->root = NULL;
  self->size = 0;
}

/**
 * Releases the allocated memory blocks for each entry and its and nodes.
 *
 * @param self List instance
 */ 
void releaseSList(SList* self)
{
  if (self->size > 0)
  {
    SListNode* nextNode = self->root, *currNode;
    while (nextNode != NULL)
    {
      currNode = nextNode;
      nextNode = currNode->next;

      if (currNode->allocSize > 0)
      {
        free(currNode->data);
      }
      free(currNode);
    }
  }
}

inline int sizeOfSList(SList* self)
{
  return self->size;
}

inline void* appendToSList(SList* self, size_t dataSize)
{
  return insertIntoSList(self, self->size, dataSize);
}

inline bool appendDataToSList(SList* self, void* data)
{
  return insertDataIntoSList(self, self->size, data);
}

void* insertIntoSList(SList* self, int index, size_t dataSize)
{
  // Out of boundaries (size + 1)
  if (index > self->size)
  {
    RAISE_ERROR("Out of boundaries (size=%d, index=%d)", self->size, index);
    return NULL;
  }

  // Create a node
  SListNode* newNode = (SListNode*)malloc(sizeof(SListNode));
  if (newNode == NULL)
  {
    RAISE_ERROR("Not enough memory for a new list node");
    return NULL;
  }

  // Allocate the data storage 
  if (dataSize > 0)
  {
    newNode->data = malloc(dataSize);
    if (newNode->data == NULL)
    {
      RAISE_ERROR("Not enough memory for the data");
      free(newNode);
      return NULL;
    }
    newNode->allocSize = dataSize; 
 
  // The user wants to set his own data pointer
  } 
  else
  {
    newNode->data      = NULL;
    newNode->allocSize = 0;
  }
  
  // Make it the new root
  if (index == 0)
  {
    // The list is empty - make it the last node as well
    if (self->root == NULL)
    {
      self->last = newNode;  
    }

    newNode->next = self->root;
    self->root = newNode;

  // Append it as last-node
  } 
  else if (index == self->size) //  SUSPICIOUS PART --KH--  SEE also ./server/command_queue.c:162
  {
    self->last->next = newNode;  //<MUST use this (KH)> newNode->next = self->last->next; 
    self->last = newNode;
    newNode->next = NULL;
  // Go over the list
  } 
  else
  {
    // We need to find the index, i.e. the prev. node
    SListNode* prevNode = self->root;
    for (index--; index > 0; index--)
    {
      prevNode = prevNode->next;
    }

    newNode->next = prevNode->next;
    prevNode->next = newNode;
  }

  // One more
  self->size++;

  return (newNode->allocSize > 0) ? newNode->data : newNode;
}

bool insertDataIntoSList(SList* self, int index, void* data)
{
  SListNode* newNode = insertIntoSList(self, index, 0);
  if (newNode != NULL)
  {
    newNode->data = data;
    return true;
  }
  return false;
}

bool deleteFromSList(SList* self, void* data) // SUSPICIOUS --KH--
{
  if (self->size > 0)
  {
    SListNode* currNode = self->root, *prevNode = NULL;

    while (currNode != NULL)
    {
      // Found the corresponding node
      if (currNode->data == data)
      {
        // Entry in the middle/end
        if (prevNode != NULL)
        {
          prevNode->next = currNode->next;

          // We deleted the last node
          if (currNode->next == NULL)
          {
            self->last = prevNode;
          }
        // New root
        } 
        else
        {
          self->root = currNode->next;
        }
        free(currNode);
        self->size--;
        return true;
      }

      prevNode = currNode;
      currNode = currNode->next;
    }
  }
  return false;
}

/**
 * Removes all nodes from the list and frees up the memory used. This method is
 * equivalent to releaseList followed by initList.
 *
 * @param self List instance
 */
void emptySList(SList* self)
{
  releaseSList(self);
  initSList(self);
}

void* shiftFromSList(SList* self)
{
  SListNode*  firstNode;
  void*       data;

  // Empty list
  if (self->size == 0)
  {
    return NULL;
  }

  // Relink
  firstNode = self->root;
  self->root = firstNode->next;

  // Release the node - but not the data
  data = firstNode->data;
  free(firstNode);
  self->size--;
  return data;
}

bool existsInSList(SList* self, void* data)
{
  if (self->size > 0)
  {
    SListNode* node;
  
    FOREACH_SLIST(self, node)
    {
      if (node->data == data)
      {
        return true;
      }
    }
  }
  return false;
}

void* getFromSList(SList* self, int index)
{
  SListNode* node = getNodeFromSList(self, index);

  return (node == NULL) ? NULL : node->data;
}

void foreachInSList(SList* self, void (*cbFunc)(void* data))
{
  SListNode* currNode;

  if ((self->size > 0) && (cbFunc != NULL))
  {
    for (currNode = self->root; currNode != NULL; currNode = currNode->next)
    {
      cbFunc(currNode->data);
    }
  }
}

SListNode* getNodeFromSList(SList* self, int index)
{
  SListNode* currNode;

  if (index >= self->size)
  {
    RAISE_ERROR("Out of boundaries (%d > %d)", index, self->size - 1);
    return NULL;
  }

  for (currNode = self->root; index > 0; index--)
  {
    currNode = currNode->next;
  }
  return currNode;
}

inline SListNode* getRootNodeOfSList(SList* self)
{
  return (self == NULL) ? NULL : self->root;
}

inline SListNode* getLastNodeOfSList(SList* self)
{
  return (self == NULL) ? NULL : self->last;
}

inline SListNode* getNextNodeOfSListNode(SListNode* node)
{
  return (node == NULL) ? NULL : node->next;
}

inline void* getDataOfSListNode(SListNode* node)
{
  return (node == NULL) ? NULL : node->data;
}

void setDataOfSListNode(SListNode* node, void* data)
{
  if (node->allocSize > 0)
  {
    free(node->data);
  }
  node->allocSize = 0;
  node->data = data;
}

inline size_t getDataSizeOfSListNode(SListNode* node)
{
  return (node == NULL) ? 0 : node->allocSize;
}

/**
 * Copy data - if allocated, otherwise just set the data pointer
 */
static bool copyNodeData(SListNode* toNode, SListNode* fromNode)
{
  if (fromNode->allocSize > 0)
  {
    toNode->data = malloc(fromNode->allocSize);
    if (toNode->data == NULL)
    {
      RAISE_SYS_ERROR("Not enough memory to copy the node's data");
      return false;
    }

    memcpy(toNode->data, fromNode->data, fromNode->allocSize);
    toNode->allocSize = fromNode->allocSize;
  } 
  else
  {
    toNode->allocSize = 0;
    toNode->data      = fromNode->data;
  }

  return true;
}

SListNode* copySList(SList* to, SList* from)
{
  SListNode* end;
  SListNode* currFromNode, *prevToNode;
  SListNode* newNode;

  // Nothing to copy
  if (from->size == 0)
  {
    return NULL;
  }
 
  // Copying to an empty list
  if (to->size == 0)
  {
    end = NULL;

    // Copy the root
    to->root = (SListNode*)malloc(sizeof(SListNode));
    if (to->root == NULL) 
    {
      RAISE_SYS_ERROR("Not enough memory for a copy of the root node");
      return NULL;
    }
    if (!copyNodeData(to->root, from->root))
    {
      free(to->root);
      return NULL;
    }
    to->size++;
 
    // Copy all after the root
    currFromNode = from->root->next;
    prevToNode   = to->root;
  
  // At least one entry - append
  } 
  else
  {
    currFromNode = from->root;
    prevToNode   = to->last;
    end          = prevToNode;
  }

  // Copy the rest
  for (; currFromNode; currFromNode = currFromNode->next)
  {
    // A new node
    newNode = (SListNode*)malloc(sizeof(SListNode));
    if (newNode == NULL)
    {
      RAISE_SYS_ERROR("Not enough memory to copy a node");
      to->last = prevToNode; // Terminate the list at least
      return NULL;
    }

    // Copy data - if allocated, otherwise just set the data pointer
    if (!copyNodeData(newNode, currFromNode))
    {
      free(newNode);
      to->last = prevToNode;
      break;
    }

    prevToNode->next = newNode;
    to->size++;
    prevToNode = newNode;
  }

  // The last node does not point anywhere
  to->last = prevToNode;
  prevToNode->next = NULL;

  return (end == NULL) ? to->root : end->next;
}

SListNode* copySListNode(SList* to, SListNode* node)
{
  SListNode* new = appendToSList(to, node->allocSize);
  if (new == NULL)
  {
    return NULL;
  }
  if (node->allocSize == 0)
  {
    new->data = node->data;
  } 
  else
  {
    memcpy(new->data, node->data, node->allocSize);
  }
  return new;
}

SListNode* moveSList(SList* to, SList* from)
{
  SListNode* astart;
 
  // Moving an empty list is easy - nothing to do
  if (from->size == 0)
  {
    return NULL;
  }
 
  // Target is empty
  if (to->size == 0)
  {
    to->root = from->root;
    to->last = from->last;
    to->size = from->size;

  // Append
  } 
  else
  {
    to->last->next = from->root;
    to->last       = from->last;
    to->size      += from->size;
  }

  astart = from->root;

  from->root = NULL;
  from->size = 0;

  return astart;
}

void moveSListNode(SList* to, SList* from, SListNode* node, 
                   SListNode* prevNode)
{
  if (to->size == 0)
  {
    to->root = node;  
  } 
  else
  {
    to->last->next = node;
  }
  to->last = node;
  to->size++;

  if (prevNode == NULL)
  {
    from->root = node->next;
  } 
  else
  {
    prevNode->next = node->next;
  }
  node->next = NULL;
  from->size--;
}
