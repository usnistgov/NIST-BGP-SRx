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
 * This File provides a binary trie.
 *
 * @version 0.1.0.1
 * 
 * ChangeLog:
 * ----------------------------------------------------------------------------
 *  0.1.0.1 - 2018/06/10 - oborchert
 *            * Fixed some compiler errors
 *  0.1.0.0 - 2018/03/12 - oborchert
 *            * Source created.
 */
#include <stddef.h>
#include <stdbool.h>
#include <malloc.h>
#include "antd-util/prefix_trie.h"

/**
 * Create a Tree Node element. The element is allocated using malloc.
 * 
 * @param root The root element. CAN BE NULL
 * @param elem The element itself, CAN BE NULL
 * 
 * @return The node element.
 */
static PrefixTrieNode* _createTreeNode(PrefixTrieNode* root, 
                                       PrefixTrieElem* elem)
{
  PrefixTrieNode* node = malloc(sizeof(PrefixTrieNode));
  memset(node, 0, sizeof(PrefixTrieNode));
  node->parent = root;
  node->elem   = elem;
  return node;
}

/**
 * Create a new PrefixTrie. The memory is allocated using malloc.
 * 
 * @param element The element. Can be NULL.
 * 
 * @return Pointer to the allocated memory.
 */
PrefixTrie* createTree(PrefixTrieElem* element)
{
  PrefixTrie* trie = malloc(sizeof(PrefixTrie));
  memset(trie, 0, sizeof(PrefixTrie));
  trie->root = _createTreeNode(NULL, element);
  
  return trie;
}

/**
 * Insert the element into the trie.
 * 
 * @param trie The trie the element has to be inserted into.
 * @param element The element to the inserted (MUST NOT BE NULL)
 * 
 * @return The element that was replaced by this element or NULL.
 */
PrefixTrieElem* insertElem(PrefixTrie* trie, PrefixTrieElem* element)
{
  PrefixTrieNode* ptr = trie->root;
  PrefixTrieNode* hlp = NULL;
  PrefixTrieElem* retVal = NULL;
  
  int cmpVal = 0;
  while (ptr != NULL)
  {
    cmpVal = trie->compareData(element, ptr->elem);
    // Check or insert the left child
    if (cmpVal < 0)
    {
      // left child or create node for left child
      if (ptr->left != NULL)
      {
        // Check if elem could be a parent of left.
        if (trie->compareData(element, ptr->left->elem) > 0)
        {
          hlp = ptr->left;
          ptr->left = _createTreeNode(ptr, element);
          
        }
        else
        {
          ptr = ptr->left;
        }
      }
      else
      {
        ptr->left = _createTreeNode(ptr, element);
        ptr = NULL;
      }
      continue;
    }
    
    // Check or insert the right child
    if (cmpVal > 0)
    {
      if (ptr->right != NULL)
      {
        ptr = ptr->right;
      }
      // right child or create child for right child
      continue;
    }
    
    // replace or set current element.
    retVal    = ptr->elem;
    ptr->elem = element;
    ptr       = NULL; // This ends the loop.
  }
  
  return retVal;
}

/**
 * Remove the element from the trie
 * 
 * @param trie The trie where the element has to be removed from
 * @param element The element to be removed.
 * 
 * @return true if the element was found and removed, false if not found.
 * 
 */
bool removeElem(PrefixTrieElem trie, PrefixTrieElem* element);
