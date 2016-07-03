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
 * -----------------------------------------------------------------------------
 *  0.1.0.1 - 2018/04/10 - oborchert
 *            * Fixed some compiler errors. 
 *  0.1.0.0 - 2018/03/12 - oborchert
 *            * Source created.
 */
#ifndef PREFIX_TRIE_H
#define PREFIX_TRIE_H

typedef void PrefixTrieElem;

/**
 * This enumeration provides the compare results.
 */
typedef enum {
  /** Both prefixes are the same */
  SAME   = 0,
  PARENT = 1,
  LCHILD = 2,
  RCHILD = 3
} PrefixTrieComp;

typedef struct _PrefixTrieNode {
  /** The parent node (NULL if root). */
  struct _PrefixTrieNode*  parent;
  /** The left node (lower value). */
  struct _PrefixTrieNode*  left;
  /** The right node (higher value). */
  struct _PrefixTrieNode*  right;
  /** The element stored within this node. */
  PrefixTrieElem* elem;  
} PrefixTrieNode;

/** This */
typedef struct 
{
  /** The root node. */
  PrefixTrieNode* root;
    
  /** 
   * This function (if set) will be called for each elem that has to be
   * free'd.
   * 
   * @param elem The element to be free'd
   */
  void (*releaseData)(PrefixTrieElem* elem);
  
  /**
   * Method to compare e1 with e2. If NULL the pointer values are compared.
   * The return value is:
   *   < 0 : e1  < e2
   *  == 0 : e1 == e2
   *   > 0 : e1  > e2
   * 
   * @param e1 The first element.
   * @param e2 The second element.
   * 
   * @return < 0, 0, > 0 if e1 < e2, e1 == e2, or e1> e2 
   * 
   */ 
  int (*compareData)(PrefixTrieElem* e1, PrefixTrieElem* e2);
  
} PrefixTrie;

/**
 * Create a new BinTreeNode.
 * 
 * @param element The element. Can be NULL.
 * 
 * @return Pointer to the allocated memory.
 */
PrefixTrie* createTree(PrefixTrieElem* element);

/**
 * Insert the element into the trie.
 * 
 * @param trie The trie the element has to be inserted into.
 * @param element The element to tbe inserted (MUST NOT BE NULL)
 * 
 * @return The element that was replaced by this element or NULL.
 */
PrefixTrieElem* insertElem(PrefixTrie* trie, PrefixTrieElem* element);

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

#endif /* BIN_TREE_H */

