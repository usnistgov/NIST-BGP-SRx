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
 * Implements a simple linked list
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *   0.1.0 - August 26, 2015 - borchert
 *           * Created File.
 */
#ifndef LINKED_LIST_H
#define	LINKED_LIST_H

#include <stdbool.h>

/** look into the list forward - starting by head */
#define LIST_DIR_FWD 1
/** look into the list backwards - starting by tail */
#define LIST_DIR_BWD 0

/**
 * A comparator method that compares both given parameters. The result MUST be:
 *  1: e1 is larger than e2
 *  0: both are equal
 * -1: e1 is less than e2
 * 
 * in case e1 is equal larger it will be added after e2
 * in case e1 is smaller it will be inserted ahead of e2
 */
typedef int (*method_compare)(void* e1, void* e2);

/**
 * This method is used to free the attached element in case for a destroyDeep 
 * call. 
 */
typedef void (*method_free)(void* elem);
/**
 * The list element only for internal usage
 */
typedef struct _ListElem
{
  struct _ListElem* prev;
  struct _ListElem* next;
  void* elem;
} ListElem;

/**
 * The list element.
 */
typedef struct 
{
  /* The head element in the list. */
  ListElem* head;
  /* The tail element in the list. */
  ListElem* tail;
  /* The number of elements in the list. */
  int count;
} List;

/**
 * Creates and initializes the list elements. This function allocates the memory
 * needed for the list. Call destroyList to free the memory again. 
 * 
 * @param list the list element.
 */
List* createList();

/**
 * initializes the list.
 * 
 * @param list the list to be initialized;
 */
void initList(List* list);

/**
 * Add the given element ot the list.
 * 
 * @param list The list where to add the element.
 * @param elem The element itself
 * 
 * @return true if the element could be added.
 */
bool addListElem(List* list, void* elem);

/**
 * Insert the element into the list.
 * 
 * 
 * @param list the list where to add the element into
 * @param elem The element to be added
 * @param comp The comparator function - MUST NOT BE NULL
 * 
 * @return true if the element was inserted.
 */
bool insertListElem(List* list, void* elem, method_compare comp);

/**
 * deleted the given element from the list. If the element exists multiple time
 * only one the first occurance will be deleted.
 * 
 * @param list the list where to remove the element form 
 * @param element the element to be deleted
 * @param dir Gives the direction to start looking from
 * 
 * @return the element of the found list element that was removed or NULL.
 */
void* removeListElem (List* list, void* element, int dir);

/**
 * Remove the internal list element from the list and frees the memory allocated
 * by it. The data is untouched.
 * 
 * This function should not be called directly. It is more for internal use and
 * other lists that base on this one.
 * 
 * @param list The list 
 * @param elem the element.
 */
void removeInternalListElem(List* list, ListElem* elem);

/**
 * Return the number of elements stored in the list.
 * 
 * @param list The list element
 * 
 * @return  the number of elements stored in the list.
 */
int listSize(List* list);

/**
 * Empties the list and frees the memory of all internal list elements including
 * the attached element if deep is selected
 * 
 * @param list the list itself.
 * @param deep indicates if the element has to be freed as well.
 * @param mFree mFree the method to use to free the allocated memory for the 
 *              elem. Can be NULL if NOT deep destroy
 */
void emptyList(List* list, bool deep, method_free mFree);

/**
 * Destroy the list by removing all elements and freeing all allocated memory 
 * including the List instance itself.
 * 
 * @param stack the stack itself
 */
void destroyList(List* list);

/**
 * Destroy the list and free all allocated memory including the elements
 * 
 * @param list the stack itself
 * @param mFree the method to use to free the allocated memory for the elem.
 */
void destroyListDeep(List* list, method_free mFree);

/**
 * Determines if the list is empty
 * 
 * @param stack The list to be examined
 * 
 * @return true if the list is empty, otherwise false.
 */
bool isListEmpty(List* list);

/**
 * Retrieve the element at the given position. NOT THREAD SAFE!!!
 *  
 * @param list the list.
 * @param idx the position.
 * 
 * @return the stored element or NULL if not found.
 */
void* getListElementAt(List* list, int idx);

#endif	/* LINKED_LIST_H */

