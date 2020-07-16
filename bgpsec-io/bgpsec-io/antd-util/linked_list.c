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
 * Implements a linked list - loops are not permitted.
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *   0.1.0 - August 26, 2015 - oborchert
 *           * Created File.
 */

#include <stddef.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include "linked_list.h"

/**
 * Creates and initializes the list elements. This function allocates the memory
 * needed for the list. Call destroyList to free the memory again. 
 * 
 * @param list the list element.
 */
List* createList()
{
  List* list = malloc(sizeof(List));
  memset (list, 0, sizeof(List));
  
  return list;
}

/**
 * initializes the list.
 * 
 * @param list the list to be initialized;
 */
void initList(List* list)
{
  memset (list, 0, sizeof(List));  
}

/**
 * Add the given element to the list.
 * 
 * @param list The list where to add the element.
 * @param elem The element itself
 * 
 * @return true if the element could be added.
 */
bool addListElem(List* list, void* elem)
{
  ListElem* newElem = malloc(sizeof(ListElem));
  if (newElem)
  {
    memset (newElem, 0, sizeof(ListElem));
    
    newElem->elem = elem;
    newElem->prev = list->tail;
    
    if (list->tail == NULL)
    { // New element
      list->head = newElem;
      list->tail = newElem;
    }
    else
    { // Add to tail
      list->tail->next = newElem;
      list->tail = newElem;
    }
    list->count++;
    return true;
  }
  
  return false;
}

/**
 * Insert the element into the list.
 * 
 * @param list the list where to add the element into
 * @param elem The element to be added
 * @param comp The comparator function - MUST NOT BE NULL
 * 
 * @return true if the element was inserted.
 */
bool insertListElem(List* list, void* elem, method_compare comp)
{
  ListElem* helper = list->head;
  ListElem* newElem = NULL;

  if (helper == NULL)
  {
    addListElem(list, elem);
  }
  else
  {
    while (helper != NULL)
    {
      int cRes = 1;
      if (comp != NULL)
      {
        cRes = comp(elem, helper->elem);
      }
      switch (cRes)
      {
        case -1:
          // insert here before helper;
          newElem = malloc(sizeof(ListElem));
          newElem->elem = elem;
          newElem->next = helper;
          newElem->prev = helper->prev;
          helper->prev  = newElem;
          if (newElem->prev == NULL)
          {
            list->head = newElem;
          }
          else
          {
            newElem->prev->next = newElem;
          }
          list->count++;
          helper = NULL; // To stop the loop
          continue;
          break;
        case 0:
        case 1:
          // move to to the next element or add to the end
          if (helper->next == NULL)
          {
            return addListElem(list, elem);
          }
          break;
        default:
          printf("compare function returned invalid result!\n");
          return false;
      }
      helper = helper->next;
    }
  }
  
  return true;
}

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
void removeInternalListElem(List* list, ListElem* elem)
{
  if (elem->prev != NULL)
  {
    elem->prev->next = elem->next;
  }
  if (elem->next != NULL)
  {
    elem->next->prev = elem->prev;
  }
  if (list->head == elem)
  {
    list->head = elem->next;
  }
  if (list->tail == elem)
  {
    list->tail = elem->prev;
  }
  elem->prev = NULL;
  elem->next = NULL;
  elem->elem = NULL;
  free (elem);
  list->count--;  
}

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
void* removeListElem (List* list, void* element, int dir)
{
  // find element
  ListElem* helper;
  void* found = NULL;
  
  int idx = list->count;
  
  switch (dir)
  {
    case LIST_DIR_FWD:
      helper = list->head;
      while (helper != NULL && found == NULL)
      {
        idx--;
        if (helper->elem == element)
        {
          found = helper->elem;
          removeInternalListElem(list, helper);
        }
        else
        {
          helper = idx == 0 ? NULL : helper->next;
        }
      }
      break;
    case LIST_DIR_BWD:
      helper = list->tail;
      while (helper != NULL && found == NULL)
      {
        idx--;
        if (helper->elem == element)
        {
          found = helper->elem;
          removeInternalListElem(list, helper);
        }
        else
        {
          helper = idx == 0 ? NULL : helper->prev;
        }
      }
      break;
    default:
      break;
  }
  
  return found;
}

/**
 * Return the number of elements stored in the list.
 * 
 * @param list The list element
 * 
 * @return  the number of elements stored in the list.
 */
int listSize(List* list)
{
  return list->count;
}

/**
 * Empties the list and frees the memory of all internal list elements including
 * the attached element if deep is selected
 * 
 * @param list the list itself.
 * @param deep indicates if the element has to be freed as well.
 * @param mFree mFree the method to use to free the allocated memory for the 
 *              elem. Can be NULL if NOT deep destroy
 */
void emptyList(List* list, bool deep, method_free mFree)
{
  if (list == NULL)
  {
    return;
  }
  
  if (list->count > 0)
  {
    ListElem* helper = list->head;
    if (list->head->prev != NULL)
    {
      printf("ERROR: List head is out of synch!\n");
      return;
    }

    if (deep)
    {
      while (list->head != NULL)
      {
        helper = list->head;
        list->head = helper->next;
        mFree (helper->elem);
        helper->elem = NULL;
        removeInternalListElem(list, helper);
      }
    }
    else
    {
      while (list->head != NULL)
      {
        helper = list->head;
        list->head = helper->next;
        removeInternalListElem(list, helper);
      }
    }

    list->tail = NULL;
  }
}

/**
 * Destroy the list by removing all elements and freeing all allocated memory 
 * including the List instance itself.
 * 
 * @param stack the stack itself
 */
void destroyList(List* list)
{
  emptyList(list, false, NULL);
  free(list);
}

/**
 * Destroy the stack and free all allocated memory including the elements
 * 
 * @param list the stack itself
 * @param mFree the method to use to free the allocated memory for the elem.
 */
void destroyListDeep(List* list, method_free mFree)
{
  emptyList(list, true, mFree);
  free(list);
}

/**
 * Determines if the list is empty
 * 
 * @param stack The list to be examined
 * 
 * @return true if the list is empty, otherwise false.
 */
bool isListEmpty(List* list)
{
  return list->count == 0;
}

/**
 * Retrieve the element at the given position. NOT THREAD SAFE!!!
 *  
 * @param list the list.
 * @param idx the position - starting with 0.
 * 
 * @return the stored element or NULL if not found.
 */
void* getListElementAt(List* list, int idx)
{
  void* retVal = NULL;
  
  if (idx < list->count)
  {
    ListElem* elem = list->head;
    while (idx != 0)
    {
      elem = elem->next;
      idx--;
    }
    retVal = elem->elem;
  }
    
  return retVal;
}

