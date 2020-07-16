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
 * Implements a FIFO stack
 * 
 * @version 0.1.2
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.1.2 - 2018/01/16 - oborchert
 *          * Fixed segmentation fault in popStack when stack is empty.
 *  0.1.1 - 2018/01/11 - oborchert
 *          * Modified isStackEmpty to return false in case the given Stack is
 *            NULL.
 *  0.1.0 - 2015/08/26 - oborchert
 *          * Created File.
 */

#include <stddef.h>
#include <malloc.h>
#include <string.h>
#include "stack.h"

/**
 * Used to insert the element on top of the list.
 * 
 * @param e1 will be ignored
 * @param e2 will be ignored
 * 
 * @return -1
 */
static int _compare(void* e1, void* e2)
{
  return -1; // results in insert on top.
}

/**
 * Initialize the given stack
 * 
 * @param stack the given stack element
 * 
 * @return the allocated empty stack
 * 
 */
Stack* createStack()
{
  return (Stack*)createList(); 
}

/**
 * initializes the stack.
 * 
 * @param stack the stack to be initialized;
 */
void initStack(Stack* stack)
{
  memset (stack, 0, sizeof(Stack));  
}

/**
 * Pushed the given element on the stack
 * 
 * @param stack The stack where to put the element on
 * @param elem The element to add on the stack.
 * 
 */
void pushStack(Stack* stack, void* elem)
{
  // Insert on the top.
  insertListElem((List*)stack, elem, _compare);
}

/**
 * Pushed the given element on the bottom of the stack. This transforms the 
 * stack into a FIFO queue.
 * 
 * @param stack The stack where to put the element on
 * @param elem The element to add on the stack.
 * 
 */
void fifoPush(Stack* stack, void* elem)
{
  addListElem((List*)stack, elem);
}

/**
 * Retrieve the top data and remove it from the stack
 * 
 * @param stack The stack
 * @param data the data to be returned.
 * 
 * @return return the top stack element and removed it from the stack or NULL.
 */
void* popStack(Stack* stack)
{
  void* elem = NULL;
  if (stack->count != 0)
  {
    elem = stack->head->elem;
    removeListElem((List*)stack, elem, LIST_DIR_FWD);
  }
  return elem;
}

/**
 * Have a peek at the top element.
 * 
 * @param stack the stack
 * 
 * @return the top stack element. 
 */
void* peekStack(Stack* stack)
{
  if (stack->count != 0)
  {
    return stack->head->elem;
  }
  return NULL;
}

/**
 * Destroy the stack by removing all elements and freeing all allocated memory 
 * except the Stack instance itself. This MUST be freed by the caller.
 * 
 * @param stack the stack itself
 * 
 * @see destroyList(List)
 */
void destroyStack(Stack* stack)
{
  destroyList((List*)stack);
}

/**
 * Destroy the stack and free all allocated memory including the elements
 * 
 * @param stack the stack itself
 * @param mFree the method to use to free the allocated memory for the elem.
 */
void destroyStackDeep(Stack* stack, method_free mFree)
{
  destroyListDeep((List*)stack, mFree);
}

/**
 * Determines if the stack is empty. If the stack is NULL the function returns
 * true.
 * 
 * @param stack The stack to be examined
 * 
 * @return true if the stack is empty, otherwise false.
 */
bool isStackEmpty(Stack* stack)
{
  return stack != NULL ? stack->count == 0 : true;
}