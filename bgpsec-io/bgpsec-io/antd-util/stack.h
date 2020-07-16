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
 * Implements a LIFO Stack based on a linked list
 * 
 * @version 0.1.1
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.1.1 - 2018/01/11 - oborchert
 *          * Modified isStackEmpty to return false in case the given Stack is
 *            NULL.
 *  0.1.0 - 2015/08/26 - oborchert
 *          * Created File.
 */
#ifndef STACK_H
#define	STACK_H

#include "linked_list.h"

typedef List Stack;

/**
 * Initialize the given stack
 * 
 * @param stack the given stack element
 * 
 * @return the allocated empty stack
 * 
 */
Stack* createStack();

/**
 * initializes the stack.
 * 
 * @param stack the stack to be initialized;
 */
void initStack(Stack* stack);

/**
 * Pushed the given element on top of the stack
 * 
 * @param stack The stack where to put the element on
 * @param elem The element to add on the stack.
 * 
 */
void pushStack(Stack* stack, void* elem);

/**
 * Pushed the given element on the bottom of the stack. This transforms the 
 * stack into a FIFO queue.
 * 
 * @param stack The stack where to put the element on
 * @param elem The element to add on the stack.
 * 
 */
void fifoPush(Stack* stack, void* elem);

/**
 * Have a peek at the top element.
 * 
 * @param stack the stack
 * 
 * @return the top stack element. 
 */
void* peekStack(Stack* stack);

/**
 * Retrieve the top data and remove it from the stack
 * 
 * @param stack The stack
 * @param data the data to be returned.
 * 
 * @return return the top stack element and removed it from the stack.
 */
void* popStack(Stack* stack);

/**
 * Destroy the stack by removing all elements and freeing all allocated memory 
 * except the Stack instance itself. This MUST be freed by the caller.
 * 
 * @param stack the stack itself
 * 
 * @see destroyList(List)
 */
void destroyStack(Stack* stack);

/**
 * Destroy the stack and free all allocated memory including the elements
 * 
 * @param stack the stack itself
 * @param mFree the method to use to free the allocated memory for the elem.
 */
void destroyStackDeep(Stack* stack, method_free mFree);

/**
 * Determines if the stack is empty. If the stack is NULL the function returns
 * true.
 * 
 * @param stack The stack to be examined
 * 
 * @return true if the stack is empty, otherwise false.
 */
bool isStackEmpty(Stack* stack);

#endif	/* STACK_H */