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
 * This software might use libraries that are under GNU public license or
 * other licenses. Please refer to the licenses of all libraries required 
 * by this software.
 *
 *  
 * This files is used for testing the RPKI Queue functions.
 *
 * @version 0.5.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.5.0.0  - 2017/06/22 - oborchert
 *            * File created
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <srx/srxcryptoapi.h>
#include "server/rpki_queue.h"

#define NO_ELEMENTS 12

/**
 * check the value against expected, if not match then exit.
 * 
 * @param val the value to be checked
 * @param expected the value to be checked against (expected value)
 * @param error the error string in case of exit
 */
static void assert_int(RPKI_QUEUE* queue, int val, int expected, char* error)
{
  if (val != expected)
  {
    if (error == NULL)
    {
      error = "";
    }
    printf ("Error: %s; Expected %i but received %i\n", error, expected, val);
    
    rq_releaseQueue(queue);
    exit (EXIT_FAILURE);    
  }
}

/** 
 * Initialize the queue or exit program
 * 
 * @return the initialized queue
 */
static RPKI_QUEUE* _initialize()
{
  printf ("Initialize experiment\n");
  RPKI_QUEUE* queue = rq_createQueue();
  
  int size = rq_size(queue);
  printf ("         RPKI Queue size: %i\n", size);
  assert_int(queue, size, 0, "Initial Queue Size");  
  
  printf ("         passed.\n");
  return queue;
}

/**
 * Fill the queue with noElements elements or exit. 
 * Each odd element is RQ_KEY, each even element is RQ_ROA
 * 
 * @param queue The queue to be tested
 * @param noElements The number of elements to be added
 * @param expectedSize Expected number of elements in the queue
 * 
 */
static void _test1(RPKI_QUEUE* queue, int noElements, int expectedSize)
{
  printf ("Test #1: Queue %i elements with %i being stored!\n", 
          noElements, expectedSize);
  printf ("         even = RQ_ROA\n");
  printf ("         odd  = RQ_KEY\n");
  
  SRxUpdateID updateID = 0;
  for (updateID = 0; updateID < noElements; updateID++)
  {
    if (updateID % 2 == 0)
    {
      rq_queue(queue, RQ_ROA, &updateID);
    }
    else
    {
      rq_queue(queue, RQ_KEY, &updateID);      
    }
  }
  int size = rq_size(queue);
  printf ("         RPKI Queue size: %i\n", size);
  assert_int (queue, size, expectedSize, "After Queue was filled");     
  printf ("         passed.\n");
}

/**
 * Fill the queue with noElements elements or exit. 
 * Each odd element is RQ_ROA, each even element is RQ_KEY
 * 
 * @param queue The queue to be tested
 * @param noElements The number of elements to be added
 * @param expectedSize Expected number of elements in the queue
 * 
 */
static void _test2(RPKI_QUEUE* queue, int noElements, int expectedSize)
{
  printf ("Test #2: Queue %i elements with %i being stored!\n", 
          noElements, expectedSize);
  printf ("         even = RQ_KEY\n");
  printf ("         odd  = RQ_ROA\n");
  SRxUpdateID updateID = 0;
  for (updateID = 0; updateID < noElements; updateID++)
  {
    if (updateID % 2 == 0)
    {
      rq_queue(queue, RQ_KEY, &updateID);
    }
    else
    {
      rq_queue(queue, RQ_ROA, &updateID);      
    }
  }
  int size = rq_size(queue);
  printf ("         RPKI Queue size: %i\n", size);
  assert_int (queue, size, expectedSize, "After Queue was filled");     
  
  printf ("         passed.\n");
}

/**
 * Fill the queue with noElements elements or exit. Each odd element is RQ_ROA
 * each even element is RQ_KEY
 * 
 * @param queue The queue to be tested
 * @param even the expected type of even elements
 * @param odd the expected type of odd elements
 * 
 */
static void _test3(RPKI_QUEUE* queue, 
                        e_RPKI_QUEUE_REASON even, e_RPKI_QUEUE_REASON odd)
{
  printf ("Test #3: Check the element status for\n");
  printf ("         even = %s\n", (even == RQ_ROA) 
                                  ? "RQ_ROA" : (even == RQ_KEY) 
                                  ? "RQ_KEY" : "RQ_BOTH");
  printf ("         odd  = %s\n", (odd == RQ_ROA) 
                                  ? "RQ_ROA" : (odd == RQ_KEY) 
                                  ? "RQ_KEY" : "RQ_BOTH");
  RPKI_QUEUE_ELEM queueElem;
  
  while (rq_dequeue(queue, &queueElem))
  {
    if (queueElem.updateID % 2 == 0)
    {
      //even
      assert_int(queue, queueElem.reason, even, "Even Element");
    }
    else
    {
      //odd
      assert_int(queue, queueElem.reason, odd, "Odd Element");
    }
  }
  printf ("         passed.\n");
}

/**
 * Empty the queue or exit the program
 * 
 * @param queue The queue to be tested
 */
static void _test4(RPKI_QUEUE* queue)
{   
  printf ("Test #4: Empty the queue!\n");
  
  rq_empty(queue);
  assert_int(queue, rq_size(queue), 0, "Queue should be empty");
  
  printf ("         passed.\n");
}

/**
 * This is the main function
 */
int main(int argc, char** argv) 
{

  RPKI_QUEUE* queue = _initialize();
  
  printf("\nRun tests #1 and #3 to store %i elements and check for ("
         "even: RQ_BOTH, odd: RQ_BOTH)\n", NO_ELEMENTS);    
  // Fill
  _test1(queue, NO_ELEMENTS, NO_ELEMENTS);
  // Check - does dequeue and check the elements
  _test3(queue, RQ_ROA, RQ_KEY);
  
  printf("\nRun test1 #2 and #3 to store %i elements and check for ("
         "even: RQ_BOTH, odd: RQ_BOTH)\n", NO_ELEMENTS);    
  // Fill
  _test2(queue, NO_ELEMENTS, NO_ELEMENTS);
  // Check - does dequeue and check the elements
  _test3(queue, RQ_KEY, RQ_ROA);
  
  printf("\nRun tests #1, #2, and #3 to store %i elements and check for ("
         "even: RQ_BOTH, odd: RQ_BOTH)\n", NO_ELEMENTS);    
  // Fill again
  _test1(queue, NO_ELEMENTS, NO_ELEMENTS);
  // Fill again
  _test2(queue, NO_ELEMENTS, NO_ELEMENTS);
  //Check
  _test3(queue, RQ_BOTH, RQ_BOTH);
  
  printf("\nRun tests #1 and #4 to store %i elements empty the queue\n", 
         NO_ELEMENTS);    
  // Fill again
  _test1(queue, NO_ELEMENTS, NO_ELEMENTS);
  // Clean
  _test4(queue);

  
  rq_releaseQueue(queue);
  
  printf ("End of all tests!\n");
  return (EXIT_SUCCESS);
}