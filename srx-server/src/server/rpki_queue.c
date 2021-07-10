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
 * This file implements the RPKI Queue, a thread safe queue with semaphore
 * controlled single access.
 *
 * NOTE:
 * Functions starting with underscore are only to be called from within this
 * file. Therefore no additional checking is needed is some provided values
 * are NULL. entry functions specified in the header file do take cate of that.
 * 
 * @version 0.5.0.1
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.5.0.1  - 2017/08/25 - oborchert
 *            * BZ1224: Function __rq_createQueueElem did not return the 
 *              generated object. (fixed)
 * 0.5.0.0  - 2017/06/22 - oborchert
 *            * File created
 */
#include <malloc.h>
#include <string.h>
#include <semaphore.h>
#include "srx/srxcryptoapi.h"
#include "server/rpki_queue.h"
#include "shared/srx_identifier.h"
#include "util/log.h"

/** The Queue element */
typedef struct _rpki_queue_list_elem {
  /** Pointer to the next element */
  struct _rpki_queue_list_elem* next;
  /** The element to be queued. */
  RPKI_QUEUE_ELEM elem;
} _RPKI_QUEUE_LIST_ELEM;

/** The RPKI queue - This queue will have each element only once. Each new 
 * element will be added to the tail end - if not in the queue already. */
typedef struct {
  /** The queues head element */
  _RPKI_QUEUE_LIST_ELEM* head;
  /** Count the number of elements in the queue. */
  u_int32_t size;
  /** For thread safety */
  sem_t semaphore;
} _RPKI_QUEUE;

/**
 * Set the Semaphore lock
 * 
 * @param rQueue the queue whose access is locked.
 * 
 * @return false if an error occurred
 */
static bool _rq_lock(_RPKI_QUEUE* rQueue)
{
  if (rQueue != NULL)
  {
    // Maybe use the sem_wait_wrapper which expires after some time
    sem_wait(&rQueue->semaphore);
    // or sem_timedwait(...)
  }
  
  return rQueue != NULL;
}

/**
 * Set the Semaphore lock
 * 
 * @param rQueue the queue whose access will be unlocked.
 * 
 * @return false if an error occurred
 */
static bool _rq_unlock(_RPKI_QUEUE* rQueue)
{
  bool retVal = false;
  
  // The caller assures that rQueue is not NULL  
  int lockVal;
  sem_getvalue(&rQueue->semaphore, &lockVal);
  // This checks the binary semaphore (0|1)
  if (lockVal == 0)
  {
    // Maybe use the sem_wait_wrapper which expires after some time
    sem_post(&rQueue->semaphore);
    retVal = true;
  }
  else 
  {
    LOG(LEVEL_ERROR, "%s called without a previously aquired lock.", 
                     __func__);
  }
  
  return retVal;
}

/**
 * Create a list element
 * 
 * @param reason The reason information
 * @param updateID The SRx Update ID
 * 
 * @return The instance of the element
 */
static _RPKI_QUEUE_LIST_ELEM* __rq_createQueueElem(e_RPKI_QUEUE_REASON reason, 
                                                   SRxUpdateID* updateID)
{
  _RPKI_QUEUE_LIST_ELEM* listElem = malloc(sizeof(_RPKI_QUEUE_LIST_ELEM));
  memset (listElem, 0, sizeof(_RPKI_QUEUE_LIST_ELEM));
  
  listElem->elem.reason   = reason;
  memcpy(&listElem->elem.updateID, updateID, LEN_SRxUpdateID);
  listElem->next = NULL;
  
  return listElem;
}

/**
 * Fills the given data with the next element of the queue and removed the queue
 * element and returns 'true'. 
 * If no element resides in the queue, the given element will NOT be touched and
 * the call returns 'false'
 * 
 * THIS FUNCTION DOES NOT USE SEMAPHORE - USED BY rq_dequeue and rq_empty
 * 
 * @param rQueue The _RPKI queue.
 * @param elem The element to be filled with the next element.
 * 
 * @return true if the given element was filled with meaningful data. False 
 *         if either no element is available or the given 'elem' is NULL.
 * 
 * @since 0.5.0.0
 */
static bool _rq_dequeue(_RPKI_QUEUE* rQueue, RPKI_QUEUE_ELEM* elem)
{
  bool retVal = false;
  
  // The caller assures that rQueue is not NULL
  
  int size = sizeof(RPKI_QUEUE_ELEM);
  if (rQueue->size != 0)
  {
    // remove the list element from the top of the queue
    _RPKI_QUEUE_LIST_ELEM* listElem = rQueue->head;
    rQueue->head = listElem->next;
    rQueue->size--;

    // copy the queue element into the return value
    memcpy(elem, &listElem->elem, size);
    retVal = true;

    // clean up the list elements
    memset(listElem, 0, size);
    free(listElem);
  }
  
  return retVal;
}

////////////////////////////////////////////////////////////////////////////////
// THE HEADER FUNCTIOINS
////////////////////////////////////////////////////////////////////////////////

/**
 * Create and initialize the RPKI queue.
 * 
 * @return The RPKI Queue.
 * 
 * @since 0.5.0.0
 */
RPKI_QUEUE* rq_createQueue()
{
  _RPKI_QUEUE* rQueue = malloc(sizeof(_RPKI_QUEUE));
  memset(rQueue, 0, sizeof(_RPKI_QUEUE));
 
  // Initialize the Semaphore - no shared fork, value 0
  if (sem_init(&rQueue->semaphore, 0, 1) != 0)
  {
    free(rQueue);
    LOG(LEVEL_ERROR, "Could not initialize the RPKI Queue Semaphore.");
    rQueue=NULL;
  }
  
  return (RPKI_QUEUE*)rQueue;
}

/**
 * Empties and frees all memory allocated by this queue
 * 
 * @param queue The queue to be released
 * 
 * @since 0.5.0.0
 */
void rq_releaseQueue(RPKI_QUEUE* queue)
{
  if (queue != NULL)
  {    
    _RPKI_QUEUE* rQueue = (_RPKI_QUEUE*)queue;
    rq_empty(rQueue);
    sem_destroy(&rQueue->semaphore);
    memset(rQueue, 0, sizeof(_RPKI_QUEUE));
    free(rQueue);    
  }
}

/** 
 * Do add the update id to the RPKI queue. The queue might combine multiple 
 * reasons of the same update into one. 
 * 
 * @param queue The RPKI queue.
 * @param reason Explains what happened and might affect the update
 * @param updateID The id of the update that is affected by this reason.
 * 
 * @since 0.5.0.0
 */
void rq_queue(RPKI_QUEUE* queue, 
              e_RPKI_QUEUE_REASON reason, SRxUpdateID* updateID)
{
  // Each update id is listed only once. New elements will be added to the end 
  // of the list. While walking through the list to the end, each element will 
  // be compared to the new element and possibly updated. 
  // this means if none is found the end will be reached and the update will be 
  // added.
  if (queue != NULL)
  {
    _RPKI_QUEUE* rQueue = (RPKI_QUEUE*)queue;
    
    if (_rq_lock(rQueue))
    {
      _RPKI_QUEUE_LIST_ELEM* listElem = rQueue->head;
      bool added = false;

      if (listElem != NULL)
      {    
        while (!added)
        {
          if (compareSrxUpdateID(&listElem->elem.updateID, updateID, SRX_UID_BOTH) 
              != 0)
          {
            // Not the same, move on
            if (listElem->next != NULL)
            {
              listElem = listElem->next;
            }
            else
            {
              listElem->next = __rq_createQueueElem(reason, updateID);
              added = true;
              rQueue->size++;
            }
          }
          else
          {
            // already added, maybe the reason myst be updated
            added = true;
            if (listElem->elem.reason != reason)
            {
              // Set it to both if the reason is different. If in the future more
              // reasons are added then this needs to be modified.
              listElem->elem.reason = RQ_ALL;
            }
          }
        }
      }
      else
      {
        rQueue->head = __rq_createQueueElem(reason, updateID);
        rQueue->size++;
      }

      _rq_unlock(rQueue);
    }
    else
    {
      LOG(LEVEL_ERROR, "Could not aquire lock for RPKI QUEUE");
    }
  }
}

/**
 * Fills the given data with the next element of the queue and removed the queue
 * element and returns 'true'. 
 * If no element resides in the queue, the given element will NOT be touched and
 * the call returns 'false'
 * 
 * @param queue The RPKI queue.
 * @param elem The element to be filled with the next element.
 * 
 * @return true if the given element was filled with meaningful data. False 
 *         if either no element is available or the given 'elem' is NULL.
 * 
 * @since 0.5.0.0
 */
bool rq_dequeue(RPKI_QUEUE* queue, RPKI_QUEUE_ELEM* elem)
{
  bool retVal = false;
  
  if (queue != NULL)
  {
    _RPKI_QUEUE* rQueue = (RPKI_QUEUE*)queue;
    if (_rq_lock(rQueue))
    {
      retVal = _rq_dequeue(rQueue, elem);      
      _rq_unlock(rQueue);
    }
    else
    {
      LOG(LEVEL_ERROR, "Could not aquire lock for RPKI QUEUE");
    }
  }
  
  return retVal;
}

/**
 * Empty the RPKI queue
 * 
 * @param queue The RPKI queue to be emptied
 */
void rq_empty(RPKI_QUEUE* queue)
{
  if (queue != NULL)
  {
    _RPKI_QUEUE* rQueue = (RPKI_QUEUE*)queue;
    if (_rq_lock(rQueue))
    {
      RPKI_QUEUE_ELEM elem;
      while (_rq_dequeue(rQueue, &elem)) {}
      _rq_unlock(rQueue);    
    }
    else
    {
      LOG(LEVEL_ERROR, "Could not aquire lock for RPKI QUEUE");
    }
  }
}

/**
 * Return the number of elements in the queue. This function is NOT synchronized
 * which means the number of elements might change during the call which is 
 * not relevant because it can change after it was retrieved and before it is 
 * processes anyhow.
 * 
 * @param queue The RPKI Queue
 * 
 * @return the number of elements in the queue
 */
int rq_size(RPKI_QUEUE* queue)
{
  int size = 0;
  
  if (queue != NULL)
  {
    _RPKI_QUEUE* rQueue = (_RPKI_QUEUE*)queue;
    size = rQueue->size;
  }
  
  return size;
}
