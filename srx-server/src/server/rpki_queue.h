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
 * This Header file specifies RPKI queuing structures. A queue implementation 
 * might follow later on.
 *
 * @version 0.5.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.5.0.0 - 2017/07/08 - oborchert
 *            * Added values to enumeration e_RPKI_QUEUE_REASON to allow 
 *              bit encoding.
 *         - 2017/06/22 - oborchert
 *            * File created
 */
#ifndef RPKI_QUEUE_H
#define RPKI_QUEUE_H

#include <stdlib.h>
#include <stdbool.h>
#include "shared/srx_defs.h"

/** This enumeration signals what happened and might affect the validation state
 * of the update */
typedef enum {
  /** A ROA modification */
  RQ_ROA=1,
  /** A Key Modification */
  RQ_KEY=2,
  /** Both happened */
  RQ_BOTH=3,        
  /* ASPA modification */
  RQ_ASPA=4,       
  /* all conditions */
  RQ_ALL=7,       
} e_RPKI_QUEUE_REASON;

/** The preliminary queue type */
typedef void RPKI_QUEUE;

/** This struct is used to return the next queue element. */
typedef struct {
  /** Contains the reason of this element. */
  e_RPKI_QUEUE_REASON reason;
  /** The ID of the affected update. */
  SRxUpdateID         updateID;
} RPKI_QUEUE_ELEM;

/**
 * Create and initialize the RPKI queue.
 * 
 * @return The RPKI Queue.
 * 
 * @since 0.5.0.0
 */
RPKI_QUEUE* rq_createQueue();

/**
 * Empties and frees all memory allocated by this queue
 * 
 * @param queue The queue to be released
 * 
 * @since 0.5.0.0
 */
void rq_releaseQueue(RPKI_QUEUE* queue);

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
              e_RPKI_QUEUE_REASON reason, SRxUpdateID* updateID);

/**
 * Fills the given data with the next element of the queue and removed the queue
 * element and returns 'true'. 
 * If no element resides in the queue, the given element will NOT be touched and
 * the call returns 'false'
 * 
 * @param queue The RPKI queue.
 * @param elem The element to be filled with the next element.
 * 
 * @return true if the given element was filled with meaningful data.
 * 
 * @since 0.5.0.0
 */
bool rq_dequeue(RPKI_QUEUE* queue, RPKI_QUEUE_ELEM* elem);

/**
 * Empty the RPKI queue
 * 
 * @param queue The RPKI queue to be emptied
 */
void rq_empty(RPKI_QUEUE* queue);

/**
 * Return the number of elements in the queue,
 * 
 * @param queue The RPKI Queue
 * 
 * @return the number of elements in the queue
 */
int rq_size(RPKI_QUEUE* queue);

#endif /* RPKI_QUEUE_H */

