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
 * Functions for Mutex (Mutual Exclusion) handling.
 * @note Currently based on PThread
 * log.h is used for error reporting.
 * 
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 *            * Added Changelog
 *            * Added inline int destroyCond(...) from c to header 
 * 0.1.0.0  - 2010/01/11 - pgleichm
 *            * Code created.
 */

#ifndef __MUTEX_H__
#define __MUTEX_H__

#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdint.h>

/** A mutex. */
typedef pthread_mutex_t Mutex;
typedef pthread_cond_t Cond;
typedef pthread_condattr_t CondAttr;

/** 
 * Initializes a mutex.
 *
 * @param self New mutex
 * @return \c true = successfully allocated the necessary resource, 
 *    \c false = failed
 */
extern bool initMutex(Mutex* self);


/** 
 * Releases a previously initialized mutex. This call also unblocks a
 * waiting routine.
 *
 * @param self Mutex instance
 */
extern void releaseMutex(Mutex* self);

/**
 * Waits until the mutex could be locked and then locks it.
 *
 * @param self Mutex instance
 * @see unlockMutex
 */
extern void lockMutex(Mutex* self);

/**
 * Unlocks a mutex.
 *
 * @param self Mutex instance
 * @see lockMutex
 */
extern void unlockMutex(Mutex* self);

/**
 * Waits for a mutex to become unlocked, but does not lock it.
 *
 * @param self Mutex
 */
extern void waitMutex(Mutex* self);


extern int initCond(Cond *cond);
extern int signalCond(Cond *cond);
/** Wait for a time milli seconds. time - 0 = until notify called! */
extern int waitCond(Cond *cond, Mutex *self, uint32_t millis);

/**
 * wait for a given amount of milli seconds
 * 
 * @param sem_var The semaphor variable to wait on
 * @param millis The time in milli seconds
 */
extern int sem_wait_wrapper(sem_t *sem_var, uint32_t millis);


inline int destroyCond(Cond *cond);
#endif // !__MUTEX_H__

