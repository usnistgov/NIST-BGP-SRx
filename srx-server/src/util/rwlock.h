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
 * Read/write lock - multiple readers or one writer at the same time
 * @note Currently based on PThread
 * 
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 *            * Added Changelog
 * 0.1.0.0  - 2010/06/04 - pgleichm
 *            * Code created.
 */

#ifndef __RWLOCK_H__
#define __RWLOCK_H__

#include <pthread.h>
#include <stdbool.h>

/** An R/W lock. */
typedef pthread_rwlock_t  RWLock;

/**
 * Initializes an R/W lock.
 *
 * @param self Variable that should be initialized
 * @return \c true = successful, \c false = failed
 */
extern bool createRWLock(RWLock* self);

/**
 * Releases an R/W lock.
 *
 * @param self Instance
 */
extern void releaseRWLock(RWLock* self);

/**
 * Acquires a read lock. 
 * Blocks until an eventually existing write lock is unlocked.
 *
 * @param self Instance
 */
extern void acquireReadLock(RWLock* self);

/**
 * Unlocks a read lock.
 *
 * @param self Instance
 */
extern void unlockReadLock(RWLock* self);


/** 
 * Acquires a write lock.
 * Blocks until all existing read and write locks are unlocked.
 *
 * @param self Instance
 */
extern void acquireWriteLock(RWLock* self);

/**
 * Unlocks a write lock.
 *
 * @param self Instance
 */
extern void unlockWriteLock(RWLock* self);

/**
 * Changes from a read to a write lock.
 * Blocks until all existing read and write locks are unlocked.
 *
 * @param self Instance
 */
extern void changeReadToWriteLock(RWLock* self);

/** 
 * Changes from write to read lock.
 * Blocks until an eventually existing write lock is unlocked.
 *
 * @param self Instance
 */
extern void changeWriteToReadLock(RWLock* self);

#endif // !__RWLOCK_H__

