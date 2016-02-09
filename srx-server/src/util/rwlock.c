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
 */
/*
 * 06/04/2010
 */

#include "util/rwlock.h"
#include "util/log.h"

bool createRWLock(RWLock* self)
{
  int ret = pthread_rwlock_init(self, NULL);
  if (ret == 0) 
  {
    return true;
  }
  RAISE_ERROR("Failed to create an R/W lock (error: %d)", ret);
  return false;
}

void releaseRWLock(RWLock* self)
{
  if (self != NULL) 
  {
    int ret = pthread_rwlock_destroy(self);

    // Unlock if busy
    while (ret == EBUSY) 
    {
      if (pthread_rwlock_unlock(self) != 0) 
      {
        break;
      }
      ret = pthread_rwlock_destroy(self);
    } 
  }
}

void acquireReadLock(RWLock* self)
{
  pthread_rwlock_rdlock(self);
}

void unlockReadLock(RWLock* self)
{
  pthread_rwlock_unlock(self);
}

void acquireWriteLock(RWLock* self)
{
  pthread_rwlock_wrlock(self);
}

void unlockWriteLock(RWLock* self)
{
  pthread_rwlock_unlock(self);
}

void changeReadToWriteLock(RWLock* self)
{
  if (pthread_rwlock_unlock(self) == 0)
  {
    pthread_rwlock_wrlock(self);
  }
}

void changeWriteToReadLock(RWLock* self)
{
  if (pthread_rwlock_unlock(self) == 0)
  {
    pthread_rwlock_rdlock(self);
  }
}

