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
 * This file mainly wraps mutex and condition methods. This allows easier
 * debugging.
 *
 * @file mutex.c
 * @date Created: 01/11/2010
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2016/01/21 - kyehwanl
 *            * change log level of waitCond() from LOGLEVEL to LEVEL_COMM,
 *              in order to avoid the infinate printing while waiting command
 */

#include <time.h>
#include "util/mutex.h"
#include "util/log.h"

#define LOGLEVEL LEVEL_DEBUG

inline bool initMutex(Mutex* self)
{
  LOG(LOGLEVEL, "([0x%08X] Mutex):  >  [0x%08X] INIT", pthread_self(), self);
  return (pthread_mutex_init(self, NULL) == 0);
}

inline void releaseMutex(Mutex* self)
{
  LOG(LOGLEVEL, "([0x%08X] Mutex):  >  [0x%08X] RELEASE", pthread_self(), self);
  (void)pthread_mutex_destroy(self);
}

inline void lockMutex(Mutex* self)
{
  LOG(LOGLEVEL, "([0x%08X] Mutex): --> [0x%08X] REQ LOCK ",
      pthread_self(), self);
  (void)pthread_mutex_lock(self);
  LOG(LOGLEVEL, "([0x%08X] Mutex): <-- [0x%08X] LOCKED",
      pthread_self(), self);
}

inline void unlockMutex(Mutex* self)
{
  LOG(LOGLEVEL, "([0x%08X] Mutex): ==> [0x%08X] UNLOCK",
      pthread_self(), self);
  (void)pthread_mutex_unlock(self);
  LOG(LOGLEVEL, "([0x%08X] Mutex): <== [0x%08X] UNLOCKED",
      pthread_self(), self);
}

inline void waitMutex(Mutex* self)
{
  LOG(LOGLEVEL, "([0x%08X] Mutex): >>> [0x%08X] WAIT", pthread_self(), self);
  lockMutex(self);
  unlockMutex(self);
  LOG(LOGLEVEL, "([0x%08X] Mutex): <<< [0x%08X] WAIT", pthread_self(), self);
}

inline int initCond(Cond *cond)
{
  LOG(LOGLEVEL, "([0x%08X] Condition):  >  [0x%08X] INIT",
      pthread_self(), cond );
  return (pthread_cond_init(cond, NULL) == 0);
}


inline int signalCond(Cond *cond)
{
  LOG(LOGLEVEL, "([0x%08X] Condition signal): --> to [0x%08X] ",
      pthread_self(), cond);
  return (pthread_cond_signal(cond));
}

/** Wait for time milliseconds. time - 0 = until notify called! */
inline int waitCond(Cond *cond, Mutex *self, uint32_t millis)
{
  if (millis > 0)
  {
    struct timespec to;
    memset(&to, 0, sizeof(to));

    // Fix BZ133
    long int stime = millis < 1000 ? 0 : millis / 1000;
    long int ntime = (millis < 1000 ? millis : millis % 1000) * 1000;

    to.tv_sec  = stime + time(0);
    to.tv_nsec = ntime;
    LOG(LEVEL_COMM, "([0x%08X] Condition wait): --> [0x%08X] at Mutex[0x%08x] "
                  "for %i milliseconds = (%i seconds! and %i nanoseconds)",
                  pthread_self(), cond, self, millis, stime, ntime);
    return pthread_cond_timedwait(cond, self, &to);
  }
  else
  {
    LOG(LEVEL_COMM, "([0x%08X] Condition wait): --> [0x%08X] at Mutex[0x%08x] ",
                   pthread_self(), cond, self);
    return pthread_cond_wait(cond, self);
  }
}

/**
 * Destroy the condition object
 *
 * @param cond the condition object
 *
 * @return the return value of the wrapped function pthread_cond_destroy.
 *
 * @since 0.3.0
 */
inline int destroyCond(Cond *cond)
{
  LOG(LOGLEVEL, "([0x%08X] Destroy Condition): --> to [0x%08X] ",
      pthread_self(), cond);
  return (pthread_cond_destroy(cond));
}

/**
 * wait for a given amount of milli seconds or forever if millis is 0
 *
 * @param sem_var The semaphor variable to wait on
 * @param millis The time in milli seconds
 */
inline int sem_wait_wrapper(sem_t *sem_var, uint32_t millis)
{
  if (millis > 0)
  {
    struct timespec to;
    memset(&to, 0, sizeof(to));

    // Fix BZ133
    long int stime = millis < 1000 ? 0 : millis / 1000;
    long int ntime = (millis < 1000 ? millis : millis % 1000) * 1000;

    to.tv_sec  = stime + time(0);
    to.tv_nsec = ntime;
    LOG(LOGLEVEL, "([0x%08X] Condition wait): --> [0x%08X] at Semaphor[0x%08x] "
                  "for %i milliseconds = (%i seconds! and %i nanoseconds)",
                  pthread_self(), sem_var, millis, stime, ntime);

    return sem_timedwait(sem_var, &to);
  }
  else
  {
    return sem_wait(sem_var);
  }
}
