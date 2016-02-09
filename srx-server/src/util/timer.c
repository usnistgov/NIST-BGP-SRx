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
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Added Changelog
 *            * Fixed speller in documentation header
 *            * Added missing void to function setTimer
 * 0.1.0    - 2009/12/32 -pgleichm
 *            * Code created. 
 */
#include <stdio.h>
#include <signal.h>
#include <sys/time.h>
#include "util/slist.h"
#include "util/timer.h"
// @TODO: Check if still used of if already replaced by stock functions.
/**
 * A single timer
 */
typedef struct {
  int           id;
  bool          active;
  time_t        future; 
  int           interval;
  TimerExpired  callback;
} Timer;

/** Prevents that the timer-list gets reset */
static bool   _initialized = false;
/** List of all timers */
static SList  _timerList;
/** Id of the active timer */
static int    _activeId; 


static void setTimer(int sec) 
{
  struct itimerval  tv;

  timerclear(&tv.it_interval);
  tv.it_value.tv_usec = 0;
  tv.it_value.tv_sec  = sec;

  setitimer(ITIMER_REAL, &tv, NULL);
}

/**
 * Sets the alarm to the earliest timer.
 */
static void selectTimer() 
{
  time_t            min = 0;
  SListNode*        cnode;
  Timer*            tcurr, *tsel = NULL;

  // Search for the earliest time - a sorted list would be an alternative
  FOREACH_SLIST(&_timerList, cnode) 
  {
    tcurr = (Timer*)cnode->data;

    // Not an active timer - skip
    if (!tcurr->active) 
    {
      continue;
    }

    // Earlier than the previous timer(s)
    if ((tcurr->future < min) || (min == 0)) 
    {
      tsel = tcurr;
      min = tcurr->future;
    }
  }

  // A timer has been selected
  if (tsel != NULL) 
  {
    _activeId = tsel->id;
    setTimer(tsel->future - time(NULL));

  // No active timer
  } 
  else 
  {
    _activeId = -1;
  }
}

/** 
 * \c alarm function.
 *
 * @param _sig (unused) Signal
 */
static void alarmSignal(int sig) 
{
  if (_activeId > -1) 
  {
    Timer* t = getFromSList(&_timerList, _activeId);

    // Other signal was fired - restart the timer 
    if (sig != SIGALRM) 
    {
      setTimer(t->future - time(NULL));
    } 
    else 
    {
      // One shot timer - disable it
      if (t->interval == -1) 
      {
        t->active = false;
      } 
      else 
      {
        t->future += t->interval;
      }

      // Select a new timer
      selectTimer();

      // Call the handler
      t->callback(t->id, time(NULL));
    }
  }
}

/** 
 * Clears the \c alarm.
 */
static void clearAlarm() 
{
  struct itimerval tv;

  timerclear(&tv.it_value);
  setitimer(ITIMER_REAL, &tv, NULL);
}

int setupTimer(TimerExpired callback) 
{
  Timer*  t; 
 
  // No timer yet
  if (!_initialized) 
  {
    initSList(&_timerList);
    _initialized = true;
    _activeId    = -1;
    signal(SIGALRM, alarmSignal);
  }

  // Append the new timer structure
  t = appendToSList(&_timerList, sizeof(Timer));
  if (t == NULL) 
  {
    return -1;
  }

  t->id       = sizeOfSList(&_timerList) - 1;
  t->active   = false;
  t->callback = callback;

  return t->id;
}

void deleteTimer(int id) 
{
  Timer* t = getFromSList(&_timerList, id);
  if (t != NULL) 
  {
    stopTimer(id);
    deleteFromSList(&_timerList, t);
  }
}

void deleteAllTimers() 
{
  clearAlarm();
  releaseSList(&_timerList);
  _initialized = false;
}

bool isActiveTimer(int id) 
{
  Timer* t = getFromSList(&_timerList, id);
  return (t == NULL) ? false : t->active;
}

/**
 * Starts the timer, to fire in the a specific time.
 *
 * @param id Timer identifier
 * @param future When to fire (UNIX timestamp)
 * @param interval Fire again afer \c internval seconds, \c -1 = only once
 */
static void startTimer(int id, time_t future, int interval) 
{
  Timer* t;

  // Active timer - then deactivate it first
  if (_activeId == id) 
  {
    clearAlarm();
  }

  // Store the parameters
  t = getFromSList(&_timerList, id);
  if (t != NULL) 
  {
    t->future   = future;
    t->interval = interval;
    t->active   = true;

    selectTimer();  
  }
}

void startIntervalTimer(int id, int sec, bool oneShot) 
{
  startTimer(id, time(NULL) + sec, oneShot ? -1 : sec);
}

void startAbsoluteTimer(int id, time_t future) 
{
  if (future > time(NULL)) 
  {
    startTimer(id, future, -1);
  }
}

void stopTimer(int id) 
{
  Timer* t;

  // The given timer is the active timer
  if (_activeId == id) 
  {
    // Deactivate first
    clearAlarm();

    // Set to inactive and select a new timer
    t = getFromSList(&_timerList, id);
    t->active = false;
    selectTimer();

  // Not the active timer
  } 
  else 
  {
    t = getFromSList(&_timerList, id);
    if (t != NULL) 
    {
      t->active = false;
    }
  }
}