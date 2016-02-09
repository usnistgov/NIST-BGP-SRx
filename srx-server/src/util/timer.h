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
 * Managed timers.
 * 
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 *            * Added Changelog
 * 0.1.0.0  - 2009/12/31 - pgleichm
 *            * Code created. 
 */

#ifndef __TIMER_H__
#define __TIMER_H__

#include <time.h>
#include <stdbool.h>

/**
 * Definition of the function that should be called upon the firing of a
 * alarm.
 *
 * @param now Current time (UNIX timestamp)
 * @see createTimer
 */
typedef void (*TimerExpired)(int id, time_t now);

/**
 * Sets up a new timer.
 *
 * @param callback Function that should be called upon the firing of the timer
 * @return Identifier of the new timer, or \c -1 in case of an error
 */
extern int setupTimer(TimerExpired callback);

/**
 * Deletes a timer.
 *
 * @note Also stops the timer if necessary
 *
 * @param id Timer identifier
 */
extern void deleteTimer(int id);

/**
 * Deletes all timers.
 *
 * @note Stops all timers
 */
extern void deleteAllTimers();

/**
 * Checks if the timer is active, i.e. will fire in the future.
 *
 * @param id Timer identifier
 * @return \c true = active, \c inactive
 */ 
extern bool isActiveTimer(int id);

/** 
 * Starts the timer with a timeout value of \c sec seconds.
 * The \c oneShot parameter specifies whether the timer should fire once
 * (= \c true), or multiple times.
 *
 * @param id Identifier
 * @param sec Seconds
 * @param oneShot Fire once
 * @see fireAbsoluteTimer
 */
extern void startIntervalTimer(int id, int sec, bool oneShot);

/** 
 * Starts the timer so that will be fired at a specific time in the future.
 *
 * @param id Identifier
 * @param future Unix-timestamp
 */
extern void startAbsoluteTimer(int id, time_t future);

/**
 * Stops a timer.
 *
 * @param id Identifer
 */
extern void stopTimer(int id);

#endif // !__TIMER_H__

