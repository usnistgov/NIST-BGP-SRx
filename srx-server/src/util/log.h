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
 * This file contains functions and macros for logging output. It is recommended 
 * to set the log method at the beginning of the application - otherwise 
 * eventual message will be discarded.
 *  
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 * 0.3.0.7  - 2015/04/21 - oborchert
 *            * Added ChangeLog.
 * 0.1.1.0  - 2010/06/25 - borchert
 *            * Added level WARNING
 *              A wonderful description on how and when to use each level can be 
 *              found at: 
 *              http://www.kiwisyslog.com/kb/info:-syslog-message-levels/
 * 0.1.0.0  - 2009/12/28 - pgleichm
 *            * Code Created
 * -----------------------------------------------------------------------------
 */
#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

/** 
 * Log levels.
 * The code corresponds to the syslog levels.
 * 
 */
typedef enum {
  /** Non-urgent failures - these should be relayed to developers or admins; 
   * each item must be resolved within a given time */
  LEVEL_ERROR   = 3,
  /** Warning messages - not an error, but indication that an error will occur
   * if action is not taken, e.g. file system 85% full - each item must be 
   * resolved within a given time */
  LEVEL_WARNING = 4,  
  /** Events that are unusual but not error conditions - might be summarized in
   * an email to developers or admins to spot potential problems - no immediate
   * action required */
  LEVEL_NOTICE  = 5,
  /** Normal operational messages - may be harvested for reporting, measuring 
   * throughput, etc - no action required */
  LEVEL_INFO    = 6,
  /** Info useful to developers for debugging the application, not useful during
   * operations */
  LEVEL_DEBUG   = 7,
  LEVEL_COMM   = 8
} LogLevel;

/** 
 * Function that is called when a log message has been received.
 *
 * @param fmt Format string (ala printf)
 * @param args Variable number of arguments
 * @see setLogMethodToCallback
 */
typedef void (*LogMessagePosted)(LogLevel level, const char* fmt, va_list args);

/**
 * Sets the log method to 'FILE' mode, i.e. all messages will be written 
 * to a stream.
 *
 * @param stream Target file-stream for the messages
 */

extern void setLogMethodToFile(FILE* stream);

/** 
 * Sets the log method to syslog, i.e. all messages will be send to syslog.
 */
extern void setLogMethodToSyslog();

/** 
 * Sets the log method to 'BUFFER' mode, i.e. the last message will be in
 * the buffer.
 *
 * @param buffer (out) Target buffer
 * @param max Maximum message length
 */
extern void setLogMethodToBuffer(char* buffer, size_t max);

/** 
 * Sets the log method to 'CALLBACK' mode, i.e. for each message the given
 * function will be called.
 *
 * Example:
 * @code
 * static void myLogCallback(LogLevel level, const char* fmt, va_list args) {
 *   :
 * }
 * int main(...) {
 *   setLogMethodToCallback(myLogCallback);
 *   :
 * }
 * @endcode
 *
 * @param cb An LogMessagePosted callback
 */
extern void setLogMethodToCallback(LogMessagePosted cb);

/**
 * Suppresses all messages below the given level.
 *
 * @param level Level
 */
extern void setLogLevel(LogLevel level);

/**
 * Return the selected log level
 * 
 * @return the log level
 * 
 * @since 0.3.0
 */
extern LogLevel getLogLevel(); 

/**
 * Writes a single message. 
 * The function syntax is similar to 'printf'.
 *
 * @note Use the LOG, RAISE_ERROR, or RAISE_SYS_ERROR macros instead of calling 
 *    this function directly!
 *
 * @param level Log level
 * @param fmt Format string
 * @param ... Additional arguments
 */
extern void writeLog(LogLevel level, const char* fmt, ...);

/**
 * Returns the current date and time as a string.
 *
 * @note Primarily for internal use
 *
 * @return Timestamp
 */
extern const char* logTimeStamp();

/*-------
 * Macros
 */

/** See writeLog. */
#define LOG(LEVEL, FMT, ...) \
  writeLog(LEVEL, "[%s] " FMT, logTimeStamp(), ## __VA_ARGS__)

#define STRINGIFY_ARG(ARG) #ARG
#define STRINGIFY_IND(ARG) STRINGIFY_ARG(ARG)

#define FILE_LINE_INFO "(" __FILE__ ":" STRINGIFY_IND(__LINE__) ")"

//#define ERROR_LEAD "[%s] %s (" __FILE__ ":" STRINGIFY_IND(__LINE__) ") "
#define ERROR_LEAD "[%s] %s " FILE_LINE_INFO " "

/** Raises an error - simply a writeLog(LEVEL_ERROR, ...) shortcut */
#define RAISE_ERROR(FMT, ...) \
  writeLog(LEVEL_ERROR, ERROR_LEAD FMT, logTimeStamp(), \
           __func__,  ## __VA_ARGS__)

/**
 * Raises a system error. It uses errnum to determine the exact, detailed 
 * error messages.
 *
 * @param FMT \c printf like format string
 * @param ... arguments
 *
 * @see raiseError
 */
#define RAISE_SYS_ERROR(FMT, ...) \
  writeLog(LEVEL_ERROR, ERROR_LEAD FMT " - %s", logTimeStamp(), \
           __func__, ## __VA_ARGS__, strerror(errno))

#endif // !__LOG_H__

