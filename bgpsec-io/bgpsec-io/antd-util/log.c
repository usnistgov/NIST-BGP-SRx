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
 * @version 0.3.0.7
 *
 * ChangeLog:
 * -----------------------------------------------------------------------------
 * 0.3.0.7 - 2015/04/21 - oborchert
 *           * Added ChangeLog.
 * 0.1.1.0 - 2010/06/25 - borchert
 *           * Added level WARNING
 *             A wonderful description on how and when to use each level can be 
 *             found at: 
 *             http://www.kiwisyslog.com/kb/info:-syslog-message-levels/
 * 0.1.0.0 - 2009/12/28 - pgleichm
 *           * Code Created
 * -----------------------------------------------------------------------------
 */
#include <time.h>
#include <syslog.h>
#include "log.h"

/*----------
 * Constants
 */

#define TIMESTAMP_MAX_LEN 18
#define TIMESTAMP_FORMAT  "%D %I:%M.%S"

static const char* LOG_LEVEL_TEXT[] = {
     "EMERGENCY",
     "CRITICAL",
     "  ALERT", // 0-2
     "  ERROR", // 3:LEVEL_ERROR
     "WARNING", // 4:LEVEL_WARNING
     "   NOTE", // 5:LEVEL_NOTICE
     "   INFO", // 6:LEVEL_INFO
     "  DEBUG"  // 7:LEVEL_DEBUG
};

/*-----------------
 * Global variables
 */

static LogLevel _activeLevel = LEVEL_DEBUG;
static char _tsBuf[TIMESTAMP_MAX_LEN];
static LogMessagePosted _callback = NULL;

/*--------------------
 * "_write*" variables
 */

static FILE* _stream;
static char* _buffer;
static size_t _bufMax;

/*--------------------------
 * Internal _write functions
 */

/**
 * Writes a single message to the registered stream.
 *
 * @note LogMessagePosted syntax
 *
 * @param fmt Format string
 * @param args Arguments
 */
static void _writeToFile (LogLevel level, const char* fmt, va_list args)
{
  fprintf(_stream, "%s ", LOG_LEVEL_TEXT[level]);
  vfprintf(_stream, fmt, args);
  fputc('\n', _stream);
}

/**
 * Writes a single message to syslog.
 *
 * @note LogMessagePosted syntax
 *
 * @param fmt Format string
 * @param args Arguments
 */
static void _writeToSyslog (LogLevel level, const char* fmt, va_list args)
{
  vsyslog((int) level, fmt, args);
}

/**
 * Writes a single error message into the registered buffer.
 *
 * @note LogMessagePosted syntax
 *
 * @param fmt Format string
 * @param args Arguments
 */
static void _writeToBuffer (LogLevel level, const char* fmt, va_list args)
{
  size_t cw = snprintf(_buffer, _bufMax, "%s ", LOG_LEVEL_TEXT[level]);
  vsnprintf(_buffer + cw, _bufMax - cw, fmt, args);
}

/*
 * SetLogMethod* functions
 */
void setLogMethodToFile (FILE* stream)
{
  _stream = stream;
  _callback = (_stream != NULL) ? _writeToFile : NULL;
}

void setLogMethodToSyslog ()
{
  _callback = _writeToSyslog;
}

void setLogMethodToBuffer (char* buffer, size_t max)
{
  _buffer = buffer;
  _bufMax = max;
  _callback = ((buffer != NULL) && (max > 0)) ?
  _writeToBuffer : (LogMessagePosted) NULL;
}

void setLogMethodToCallback (LogMessagePosted cb)
{
  _callback = cb;
}

/*
 * Misc.
 */
void setLogLevel (LogLevel level)
{
  _activeLevel = level;
}

/**
 * Return the selected log level
 * 
 * @return the log level
 * 
 * @since 0.3.0
 */
LogLevel getLogLevel()
{
  return _activeLevel;
}

/*
 * Write a log entry if the given log level is activated.
 *
 * @param level of this log entry
 * @param fmt The format string
 * @param ... Format elements.
 */
void writeLog (LogLevel level, const char* fmt, ...)
{
  if ((_callback != NULL) && (level <= _activeLevel))
  {
    va_list al;

    va_start(al, fmt);
    _callback(level, fmt, al);
    va_end(al);
  }
}

/**
 * Generate the timestamp
 *
 * @return The current timestamp as formated string.
 */
const char* logTimeStamp ()
{
  time_t now = time(NULL);
  struct tm ret_tm;
  strftime(_tsBuf, TIMESTAMP_MAX_LEN, TIMESTAMP_FORMAT, localtime_r(&now, &ret_tm)); //--> error in quagga, due to localtime  *change into localtime_r() --KH--
  return (const char*) _tsBuf;
}

