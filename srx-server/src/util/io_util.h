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
 * This file contains utility functions for reading from standard input.
 *  
 * @version 0.5.0.0
 *
 * ChangeLog:
 * -----------------------------------------------------------------------------
 * 0.5.0.0  - 2017/06/16 - oborchert
 *            * Version 0.4.1.0 is trashed and moved to 0.5.0.0
 *          - 2018/08/30 - oborchert
 *           * Code Created
 * -----------------------------------------------------------------------------
 */
#ifndef IO_UTIL_H
#define IO_UTIL_H

#include <stdbool.h>

/**
 * Poll the standard input to see if something is waiting on the standard in.
 * 
 * @param sec seconds to wait
 * @param msec milli seconds to wait
 * 
 * @return true if data is ready, otherwise false.
 */
bool au_checkSTDIN(int sec, int msec);

/**
 * Read a character from the standard in.
 * 
 * @param stopper The boolean variable that allows to unblock the function call.
 * @param nullValue The value used as NULL value/
 * 
 * @return The value read from standard in or the configured NULL value.
 */
char au_getchar(bool* stopper, char nullValue);

#endif /* IO_UTIL_H */

