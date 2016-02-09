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
 * by thsi software.
 *
 * Various function to make debugging easier.
 *
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 *            * Added Changelog
 * 0.1.0.0  - 2009/12/28 - pgleichm
 *            * Created code.
 */
#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdio.h>
#include <stdbool.h>

/**
 * Writes a hexdecimal representation of data to a stream (e.g. stdout).
 *
 * @param stream File handle
 * @param data Data
 * @param size Data size in Bytes
 */
extern void dumpHex(FILE* stream, void* data, int size);

/**
 * Writes a string to a file. If the file with the same filename already 
 * exists, then it is either overwritten (\c append = \c false) or the
 * string is appended (\c append = \c true).
 *
 * @param filename Output file
 * @param append Append or overwrite
 * @param str String
 * @return \c true = written successfully, \c false = an I/O error occurred
 */
extern bool stringToFile(const char* filename, bool append, const char* str);

#endif // !__DEBUG_H__

