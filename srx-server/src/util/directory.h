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
 * Directory helper functions.
 * 
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 *            * Added Changelog
 *            * Fixed speller in header documentation
 * 0.1.0.0  - 2010/04/26 - pgleichm
 *            * Created code.
 */
#ifndef __DIRECTORY_H__
#define __DIRECTORY_H__

#include <stdbool.h>

/**
 * Checks if a file is readable.
 *
 * @param path Path pointing to the file
 * @return \c true = is readable, \c false = does not exist/permisions
 */
bool fileIsReadable(const char* path);

#endif // !__DIRECTORY_H__

