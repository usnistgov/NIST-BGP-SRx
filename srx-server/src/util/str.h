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
 * String (0-terminated) helper functions.
 *
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 * 0.2.0    - 2011/01/07 - oborchert
 *            * Changelog added with version 0.2.0 and date 2011/01/07
 *            * Version tag added
 *            * Added trim, trim_right, trim_left
 * 0.1.0    - 2010/07/28 - pgleichm
 *            * Code Created
 * -----------------------------------------------------------------------------
 *
 */
#ifndef __STR_H__
#define __STR_H__
// @TODO: Check if it cam be replaced by stock string functions.
/**
 * Removes the line-break and other white-space characters from the end of
 * a given string.
 *
 * @param str Text (will be modified)
 * @return \c str 
 */
char* chomp(char* str);

/**
 * Removes the white-space characters from both sides of the string.
 *
 * @param str Text (will be modified)
 * @return \c str
 */
char* trim(char* str);

/**
 * Removes the white-space characters from right side of the string.
 *
 * @param str Text (will be modified)
 * @return \c str
 */
char* rtrim(char* str);

/**
 * Removes the white-space characters from left side of the string.
 *
 * @param str Text (will be modified)
 * @return \c str
 */
char* ltrim(char* str);

#endif // !__STR_H__

