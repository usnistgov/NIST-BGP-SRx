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
 * NOTE:
 * Functions starting with underscore are only to be called from within this
 * file. Therefore no additional checking is needed is some provided values
 * are NULL. entry functions specified in the header file do take cate of that.
 * 
 * 
 * This utility provides helper functions to convert a TCP BGP Hex dump into a 
 * binary stream or extract the BGPsec_PATH from a BGP UPDATE and possible
 * other functions related to BGPsec.
 * 
 * @version 0.1.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.1.0.0 - 2017/06/27 - oborchert 
 *           * File created
 */
#ifndef BGPSEC_UTIL_H
#define BGPSEC_UTIL_H

#include <sys/types.h>

/**
 * Use the given byte stream input (as hex string) and extract the 
 * BGPsec_PATH attribute out of it.
 * 
 * @param updateStr The HEX ASCII representation of the BGPsec UPDATE.
 * @param buffLen A pointer to an integer which will be filled with the 
 *                total length of the attribute. (Can be NULL)
 * 
 * @return  The buffer containing the BGPsec_PATH attribute. Must be frees 
 *          by caller.
 */
u_int8_t* util_getBGPsec_PATH(char* updateStr, u_int32_t* buffLen);


#endif /* BGPSEC_UTIL_H */

