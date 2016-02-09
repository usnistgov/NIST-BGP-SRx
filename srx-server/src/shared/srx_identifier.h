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
 * 0.1.0    - 2011/05/03 -oborchert
 *            * Code created. 
 */

#include <stdint.h>
#include "util/prefix.h"

#ifndef SRX_IDENTIFIER_H
#define	SRX_IDENTIFIER_H

/**
 * This method generates an ID out of the given data.
 *
 * @param originAS The origin AS of the data
 * @param prefix The prefix to be announced (IPPrefix)
 * @param dataLength the length of the following data blob
 * @param data The data blob.
 *
 * @return return an ID.
 */
uint32_t generateIdentifier(uint32_t originAS, IPPrefix* prefix,
                            uint32_t blobLength, void* blob);


#endif	/* SRX_IDENTIFIER_H */

