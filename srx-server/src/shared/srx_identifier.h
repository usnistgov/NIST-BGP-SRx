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
 * @version 0.4.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.4.0.0  - 2016/06/19 - oborchert
 *            * Changed the input parameters of the ID generation. 
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Added Changelog
 *            * Fixed speller in documentation header
 * 0.1.0    - 2011/05/03 -oborchert
 *            * Code created. 
 */

#include <stdint.h>
#include "util/prefix.h"
#include "srx_defs.h"

#ifndef SRX_IDENTIFIER_H
#define	SRX_IDENTIFIER_H

/**
 * This particular method generates an ID out of the given data using a simple
 * CRC32 algorithm. All data is used as is, no tranformation from host to
 * network and vice versa is performed.
 *
 * @param originAS The origin AS of the data
 * @param prefix The prefix to be announced (IPPrefix)
 * @param data The bgpsec data object which contains the BGP4 path as well.
 *
 * @return return an ID.
 * 
 */
uint32_t generateIdentifier(uint32_t originAS, IPPrefix* prefix, 
                            BGPSecData* data);


#endif	/* SRX_IDENTIFIER_H */

