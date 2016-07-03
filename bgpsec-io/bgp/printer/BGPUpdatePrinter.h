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
 * Contains functionality to print update messages
 * 
 * @version 0.1.1.0
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 *  0.1.1.0 - 2016/03/25 - oborchert
 *            * Added function printBGPSEC_PathAttr to header
 *          - 2016/03/18 - borchert
 *            * Created File.
 */
#ifndef BGPUPDATEPRINTER_H
#define	BGPUPDATEPRINTER_H

#include <sys/types.h>
#include "bgp/BGPHeader.h"

/**
 * Print the BGPS Update Message
 * 
 * @param update The update message as complete BGP packet. 
 * 
 */
void printUpdateData(BGP_UpdateMessage_1* update);

/**
 * Print the BGPSEC Path attribute information
 * 
 * @param pa The BGP Path Attribute
 * @param tab The tabulator of this attribute. (if NULL then it will be replaced 
 *            with TAB_2
 * 
 * @return true if the attributes data was included in the print.
 */
bool printBGPSEC_PathAttr(BGPSEC_PathAttribute* pa, char* tab, bool more);

#endif	/* BGPUPDATEPRINTER_H */

