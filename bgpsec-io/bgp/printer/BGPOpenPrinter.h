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
 * Contains functionality to print bgp open messages
 * 
 * @version 0.2.0.12
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 *  0.2.0.12- 2018/04/12 - oborchert
 *            * Added simple to printOpenData to allow a more simplistic 
 *              printing.
 *  0.2.0.7 - 2017/03/10 - oborchert
 *            * Added printCapability to the header file
 *          - 2017/02/25 - oborchert
 *            * Created File.
 */
#ifndef BGPOPENPRINTER_H
#define	BGPOPENPRINTER_H

#include <stdbool.h>
#include "bgp/BGPHeader.h"

/**
 * Print the BGP Update Message
 * 
 * @param openmsg The open message as complete BGP packet. 
 * @param simple If true, do not use the tree format as in wireshark
 * 
 */
void printOpenData(BGP_OpenMessage* openmsg, bool simple);

/** 
 * Print the Optional Parameter: Capability 
 * 
 * @param cap The Capability stream.
 * @param tabs The tab string to be prepended to each line printed.
 * @parma more Indicates if more capabilities are printed on the same level.
 * 
 * @return the number of bytes read from the capabilities stream.
 */
int printCapability(BGP_Capabilities* cap, const char* tabs, bool more);

#endif	/* BGPOPENPRINTER_H */

