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
 * Provides utilities for the BGP printer
 * 
 * @version 0.2.0.1
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 *  0.2.0.1 - 2016/06/24 - oborchert
 *            * Fixed printHex missing CR in case of empty data.
 *  0.1.1.0 - March 18, 2016 - borchert
 *            * Created File.
 */
#ifndef BGPPRINTERTOOLS_H
#define	BGPPRINTERTOOLS_H

#include <sys/types.h>
#include "bgp/BGPHeader.h"

#define BYTE_STR  "byte\0";
#define BYTES_STR "bytes\0";

/**
 * Print the data in hex format. This method prints at least one '\n'.
 * 
 * @param data The data to be printed
 * @param length The length of the data buffer
 * @param tab The tab to be used for each new line.
 */
void printHex(u_int8_t* data, int length, char* tab);

/**
 * Print the given prefix on the screen.
 * 
 * @param prefix The IP prefix.
 */
void printPrefix(BGPSEC_PrefixHdr* prefix);
#endif	/* BGPPRINTERTOOLS_H */

