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
 * @version 0.2.0.21
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 *  0.2.0.21- 2018/06/07 - oborchert
 *            * Added parameter simple to function printBGPSEC_PathAttr
 *  0.2.0.20- 2018/05/02 - oborchert
 *            * Added define for RPN_SIMPLE_CA
 *  0.2.0.13- 2018/04/17 - oborchert
 *            * Split PRN_SIMPLE_PREFIX into PRN_SIMPLE_PREFIX_A 
 *              and PRN_SIMPLE_PREFIX_W
 *  0.2.0.12- 2018/04/14 - oborchert
 *            * Added PRN_SIMPLE_... defines for simple printout.
 *  0.2.0.11- 2018/03/23 - oborchert
 *            * Added AS_PATH printing (simple for now)
 *          - 2018/03/22 - oborchert
 *            * Added parameter isAS4 to printUdateData.
 *  0.2.0.5 - 2016/11/01 - oborchert
 *            * Adjusted the signature of the method printBGPSEC_PathAttr to
 *              use BGP_PathAttr as parameter.
 *  0.1.1.0 - 2016/03/25 - oborchert
 *            * Added function printBGPSEC_PathAttr to header
 *          - 2016/03/18 - oborchert
 *            * Created File.
 */
#ifndef BGPUPDATEPRINTER_H
#define	BGPUPDATEPRINTER_H

#include <sys/types.h>
#include "bgp/BGPHeader.h"

/** String prefix for the IP prefix announcement. */
#define PRN_SIMPLE_PREFIX_A  "+PFX: \0"
/** String prefix for the IP prefix withdrawal. */
#define PRN_SIMPLE_PREFIX_W  "-PFX: \0"
/** String prefix for the AS path. */
#define PRN_SIMPLE_ASPATH    "ASP: \0"
/** String prefix for the AS4 path. */
#define PRN_SIMPLE_AS4PATH   "A4P: \0"
/** String prefix for the BGPsec secure path. */
#define PRN_SIMPLE_SECPATH   "BSP: \0"
/** String prefix for the Extended community attribute. */
#define PRN_SIMPLE_ECA       "ECA: \0"
/** String prefix for the community attribute*/
#define PRN_SIMPLE_CA        "CA: \0"
/** String for simple received. */
#define PRN_SIMPLE_RECEIVE   "< \0"
/** String for simple send. */
#define PRN_SIMPLE_SEND      "> \0"
/** String for regular received. */
#define PRN_TXT_RECEIVED     "Received:\n\0"
/** String for regular send. */
#define PRN_TXT_SEND         "Send:\n\0"

/**
 * Print the BGPS Update Message
 * 
 * @param update The update message as complete BGP packet. 
 * @param isAS4 Indicates that 4 byte AS numbers are understood in AS_PATH
 * @param simple Indicates if the update has to be printed in a simple form,
 *               not Wireshark like.
 */
void printUpdateData(BGP_UpdateMessage_1* update, bool isAS4, bool simple);

/**
 * Print the BGPSEC Path attribute information
 * 
 * @param pa The BGP Path Attribute
 * @param tab The tabulator of this attribute. (if NULL then it will be replaced 
 *            with TAB_2
 * @param simple Indicates if the simple printer has to be used.
 * @param more Identifies if more attributes re to come.
 * 
 * @return true if the attributes data was included in the print.
 */
bool printBGPSEC_PathAttr(BGP_PathAttribute* pa, char* tab, bool simple, 
                          bool more);

#endif	/* BGPUPDATEPRINTER_H */

