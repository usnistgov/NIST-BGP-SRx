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
 * Provides functions to print the BGP header in detail.
 * 
 * @version 0.2.0.12
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.0.12- 2018/04/14 - oborchert
 *            * Added parametrer received to function printBGP_Message.
 *            * Removed define NO_WIRESHARK. It is replaced with printSimple. 
 *  0.2.0.11- 2018/03/23 - oborchert
 *            * Added AS_PATH printing (simple for now)
 *          - 2018/03/22 - oborchert
 *            * Added parameter isAS4 to printBGP_Message.
 *  0.2.0.7 - 2017/03/09 - oborchert
 *            * Removed individual printXXX_Message function with XXX equals the 
 *              message type.
 *            * Removed parameters 'title' and 'onlyHeader' from function 
 *              PrintBGP_Message
 *  0.0.1.0 - 2015/08/19 - oborchert
 *            * Created File.
 */
#ifndef BGPHEADERPRINTER_H
#define	BGPHEADERPRINTER_H

#include "bgp/BGPHeader.h"

/** Regular tabulator for printouts */
#define TAB_2   "  \0"
/** Tabulator for printouts with line */
#define TAB_3W  "  |\0" 
/** Tabulator for printouts without line */
#define TAB_3   "   \0" 
/** Maximum tab size */
#define TAB_MAX 20
/** String size. */
#define STR_MAX 256

/** Received value for function printBGP_Message */
#define BGPHP_MSG_RECEIVED true
/** Send value for function printBGP_Message */
#define BGPHP_MSG_SEND     false

/**
 * Print the BGP Header. This message allows to only print the generic header 
 * information or also the following information as hex byte stream
 * 
 * @param hdr The header to be printed.
 * @param isAS4 Indicates if AS numbers are 4 byte (true) or 2 byte (false)
 * @param simple indicates if the BGP message should be printed in the simple 
 *               form (true) or Wireshark form (false).
 * @param received Indicates if the message is received (true) or send (false)
 */
void printBGP_Message(BGP_MessageHeader* hdr, bool isAS4, bool simple, 
                      bool received);

#endif	/* BGPHEADERPRINTER_H */

