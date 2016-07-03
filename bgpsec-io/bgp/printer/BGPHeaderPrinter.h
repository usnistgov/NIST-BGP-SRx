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
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *   0.1.0 - August 19, 2015 - oborchert
 *           * Created File.
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

/**
 * Print the BGP Header. This message allows to only print the generic header 
 * information or also the following information as hex byte stream
 * 
 * @param hdr The header to be printed
 * @param title a possible title, if NULL a generic title will be generated.
 * @param headerOnly indicates if just the generic header should be printed or
 *        the complete header.
 */
void printBGP_Message(BGP_MessageHeader* hdr, char* title, bool headerOnly);

/**
 * Print the given header in tree format.
 * 
 * @param hdr the OpenMessage header.
 */
void printBGP_Open(BGP_OpenMessage* hdr);

/**
 * Print the given header in tree format.
 * 
 * @param hdr the OKeepAliveMessage header.
 */
void printBGP_KeepAlive(BGP_KeepAliveMessage* hdr);

/**
 * Print the given header in tree format.
 * 
 * @param hdr the NotificationMessage header.
 */
void printBGP_Notification(BGP_NotificationMessage* hdr);

/**
 * Print the given header in tree format.
 * 
 * @param hdr the UpdateMessage header.
 */
void printBGP_Update(BGP_UpdateMessage_1* hdr);

#endif	/* BGPHEADERPRINTER_H */

