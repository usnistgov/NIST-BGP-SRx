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
 * Provides a printer for RPKI Router to Cache Protocol Packages. 
 * Supports RFC6810 and RFC8210 package formats.
 *
 * @version 0.6.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.6.0.0  - 2021/02/17 - oborchert
 *            * Fixed speller in T4_FLAG_01_1
 *          - 2021/02/08 - oborchert
 *            * Modified T4_FLAG... to accommodate ASPA processing
 * 0.5.0.3  - 2018/02/26 - oborchert
 *            * File created
 */
#ifndef RPKI_PACKET_PRINTER_H
#define RPKI_PACKET_PRINTER_H

#include <stdbool.h>
#include "shared/rpki_router.h"

#define T4_FLAG_0 ""
#define T4_FLAG_1 "**UNDEFINED**"
#define T4_FLAG_80_0 T4_FLAG_0
#define T4_FLAG_80_1 T4_FLAG_1
#define T4_FLAG_40_0 T4_FLAG_0
#define T4_FLAG_40_1 T4_FLAG_1
#define T4_FLAG_20_0 T4_FLAG_0
#define T4_FLAG_20_1 T4_FLAG_1
#define T4_FLAG_10_0 T4_FLAG_0
#define T4_FLAG_10_1 T4_FLAG_1
#define T4_FLAG_08_0 T4_FLAG_0
#define T4_FLAG_08_1 T4_FLAG_1
#define T4_FLAG_04_0 T4_FLAG_0
#define T4_FLAG_04_1 T4_FLAG_1
#define T4_FLAG_02_0 T4_FLAG_0
#define T4_FLAG_02_1 T4_FLAG_1
#define TA_FLAG_02_0 "(AFI IPv4)"
#define TA_FLAG_02_1 "(AFI IPv6)"
#define T4_FLAG_01_0 "(withdrawal)"
#define T4_FLAG_01_1 "(announcement)"

/**
 * Create a wireshark like printout of the received rpki-to-rtr PDU. This method
 * supports PDU types of RFC6810 and RFC 8210
 * 
 * @param user NOT USED, can be NULL.
 * @param pdu The rpki-to-rtr PDU to be printed.
 * 
 * @since 0.5.0.3
 */
bool doPrintRPKI_to_RTR_PDU(void* user, RPKICommonHeader* pdu);

#endif /* RPKI_PACKET_PRINTER_H */

