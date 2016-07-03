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
 *
 * @version 0.4.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.4.0.0  - 2016/06/19 - oborchert
 *            * moved up to version 0.4.0.0 to be synched with header file.
 * 0.3.0.10 - 2015/11/10 - oborchert
 *            * Removed unused static function sappendf
 *          - 2015/11/09 - oborchert
 *            * Added Changelog
 *            * Fixed speller in documentation header
 * 0.1.0    - 2010/04/28 -pgleichm
 *            * Code created. 
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <srx/srxcryptoapi.h>
#include "shared/srx_packets.h"
#include "util/debug.h"
#include "util/prefix.h"

static const char* PACKET_TYPES[PDU_SRXPROXY_UNKNOWN + 1] = {
  "Hello",
  "Hello_Response",
  "Goodbye",
  "Verify_IPv4",
  "Verify_IPv6",
  "Request_Receipt",
  "Delete_Update",
  "Synch_Request",
  "Verification_Notification",
  "Signature_Notification",
  "Error",
  "Unknown"
};

/**
 * Returns the string of the given packet type or NULL
 *
 * @param type the packet type
 * @return The string representation or NULL
 */
const char* packetTypeToStr(SRxProxyPDUType type)
{
  if (type <= PDU_SRXPROXY_UNKNOWN)
  {
    return PACKET_TYPES[type];
  }
  else
  {
    return NULL;
  }
}
