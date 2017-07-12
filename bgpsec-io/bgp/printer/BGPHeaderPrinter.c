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
 * Print BGP Headers in tree format
 * 
 * @version 0.2.0.8
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.0.8 - 2017/06/21 - oborchert
 *            * BZ1163: Changed packed names to upper case to conform with 
 *              RFC 4271
 *  0.2.0.7 - 2017/03/10 - oborchert
 *            * Removed '+--data (no data)' printout.
 *            * Modified tree formating.
 *          - 2017/03/09 - oborchert
 *            * Removed individual printXXX_Message function with XXX equals the 
 *              message type.
 *            * Removed parameters 'title' and 'headerOnly' from function 
 *              PrintBGP_Message
 *          - 2017/03/02 - oborchert
 *            * Added printing of open messages.
 *  0.2.0.0 - 2016/05/12 - oborchert
 *            * Fixed package printout in case no data is available.
 *  0.1.0.0 - 2015/08/19 - oborchert
 *            * Created File.
 */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "bgp/printer/BGPHeaderPrinter.h"
#include "bgp/printer/BGPUpdatePrinter.h"
#include "bgp/printer/BGPNotificationPrinter.h"
#include "bgp/printer/BGPOpenPrinter.h"
#include "BGPPrinterUtil.h"

/**
 * Print the BGP Header. This message allows to only print the generic header 
 * information or also the following information as hex byte stream
 * 
 * @param hdr The header to be printed
 */
void printBGP_Message(BGP_MessageHeader* hdr)
{
  char* myTitle = (hdr->type == BGP_T_KEEPALIVE) ? "KEEPALIVE Message"
                  : (hdr->type == BGP_T_UPDATE) ? "UPDATE Message"
                  : (hdr->type == BGP_T_OPEN) ? "OPEN Message"
                  : (hdr->type == BGP_T_NOTIFICATION) ? "NOTIFICATION Message"
                  : "Unknown BGP Message";
  u_int16_t length = ntohs(hdr->length);
  // In case no specialized printer exists
  bool printData = false;
  
  printf("%s\n", myTitle);
  printf("%s+--marker: ", TAB_2);
  int idx;
  for (idx = 0; idx < BGP_MARKER_SIZE; idx++)
  {
    printf("%02X", hdr->marker[idx]);
  }
  printf("\n");
  printf("%s+--length: %u\n", TAB_2, length);
  printf("%s+--type: %u ", TAB_2, hdr->type);
  switch (hdr->type)
  {
    case BGP_T_OPEN:
      printf("(OPEN)\n");
      printOpenData((BGP_OpenMessage*)hdr);
      break;
    case BGP_T_NOTIFICATION:
      printf("(NOTIFICATION)\n");
      printNotificationData((BGP_NotificationMessage*)hdr);
      break;
    case BGP_T_KEEPALIVE:
      printf("(KEEPALIVE)\n");
      break;
    case BGP_T_UPDATE:
      printf("(UPDATE)\n");
      printUpdateData((BGP_UpdateMessage_1*)hdr);
      break;
    default:
      printf("(unknown)\n");   
      printData = true;
  }
  
  // In case the payload was not taken care of, add it here
  if (printData)
  {
    u_int8_t* data = (u_int8_t*)hdr + sizeof(BGP_MessageHeader);
    length -= sizeof(BGP_MessageHeader);
    if (length != 0)
    {
      char dataStr[STR_MAX];
      snprintf(dataStr, STR_MAX, "%s+--data: ", TAB_2);
      printf ("%s", dataStr);
      memset (dataStr, ' ', strlen(dataStr));
    
      printHex(data, length, dataStr);
    }
  }
}