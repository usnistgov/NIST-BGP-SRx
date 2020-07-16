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
 * @version 0.2.0.21
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.2.0.21- 2018/06/07 - oborchert
 *            * Added parameter simple to function printBGPSEC_PathAttr
 * 0.2.0.12 - 2018/04/14 - oborchert
 *            * Added parameter received to method printBGP_Message.
 * 0.2.0.11 - 2018/03/23 - oborchert
 *            * Added AS_PATH printing (simple for now)
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
 * @param hdr The header to be printed.
 * @param isAS4 Indicates if AS numbers are 4 byte (true) or 2 byte (false)
 * @param simple Indicates if the BGP message should be printed in the simple 
 *               form (true) or Wireshark form (false).
 * @param received Indicates if the message is received (true) or send (false)
 */
void printBGP_Message(BGP_MessageHeader* hdr, bool isAS4, bool simple, 
                      bool received)
{
  // In case no specialized printer exists
  bool printData = false;
  u_int16_t length = ntohs(hdr->length);
  const char* txtReceived = simple
                            ? received ? PRN_SIMPLE_RECEIVE : PRN_SIMPLE_SEND
                            : received ? PRN_TXT_RECEIVED : PRN_TXT_SEND;
  
  // If we end up here, we want to print this particular received message.
  printf ("%s", txtReceived);
  
  if (!simple)
  {
    char* myTitle = (hdr->type == BGP_T_KEEPALIVE) ? "KEEPALIVE Message"
                    : (hdr->type == BGP_T_UPDATE) ? "UPDATE Message"
                    : (hdr->type == BGP_T_OPEN) ? "OPEN Message"
                    : (hdr->type == BGP_T_NOTIFICATION) ? "NOTIFICATION Message"
                    : "Unknown BGP Message";

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
  }
  switch (hdr->type)
  {
    case BGP_T_OPEN:
      if (!simple)
      {
        printf("(OPEN)\n");
      }
      printOpenData((BGP_OpenMessage*)hdr, simple);
      break;
    case BGP_T_NOTIFICATION:
      if (!simple)
      {
        printf("(NOTIFICATION)\n");
      }
      printNotificationData((BGP_NotificationMessage*)hdr, simple);
      break;
    case BGP_T_KEEPALIVE:
      if (!simple)
      {
        printf("(KEEPALIVE)\n");
      }
      else
      {
        printf("KEEPALIVE\n");        
      }
      break;
    case BGP_T_UPDATE:
      if (!simple)
      {
        printf("(UPDATE)\n");
      }
      printUpdateData((BGP_UpdateMessage_1*)hdr, isAS4, simple);
      break;
    default:
      if (!simple)
      {
        printf("(unknown)\n");   
        printData = true;
      }
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