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
 * @version 0.2.0.0
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
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
#include "BGPPrinterUtil.h"

/**
 * Print the BGP Header. This message allows to only print the generic header 
 * information or also the following information as hex byte stream
 * 
 * @param hdr The header to be printed
 * @param title a possible title, if NULL a generic title will be generated.
 * @param headerOnly indicates if just the generic header should be printed or
 *        the complete header.
 */
void printBGP_Message(BGP_MessageHeader* hdr, char* title, bool headerOnly)
{
  char* myTitle = (title == NULL) ? "BGP Message" : title;
  u_int16_t length = ntohs(hdr->length);
  
  printf("%s\n", myTitle);
  printf("%s+--marker: ", TAB_2);
  int idx;
  for (idx = 0; idx < BGP_MARKER_SIZE; idx++)
  {
    printf("%02X", hdr->marker[idx]);
  }
  printf("\n");
  printf("%s+--length: %u\n", TAB_2, length);
  printf("%s+--type:   %u ", TAB_2, hdr->type);
  switch (hdr->type)
  {
    case BGP_T_OPEN:
      printf("(OPEN)\n");
      break;
    case BGP_T_NOTIFICATION:
      printf("(NOTIFICATION)\n");
      if (!headerOnly)
      {
        printNotificationData((BGP_NotificationMessage*)hdr);
        headerOnly = true;
      }
      break;
    case BGP_T_KEEPALIVE:
      printf("(KEEPALIVE)\n");
      break;
    case BGP_T_UPDATE:
      printf("(UPDATE)\n");
      if (!headerOnly)
      {
        printUpdateData((BGP_UpdateMessage_1*)hdr);
        headerOnly = true;
      }
      break;
    default:
      printf("(unknown)\n");   
  }
  
  if (!headerOnly)
  {
    char dataStr[STR_MAX];
    snprintf(dataStr, STR_MAX, "%s+--data:   ", TAB_2);
    printf ("%s", dataStr);
    memset (dataStr, ' ', strlen(dataStr));
    
    u_int8_t* data = (u_int8_t*)hdr + sizeof(BGP_MessageHeader);
    length -= sizeof(BGP_MessageHeader);
    if (length != 0)
    {
      printHex(data, length, dataStr);
    }
    else
    {
      printf("(no data)\n");
    }
  }
}

/**
 * Print the given header in tree format.
 * 
 * @param hdr the OpenMessage header.
 */
void printBGP_Open(BGP_OpenMessage* hdr)
{
  printBGP_Message((BGP_MessageHeader*)hdr, "Open Message", false);
}

/**
 * Print the given header in tree format.
 * 
 * @param hdr the OKeepAliveMessage header.
 */
void printBGP_KeepAlive(BGP_KeepAliveMessage* hdr)
{
  printBGP_Message((BGP_MessageHeader*)hdr, "KeepAlive Message", false);  
}

/**
 * Print the given header in tree format.
 * 
 * @param hdr the NotificationMessage header.
 */
void printBGP_Notification(BGP_NotificationMessage* hdr)
{
  printBGP_Message((BGP_MessageHeader*)hdr, "Notification Message", false);  
}

/**
 * Print the given header in tree format.
 * 
 * @param hdr the UpdateMessage header.
 */
void printBGP_Update(BGP_UpdateMessage_1* hdr)
{
  printBGP_Message((BGP_MessageHeader*)hdr, "Update Message", false);  
}

