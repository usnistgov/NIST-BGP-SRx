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
 * Provides Utility function for the BGP printer
 * 
 * @version 0.2.0.1
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 *  0.2.0.1 - 2016/06/24 - oborchert
 *            * Fixed printHex missing CR in case of empty data.
 *  0.2.0.0 - 2016/05/10 - oborchert
 *            * Fixed a formating error in printPrefix BZ950
 *  0.1.1.0 - 2016/03/25 - oborchert
 *            * Added stopper in case the print length is negative
 *          - 2016/03/18 - oborchert
 *            * Created File.
 */

#include <stdio.h>
#include <stdbool.h>
#include "bgp/printer/BGPPrinterUtil.h"
#include "cfg/configuration.h"

/**
 * Print the data in hex format. This method prints at least one '\n'.
 * 
 * @param data The data to be printed
 * @param length The length of the data buffer
 * @param tab The tab to be used for each new line.
 */
void printHex(u_int8_t* data, int length, char* tab)
{
  bool printCR = length <= 0;
  int idx = 1;
  
  if (tab == NULL)
  {
    tab = "\0";
  }
  
  for (; idx <= length; idx++)
  {
    printf("%02X ", *data);
    printCR = true;
    if ((idx % 16) == 0)
    {
      printf ("\n");
      if (idx+1 < length)
      {
        printf ("%s", tab);
      }
      printCR = false;
    }
    else if ((idx % 8) == 0)
    {
      printf("  ");
    }

    data++;
  }
  
  if (printCR)
  {
    printf("\n");
  }
}

/**
 * Print the given prefix on the screen.
 * 
 * @param prefix The IP prefix.
 */
void printPrefix(BGPSEC_PrefixHdr* prefix)
{
  u_int16_t afi = (prefix->afi & 0xFF00) ? ntohs(prefix->afi) : prefix->afi;
  BGPSEC_V4Prefix* v4 = NULL;
  BGPSEC_V4Prefix* v6 = NULL;
  
  printf("Prefix: \n");
  printf("  +-----afi:    %d ", afi);  
  switch (afi)
  {
    case AFI_V4:
      printf("(IPv4)\n");  
      v4 = (BGPSEC_V4Prefix*)prefix;
      break;
    case AFI_V6:
      printf("(IPv6)\n");  
      v6 = (BGPSEC_V4Prefix*)prefix;
      break;
    default:
      printf ("ERROR: Invalid Prefix type '%d'.\n", afi);
      return;
  }
  printf("  +-----safi:   %d\n", prefix->safi);  
  printf("  +-----length: %d\n", prefix->length);  
  printf("  +-----data:   ");  
  if (v4)
  {
    printf("%d.%d.%d.%d/%d\n", v4->addr[0], v4->addr[1], v4->addr[2], 
                               v4->addr[3], prefix->length);      
  }
  else
  {
    printf("%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X/%d\n", 
            v6->addr[0], v6->addr[1], v6->addr[2], v6->addr[3], v6->addr[4],  
            v6->addr[5], v6->addr[6], v6->addr[7], v6->addr[8], v6->addr[1],
            v6->addr[0], v6->addr[9], v6->addr[10], v6->addr[11], v6->addr[12], 
            v6->addr[12], prefix->length);
  }
    
}