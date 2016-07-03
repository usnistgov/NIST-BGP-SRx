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
 * @version 0.4.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.4.0.0  - 2016/06/19 - oborchert
 *            * Changed the input parameters of the ID generation. 
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Added Changelog
 *            * Fixed speller in documentation header
 *            * Fixed typecast error
 *            * REmoved unused variables
 * 0.1.0    - 2011/05/03 -oborchert
 *            * Code created. 
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "shared/crc32.h"
#include "shared/srx_identifier.h"
#include "util/prefix.h"
#include "srx_defs.h"

/**
 * This particular method generates an ID out of the given data using a simple
 * CRC32 algorithm. All data is used as is, no tranformation from host to
 * network and vice versa is performed.
 *
 * @param originAS The origin AS of the data
 * @param prefix The prefix to be announced (IPPrefix)
 * @param data The bgpsec data object which contains the BGP4 path as well.
 *
 * @return return an ID.
 */
uint32_t generateIdentifier(uint32_t originAS, IPPrefix* prefix, 
                            BGPSecData* data)
{
  // @TODO: Check what the data block should consist of, the BGP4 path or the 
  //        BGPSec Path or maybe both ?
  // The question comes up because we need ID's for both BGP4 only and BGPSec.
  // Then if we receive a request if a particular BGPSEC path for a particular
  // BGP4 path exist this can only be answered by the BGP4 path.
  // This needs some more thoughts later one. 
  uint32_t blobLength = 0;
  uint8_t* blob = NULL;
  // A change in the blob generation does impact the function 
  // update_cache.c:storeCacheEntryBlob
  if (data->bgpsec_path_attr != 0)
  {
    blobLength = data->attr_length;
    blob = (uint8_t*)data->bgpsec_path_attr;    
  }
  else
  {
    blobLength = data->numberHops * 4;
    blob = (uint8_t*)data->asPath;
  }

  uint32_t crc  = 0;
  uint32_t prefixSize = prefix->ip.version == 4 ? 4
                                                : sizeof(prefix->ip.addr.v6.u8);
  uint32_t length = (  4           /* OriginAS */
                     + prefixSize  /* IPPrefix */
                     + 1           /* Prefix Length */
                     + blobLength  /* The length of the data blob */
                    ) * 2;         /* To generate a hex string. */

  char dataText[length];
  memset(dataText, '\0', length);
  char* dataPtr = dataText;
  int i;

  sprintf(dataPtr, "%08X", originAS);
  dataPtr += 8;
  if (prefix->ip.version == 4)
  {
    sprintf(dataPtr, "%08X%02X", prefix->ip.addr.v4.u32, prefix->length);
    dataPtr += 10;
  }
  else
  {
    for (i = 0; i < prefixSize; i++)
    {
      sprintf(dataPtr, "%02X", prefix->ip.addr.v6.u8[i]);
      dataPtr += 2;
    }
    sprintf(dataPtr, "%02X", prefix->length);
    dataPtr += 2;
  }

  for (i = 0; i < blobLength; i++)
  {
    sprintf(dataPtr, "%02X", *(char*)blob);
    dataPtr += 2;
    blob++;
  }  
  crc = crc32((uint8_t*)dataText, length);
  return crc;
}

