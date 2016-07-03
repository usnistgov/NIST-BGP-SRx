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
 * Stores and loads the BGPSEC data.
 * 
 * @version 0.1.2.0
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 *  0.1.2.0 - 2016/05/05 - oborchert
 *            * Added draft number to header file.
 *  0.1.1.0 - 2016/05/03 - oborchert
 *            * Modified the signature of storeData
 *          - 2016/04/21 - oborchert
 *            * Added indicator if fake signature was used
 *  0.1.0.0 - 2015/09/11 - oborchert
 *           * Created File.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <netinet/in.h>
#include "player.h"
#include "bgp/printer/BGPPrinterUtil.h"
#include "cfg/configuration.h"

/**
 * Load the next record and return it. If the given buff(er) is not NULL and 
 * not of sufficient size, the record will NOT be loaded and NULL will be 
 * returned. in this case the file pointer will not be advanced.
 * 
 * @param file the file to be loaded.
 * @param myAS My own ASN or ignore myAS if myAS == 0. (use network format)
 * @param peerAS if not 0 then filter the data for the given peer. If 0 load
 *               the data for the next available peer. (use network format)
 * @param type the type of data (update, attribute, all)
 * @param ioBuff the buffer where the data (and keys) will be written into.
 * 
 * @return true if data could be loaded, otherwise false.
 */
bool loadData(FILE* file, u_int32_t myAS, u_int32_t peerAS, u_int8_t type,
              BGPSEC_IO_Record* record, BGPSEC_IO_Buffer* ioBuff)
{
  bool      retVal        = false;
  bool      cont          = !feof(file);
  int       read          = 0;
  u_int16_t dataLength    = 0;
  u_int16_t keyDataLength = 0;
  bool      rightType     = false;
  u_int8_t* ptr           = NULL;
  
  if (ioBuff != NULL)
  {
    if (record != NULL && ioBuff->data != NULL && ioBuff->dataSize != 0)
    {
      while (cont)
      {
        // Read the first record.
        read = fread(record, 1, sizeof(BGPSEC_IO_Record), file);
        cont = !feof(file) && (read != 0) 
               && record->version == BGPSEC_IO_RECORD_VERSION;    
        if (cont)
        {
          dataLength    = ntohs(record->dataLength);
          keyDataLength = ntohs(record->keyDataLength);

          rightType = ((record->recordType & type) == record->recordType)
                      && record->version == BGPSEC_IO_RECORD_VERSION;

          // load all data is the type is right, the peer matches or the peer 
          // does not matter (peerAS == 0))
          if (rightType 
              && (peerAS == 0 || peerAS == record->peerAS) 
              && (myAS == 0   || myAS == record->asn))
          {        
            // For now, skip over the keys
            if (keyDataLength != 0)
            {
              if (ioBuff->keySize + sizeof(u_int16_t) < keyDataLength)
              {
                printf ("ERROR: Key buffer too small to load keys.\n");
              }
              else
              {
                // Write the length of the data into the stream
                u_int16_t* klen = (u_int16_t*)ioBuff->keys;
                *klen = keyDataLength;
                ptr   = ioBuff->keys + sizeof(u_int16_t);                
                
                read = fread(ptr, 1, keyDataLength, file);
                if (read < keyDataLength)
                {
                  printf ("ERROR: Could not read all keys.Read only %d/%d bytes\n",
                          read, keyDataLength);
                  printf (">> Move to next record!\n");
                  fseek(file, keyDataLength - read, SEEK_CUR);                              
                }
              }
            }

            read = fread(ioBuff->data, 1, dataLength, file);
            retVal = read == dataLength;
            cont = false;
          }
          else
          {
            // skip to the next record
            fseek(file, dataLength + keyDataLength, SEEK_CUR);
            // continue as long as data is available (or one set is loaded)
            cont = !feof(file);    
          }
        }
        else if (record->version != BGPSEC_IO_RECORD_VERSION)
        {
          printf("ERROR: Incompatible data version. Expected V=%d, found V=%d\n",
                  BGPSEC_IO_RECORD_VERSION, record->version);
        }
      }
    }
  }
  
  return retVal;
}

/**
 * Store the given data to the file. The data will be stored as a byte stream
 * as is. Best is if the data contains data types to convert them into 
 * big-endian prior to saving to prevent issues on different platforms.
 * 
 * @param outFileFD the file descriptor.
 * @param type the type of data (update or just attribute)
 * @param asn the ASN of the bgpsec-io player (host format_.
 * @param peerAS the peer AS (host format)
 * @param data The data to be stored.
 * 
 * @return true if it could be stored, otherwise false.
 */
bool storeData(FILE* file, u_int8_t type, u_int32_t asn, u_int32_t peerAS, 
               BGPSEC_IO_StoreData* store)
{
  u_int8_t*  keyBuff     = NULL;
  u_int8_t*  ptr         = NULL;
  u_int16_t  keyBuffSize = 0;
  int        idx         = 0;
  
  BGPSecKey*         key       = NULL; 
  BGPSEC_IO_KRecord* keyRecord = NULL;
  
  BGPSEC_IO_Record record;
  u_int16_t        length = sizeof(BGPSEC_IO_Record);
  
  // Make sure the memory is initialized to zero to prevent possible security
  // issues by writing sensitive information to the file.
  memset(&record, 0, sizeof(BGPSEC_IO_Record));
  
  record.version    = BGPSEC_IO_RECORD_VERSION;
  record.recordType = type;
  record.draft      = BGPSEC_IO_DRAFT;
  record.asn        = htonl(asn);
  record.peerAS     = htonl(peerAS);
  record.dataLength = htons(store->dataLength);
  record.noSegments = htonl(store->segmentCount);
  
  BGPSEC_PrefixHdr* pHdr = (BGPSEC_PrefixHdr*)&record.prefix;

  pHdr->afi         = store->prefix->afi; // It is already in network format
  pHdr->safi        = store->prefix->safi;
  pHdr->length      = store->prefix->length;
  // Copy the prefix address portion
  cpyBGPSecAddrMem(store->prefix->afi, record.prefix.addr, store->prefix);
  int bytesWritten = 0;
  
  // Now determine if keys need to be added or not.
  if (store->numKeys != 0)
  {
    for (idx = 0; idx < store->numKeys; idx++)
    {
      key = (BGPSecKey*)store->keys[idx];
      if (key != NULL)
      {
        keyBuffSize += key->keyLength + sizeof(BGPSEC_IO_KRecord);
      }
      else
      {
        printf("WARNING: NULL - Key found!\n");
        keyBuffSize += sizeof(BGPSEC_IO_KRecord);
      }
    }
    keyBuff = malloc(keyBuffSize);
    ptr     = keyBuff;
    memset (ptr, 0, keyBuffSize);
    
    for (idx = 0; idx < store->numKeys; idx++)
    {
      key       = (BGPSecKey*)store->keys[idx];      
      keyRecord = (BGPSEC_IO_KRecord*)ptr;
      if (key != NULL)
      {
        keyRecord->algoID = key->algoID;
        keyRecord->asn    = key->asn; // ASN is stored in network format
        memcpy(keyRecord->ski, key->ski, SKI_LENGTH);
        keyRecord->keyLength = htons(key->keyLength);
        // Move the buffer to allow storing the key
        ptr += sizeof(BGPSEC_IO_KRecord);
        // Not copy the key data
        memcpy(ptr, key->keyData, key->keyLength);
        // Now move the buffer to the end of the key data
        ptr += key->keyLength;
      }
      else
      {
        // Move the buffer to the end of the NULL key
        ptr += sizeof(BGPSEC_IO_KRecord);
      }
    }
    
    length += keyBuffSize;
    record.keyDataLength = htons(keyBuffSize);
  }

  // First write the record header  
  bytesWritten = fwrite((u_int8_t*)&record, 1, sizeof(BGPSEC_IO_Record), file);

  // Now write the keys if needed
  if (store->numKeys > 0)
  {
    // WRITE KEYS
    bytesWritten += fwrite(keyBuff, 1, keyBuffSize, file);
  }

  // Now write the attribute (ass the BGP header length to the attrLength)
  bytesWritten += fwrite(store->data, 1, store->dataLength, file);
  length += store->dataLength;

  fflush(file);
  if (keyBuffSize != 0)
  {
    memset (keyBuff, 0, keyBuffSize);
    free(keyBuff);
    keyBuff = NULL;
  }
  
  return bytesWritten == length;
}