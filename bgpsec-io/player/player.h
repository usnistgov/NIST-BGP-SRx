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
 * This header file contains the data structure for the BGPSEC-IO player.
 * The player itself allows to write/read the data to and from a file.
 * 
 * @version 0.1.2.0
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 *  0.1.2.0 - 2016/05/05 - oborchert
 *            * Added draft number to header file.
 *            * Moved header version to 2
 *  0.1.1.0 - 2016/05/03 - oborchert
 *            * Modified the signature of storeData
 *          - 2016/04/21 - oborchert
 *            * Added indicator if fake signature was used
 *  0.1.0.0 - 2015/09/11 - oborchert
 *           * Created File.
 */
#ifndef PLAYER_H
#define	PLAYER_H

#include <sys/types.h>
#include <stdio.h>
#include "../bgp/BGPHeader.h"

#define BGPSEC_IO_RECORD_VERSION    3
#define BGPSEC_IO_DRAFT             15

#define BGPSEC_IO_TYPE_ALL          3
#define BGPSEC_IO_TYPE_BGP_UPDATE   1
#define BGPSEC_IO_TYPE_BGPSEC_ATTR  2

typedef struct {
  /** The version of this record. */          
  u_int8_t  version;
  /** Specifies the type of record stored. */
  u_int8_t  recordType;
  /** implementation */
  u_int8_t  draft;
  // The total payload length is the sum of dataLength and keyDataLength
  /** the length of the record data without keys. 
   * (This structure NOT included) */
  u_int16_t dataLength;
  /** Number of secure path segments in the stored update or attribute. */
  u_int32_t noSegments;
  /** the length of the key data. 
   * (This structure NOT included) */
  u_int16_t keyDataLength;
  /** The ASN for the player session in host format. */
  u_int32_t asn;
  /** The ASN of the players peer in host format. */
  u_int32_t peerAS;
  /** The NLRI */
  BGPSEC_V6Prefix prefix;
  /** Indicates if a fake signature is used */
  bool fake;  
  /** Indicates if the next portion contains key information. */
  u_int16_t numKeys;
  // Followed by a list of 'numKeys' keys of type (BGPSEC_IO_KRecord) 
  // followed by the BGPSEC_PathAttribute.
} __attribute__((packed)) BGPSEC_IO_Record;

typedef struct {
  /** The id of the used algorithm suite (See RFC)*/
  u_int8_t  algoID;
  /** The ASN that uses the Key */
  u_int32_t asn;
  /** The SKI of the key */
  u_int8_t  ski[SKI_LENGTH];
  /** The length of the key byte stream. */
  u_int16_t keyLength;
  /** Followed by the key in DER format */
} __attribute__((packed)) BGPSEC_IO_KRecord;

typedef struct {
 /** The prefix to be announced */
  BGPSEC_PrefixHdr* prefix;
 /** Allows to indicate if a fake signature / ski was used */
  bool        usesFake;
 /** dataLength the length of the data to be stored. */
  u_int16_t   dataLength;
 /** The data to be stored. */
  u_int8_t*   data;
  /** The number of path segments in the stored data. */
  u_int32_t   segmentCount;
 /** The number of keys added. */
  u_int16_t   numKeys;
 /** An array of keys. */
  BGPSecKey** keys;  
} BGPSEC_IO_StoreData;

/** This struct is used to allow one parameter for functions rather than 
 * multiple when it comes to buffers. */
typedef struct {
  /** The size of the buffer. */
  int       dataSize;
  /** The buffer itself containing the data. */
  u_int8_t* data;
  /** The key buffer. */
  int       keySize;
  /** The key buffer itself containing the keys as they were found in the 
   * stream. */
  u_int8_t* keys;
} BGPSEC_IO_Buffer;

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
              BGPSEC_IO_Record* record, BGPSEC_IO_Buffer* ioBuff);

/**
 * Store the given data to the file. The data will be stored as a byte stream
 * as is. Best is if the data contains data types to convert them into 
 * big-endian prior to saving to prevent issues on different platforms.
 * 
 * @param outFileFD the file descriptor.
 * @param type the type of data (update or just attribute)
 * @param asn the ASN of the bgpsec-io player.
 * @param peerAS the peer AS
 * @param data The data to be stored.
 * 
 * @return true if it could be stored, otherwise false.
 */
bool storeData(FILE* file, u_int8_t type, u_int32_t asn, u_int32_t peerAS, 
               BGPSEC_IO_StoreData* data);

#endif	/* PLAYER_H */

