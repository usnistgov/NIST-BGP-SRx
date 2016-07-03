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
 * This software allows to generate the BGPSEC Path attribute as binary stream.
 * The path will be fully signed as long as all keys are available.
 *
 * @version 0.2.0.0
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.0.0 - 2016/06/02 - oborchert
 *            * Merged modifications from 0.1.1.1 branch for measurement 
 *              framework
 *  0.1.1.0 - 2016/04/19 - oborchert
 *            * Added bogus data type for FAKE signatures.
 *          - 2016/03/26 - oborchert
 *            * Added list parameters to retrieve the keys used for signing.
 *          - 3016/03/24 - oborchert
 *            * Removed data type confusion for function generateBGPSecAttr
 *          - 2016/03/21 - oborchert
 *            * To remove confusion between the different BGPSEC path types the
 *                method printBGPSECPathAttribute now requires a
 *                BGPSecPathAttribute pointer rather than a u_int8_t pointer.
 *  0.1.0.0 - 2015/07/31 - oborchert
 *            * Created File.
 */

#include <stdbool.h>
#include <sys/types.h>
#include "ASList.h"
#include "antd-util/linked_list.h"
#include "bgp/BGPHeader.h"

#ifndef BGPSECPATHBIN_H
#define	BGPSECPATHBIN_H

/*--------------------------------------------------------
 * Packed packet structs and corresponding field constants
 * ths is needed to allow the structs to function as templates
 * over the data stream.
 */
//#pragma pack(1)
// pack only where pack is needed at the struct itself

// Hash struct for first signature in path
typedef struct {
  u_int32_t targetAS;
  u_int32_t originAS;
  u_int8_t  pCount;
  u_int8_t  flags;
  u_int8_t  algoID;
  u_int16_t afi;
  u_int8_t  safi; 
  // Now NLRI
  u_int8_t  pLen;
  // followed by pLen bits padded to the next full octet.
} __attribute__((packed)) Tpl13Hash1;

// Hash struct for consecutive signature in path
typedef struct {
  u_int32_t targetAS;
  u_int32_t signerAS;
  u_int8_t  pCount;
  u_int8_t  flags;
  // previous signature will follow
} __attribute__((packed)) Tpl13Hash2;

typedef struct {
  u_int32_t targetAS;
  BGPSEC_SignatureSegment signature_n_1;
  // followed by the signature
  // Followed by Tpl15Hash2
} __attribute__((packed)) Tpl15Hash3;

typedef struct {
  // preceeded by Signature
  u_int8_t  pCount;
  u_int8_t  flags;
  // Followed by either Tpl15Hash3 or Tpl15Hash1
} __attribute__((packed)) Tpl15Hash2;

typedef struct {
  u_int32_t targetAS;
  BGPSEC_SecurePathSegment pathSegment1;
  u_int8_t  algoID;
  u_int16_t afi;
  u_int8_t  safi;   
  // Now NLRI
  u_int8_t  pLen;
  // followed by pLen bits padded to the next full octet.
  
} __attribute__ ((packed)) Tpl15Hash1;

/**
 * This struct is used internally 
 */
typedef struct {
  char* asPath;
  int nrSegments;
  BGPSEC_SecurePathSegment* pathSegments;
} tAS_Path;

typedef struct _tPSegList {
  struct _tPSegList* to;
  struct _tPSegList* from;
  BGPSEC_SecurePathSegment* spSeg;
  TASInfo*  asInfo; // a helper for speedup, can be NULL
  u_int8_t  sigLen;
  u_int8_t* signature;
} tPSegList;

/** This structure can be used for signatures that could not be generated. 
 * It allows the system to inject FAKE data.
 */
typedef struct {
  u_int8_t  sigLen;
  u_int8_t* signature;
  u_int8_t  ski[SKI_LENGTH];
  u_int16_t keyLen;
  u_int8_t* key;
} BogusSignature;

////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////
/** 
 * initialize the system
 */
void initData();

/**
 * Release the systems allocated memory
 */
void releaseData();

/**
 * Generate the BGPSec Path attribute byte stream. All values inside the stream 
 * are written in network format, all parameters are given in host format.
 * 
 * @param useGlobal use internal data stream (not thread safe but faster)
 * @param asPath (optional) a comma or blank separated string containing the AS 
 *               path (origin is the right most AS), Can be empty or NULL.
 * @param segmentCt OUT variable that returns the number of path / signature 
 *               segments this BGPSec path attribute contains.
 * @param bgp_conf The configuration of the bgp session.
 * @param prefix The prefix to be used. Depending on the AFI value it will be 
 *               typecast to either BGPSEC_V4Prefix or BGPSEC_V6Prefix
 * @param asList The AS list
 * 
 * @return Return the BGPSEC path attribute
 */
BGP_PathAttribute* generateBGPSecAttr(bool useGlobal, char* asPath, 
                                      u_int32_t* segmentCt, 
                                      BGP_SessionConf* bgp_conf,
                                     BGPSEC_PrefixHdr* prefix, TASList* asList);

/**
 * Free the test data stream.
 * 
 * @param data The data to be freed
 */
void freeData(u_int8_t* data);

/**
 * Print the given bgpsec path attribute.
 * 
 * @param attr the BGPSEC path attribute to be printed
 * @param prefix the prefix to be printed (can be NULL).
 * @param title the title to be used (can be NULL)
 */
void __printBGPSEC_PathAttr(BGPSEC_PathAttribute* attr, char* prefix, 
                          char* title);
#endif	/* BGPSECPATHBIN_H */

