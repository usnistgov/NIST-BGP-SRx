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
 * ASInfo provides a double linked list for AS numbers for BGPSEC. The list is
 * sorted ascending by the as number.
 *
 * @version 0.1.1.0
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.1.1.0 - 2016/03/28 - oborchert
 *            * Modified loadSKI to prepare for public and private keys.
 *            * Added privacy state to TASCompare and the respective methods
 *          - 2016/03/09 - oborchert
 *            * Added a define into include statement to determine where to get 
 *              the srxcryptoapi header from - see parameter sca_dir
 *  0.1.0.0 - 2015/08/07 - oborchert
 *             * Created File.
 */
#ifndef ASINFO_H
#define	ASINFO_H

#include <sys/types.h>
#ifdef SCA_LDFLAG
#include "srx/srxcryptoapi.h"
#else
#include <srx/srxcryptoapi.h>
#endif
#include "antd-util/linked_list.h"

//typedef BGPSecKey TASInfo;
/** The TASInfo key structure. */
typedef struct {
  /* Indicates if the key is private of public. */
  bool isPublic;
  /* the BGPSecKey DER encoded key. */
  BGPSecKey key;
  /* Length of the OpenSSL encoded string. */
  u_int16_t ec_key_len;
  /* The OpenSSL encoded key. */
  void*     ec_key;
} __attribute__((packed)) TASInfo;

typedef List TASList;

/**
 * Insert the given element into the list and return "true" on success.
 * It is possible to have the same element inserted twice!!
 * 
 * @param list the list to insert the element into.
 * @param asn the AS number
 * @param algoID the algorithm ID
 * @param isPublic indicates if the stored element will hold a public (true) or
 *                a private (false) key.
 * @param ski The SKI.
 * 
 * @return true if the element could be inserted.
 */
bool insertElement(TASList* list, u_int32_t asn, u_int8_t algoID, bool isPublic, 
                   u_int8_t* ski);

/**
 * Retrieve the requested element. The first ASN info
 * found where the asn, algoID, and key type (private/public) matches will be 
 * returned.
 * 
 * @param list the list where all ASes are stored in.
 * @param asn The AS number
 * @param algoID the algorithmID
 * @param isPrivate if the key is private (true) or public (false)
 * 
 * @return the requested AS info element or NULL.
 */
TASInfo* getListInfo(TASList* list, u_int32_t asn, u_int8_t algoID, 
                     bool isPrivate);

/**
 * Parse the list of AS:SKI values and load it into memory. For each key type 
 * one element will be generated.
 * 
 * @param fName the filename of the SKI file.
 * @param asList the AS list where the keys have to be added to. In NULL a new 
 *               list will be generated.
 * @param algoID The id for the algorithm this keys are used for.
 * @param loadPublic load public keys.
 * @param loadPrivate load private keys. 
 * 
 * @return The asList that was handed over. NULL is no list was given and the 
 *         file not found, a new list if none was given but generated from the 
 *         file.
 *  
 */
TASList* loadAS_SKI(const char* fName, TASList* asList, u_int8_t algoID, 
                    bool loadPublic, bool loadPrivate);

/**
 * Print the given ASInfo instance
 * 
 * @param asInfo The ASInfo to be printed.
 */
void printASInfo(char* c1, char* c2, TASInfo* asInfo);

/**
 * Print the given ASList.
 * 
 * @param list The list to be printed.
 */
void printList(TASList* list);

/**
 * Free the ASList recursively.
 * 
 * @param asList The AS list to be freed.
 */
void freeASList(TASList* asList);

/**
 * Free the memory allocated by the AS info element. It is assumed the memory
 * is allocated using OPENSSL_malloc. Therefore this method uses OPENSSL_free.
 * 
 * @param info The element to be freed.
 */
void freeASInfo(void* info);

#endif	/* ASINFO_H */

