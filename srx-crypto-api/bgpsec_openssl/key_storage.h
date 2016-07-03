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
 * This file provides the implementation for SRxCryptoAPI for loading OpenSSL 
 * generated keys. This package provides the qsrx_... scripts for key 
 * generation.
 * 
 * Known Issue:
 *   At this time only pem formated private keys can be loaded.
 * 
 * @version 0.2.0.0
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 *  0.2.0.0 - 2016/06/30 - oborchert
 *            * Cleaned up unused code and removed compiler warnings
 *  0.2.0.0 - 2016/06/20 - oborchert
 *            * Modified ks_getKey in such that it also can return the der key.  
 *          - 2016/05/25 - oborchert
 *            * Created Key Storage
 */
#ifndef KEY_STORAGE_H
#define KEY_STORAGE_H

#include <sys/types.h>
#include <openssl/ec.h>
#include "../srx/srxcryptoapi.h"

/** Used to prevent an overflow */
#define MAX_KEY_USED 0xFFFF

/**
 * The enymeration type is required for the ks_getKey function.
 */
typedef enum {
  /** REpresent s EC Keys. */
  ks_eckey_e  = 0,
  /** Represents DER keys. */
  ks_derkey_e = 1       
} KS_Key_Type;

typedef struct _KS_Key_Element
{
  /** Pointer to previous element */
  struct _KS_Key_Element* prev;
  /** Pointer to next element */
  struct _KS_Key_Element* next;
  
  /** The ASN of all the keys. */
  u_int32_t   asn;
  /** The array containing the ASKI of the key. */
  u_int8_t    ski[SKI_LENGTH];
  /** An array containing the DER formated key - Normally contains only one key 
   * but in case of an SKI conflict multiple keys might be possible. */
  BGPSecKey** derKey;
  /** Contains the OpenSSL Key if loaded into memory - each array element 
   * corresponds to the DER formated key. */
  EC_KEY**    ec_key; 
  /** Number of times this key is used up to MAX_KEY_USED. */
  u_int16_t  timesUsed;
  /** Indicates how many different DER keys are stored. Normally 1 but > 1 in 
   * case of an SKI / ASN collision */
  u_int16_t  noKeys;  
} KS_Key_Element;

typedef struct 
{
  /** The algorithm ID of the keys. */
  u_int8_t algorithmID;
  /** indicates if the keys are private or not. */
  bool isPrivate;
  /** The bucket head elements of the storage. */
  KS_Key_Element** head;  
  /** The number of keys stored in the storage. */
  u_int32_t size;
} KeyStorage;

/**
 * Initialized the key storage
 * 
 * @param storage The key storage to be initialized
 * @param algoID The algorithm ID
 * @param isPrivate indicate if the storage contains private keys.
 */
void ks_init(KeyStorage* storage, u_int8_t algoID, bool isPrivate);

/**
 * Retrieve the EC_KEY associated to the given ski and asn
 * 
 * Possible USER return values:
 * 
 * API_STATUS_INFO_KEY_NOTFOUND : Key not found
 * API_STATUS_ERR_USER1: A DER key element is NULL (BUG IN List).
 * API_STATUS_ERR_NO_DATA: No data provided to find the key
 * 
 * @param storage The storage where the key is stored in
 * @param ski The SKI of the key (SKI_LENGTH)
 * @param asn The as number of the key in network format
 * @paran noKeys An OUT variable contains the size of the returned array. 
 * @param kType The type of the keys requested, EC or DER
 * @param status is an OUT parameter that if given will provide more information.
 *        API_STATUS_INFO_USER1 is used to indicate that additional keys are
 *        available at a higher position
 * 
 * @return the array of EC_Keys/DER_Keys or NULL of not found. if NULL check 
 *         status value.
 */
void** ks_getKey(KeyStorage* storage, u_int8_t* ski, u_int32_t asn, 
                 u_int16_t* noKeys, KS_Key_Type kType, sca_status_t* status);

/**
 * Store the key in the given KeyStorage.
 * 
 * API_STATUS_INFO_USER1: Duplicate Key
 * 
 * @param storage The storage where the key is stored in
 * @param key The BGPSecKey to be stored.
 * @param status an OUT value that provides more information.
 * @param convert if true then convert the DER key into the EC_KEY
 * 
 * @return API_SUCESS if it could be stored, otherwise API_FAILED. 
 */
int ks_storeKey(KeyStorage* storage, BGPSecKey* key, sca_status_t* status, 
                bool convert);

/**
 * Delete the key from the given KeyStorage.
 * 
 * @param storage The storage where the key is stored in
 * @param key The BGPSecKey to be stored.
 * @param status an OUT value that provides more information.
 * 
 * @return API_SUCESS if it could be stored, otherwise API_FAILED. 
 */
int ks_delKey(KeyStorage* storage, BGPSecKey* key, sca_status_t* status);

/** 
 * Free all Key Storage elements and *associated memory that was generated
 * within the list.
 */
void ks_empty(KeyStorage* storage);

/**
 * Empty the storage if necessary and free the allocated memory.
 * 
 * @param storage The storage to be freed.
 */
void ks_release(KeyStorage* storage);

#endif /* KEY_STORAGE_H */

