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
#include <stdbool.h>
#include <syslog.h>
#include <uthash.h>
#include <sys/types.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include "../srx/srxcryptoapi.h"
#include "key_storage.h"

#define KS_BUCKETS 256

/**
 * REturn the bucket of the given ASN
 * 
 * @param asn The AS number - format not important.
 * 
 * @return The bucket number of the ASN
 */
static u_int8_t _ks_getBucket(u_int32_t asn)
{      
  u_int8_t bucket = (asn >> 24) + ((asn >> 16) & 0xFF) + ((asn >> 8) & 0xFF)
                    + (asn & 0xFF);
  bucket = bucket & 255;
  return bucket;
}


/**
 * Create a clone of the provided key.
 * 
 * @param key This key will be cloned.
 * 
 * @return the cloned key or NULL
 */
static BGPSecKey* _ks_clone(BGPSecKey* key)
{
  BGPSecKey* clone = malloc(sizeof(BGPSecKey));
  memset (clone, 0, sizeof(BGPSecKey));
  if (clone != NULL)
  {
    clone->algoID    = key->algoID;
    clone->asn       = key->asn;
    memcpy(&clone->ski, &key->ski, SKI_LENGTH);
    clone->keyLength = key->keyLength;
    if (clone->keyLength != 0)
    {
      clone->keyData   = malloc(key->keyLength);
      if (clone->keyData != NULL)
      {
        memcpy(clone->keyData, key->keyData, key->keyLength);      
        memcpy(clone->ski, key->ski, SKI_LENGTH);
      }
      else
      {
        free(clone);
        clone = NULL;
      }
    }
  }
  
  return clone;  
}

/**
 * Convert the DER key stored in the keyData into an EC_KEY.
 * The following status will be returned:
 * API_STATUS_ERR_INVLID_KEY - The key could be converted but did fail the 
 *                             EC_KEY_check
 * API_STATUS_ERR_NO_DATA - The DER key is missing.
 * 
 * @param keyData The DER encoded key
 * @param keyLength The length of the DER encoded key
 * @param isPrivate indicate if the key is private
 * @param status Adds return information in case something goes wrong - the 
 *               status flag will NOT be initialized within the function.
 * 
 * @return The key or NULL. In the later case check status.
 */
static EC_KEY* _ks_convertKey(u_int8_t* keyData, u_int16_t keyLength, 
                              bool isPrivate, sca_status_t* status)
{
  char* p    = (char*)keyData;
  EC_KEY* ec_key = NULL;
  if (isPrivate)
  {
    ec_key = d2i_ECPrivateKey(NULL, (const unsigned char**)&p, (long)keyLength);
  }
  else
  {
    size_t ecdsa_key_int;
    ecdsa_key_int = (size_t) d2i_EC_PUBKEY(NULL, (const unsigned char**)&p, 
                                           (long)keyLength);
    ec_key = (EC_KEY*)ecdsa_key_int;
  }

  // Now we need to get the EC_KEY
  if (ec_key != NULL)
  {
    if (!EC_KEY_check_key(ec_key))
    {
      EC_KEY_free(ec_key);
      ec_key = NULL;
      *status |= API_STATUS_ERR_INVLID_KEY;
    }
  }
  else
  {
    *status |= API_STATUS_ERR_NO_DATA;    
  }
  
  return ec_key;
}

/**
 * Retrieve the EC_KEY associated to the given ski and asn
 * 
 * Possible USER return values:
 * 
 * API_STATUS_INFO_KEY_NOTFOUND : Key not found
 * API_STATUS_ERR_USER1: A DER key element is NULL (BUG IN List).
 * API_STATUS_ERR_NO_DATA: No data provided to find the key.
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
                 u_int16_t* noKeys, KS_Key_Type kType, sca_status_t* status)
{
  void** keys   = NULL;
  sca_status_t myStatus = (storage != NULL && ski != NULL && noKeys != NULL)
                          ? API_STATUS_OK
                          : API_STATUS_ERR_NO_DATA;
  
  if (myStatus == API_STATUS_OK)
  {
    // find the correct elem list
    int bucket = _ks_getBucket(asn);    
    KS_Key_Element* elem = storage->head[bucket];
    
    while (elem != NULL)
    {
      if (elem->asn < asn)
      {
        // Move forward in the list
        elem = elem->next;
        continue;
      }
      if (elem->asn > asn)
      {
        // Key Not found
        myStatus = API_STATUS_INFO_KEY_NOTFOUND;
        elem = NULL;
        break;
      }
      // ASN Element found - check ski
      if (memcmp(elem->ski, ski, SKI_LENGTH) != 0)
      {
        // No match, move on
        elem = elem->next;
        continue;
      }
      
      // ASN and ski match
      int idx = 0;
      if (kType == ks_eckey_e) 
      {
        keys = (void**)elem->ec_key;
      }
      else
      {
        keys = (void**)elem->derKey;
      }

      if (kType == ks_eckey_e)
      {
        for(; idx < elem->noKeys; idx++)
        {
          if (elem->ec_key[idx] != NULL)
          {
            continue;
          }
          // Load the key
          if (elem->derKey[idx] != NULL)
          {
            elem->ec_key[idx] = _ks_convertKey(elem->derKey[idx]->keyData,
                                               elem->derKey[idx]->keyLength,
                                               storage->isPrivate, &myStatus);
            if (myStatus & API_STATUS_ERR_NO_DATA)
            {
              myStatus |= API_STATUS_ERR_USER1;
            }
            continue;
          }
          // DER Key not found
          myStatus |= API_STATUS_ERR_USER1;
        }      
      }
      // Found the key
      *noKeys = elem->noKeys;
      break;
    }     
  }
  
  if (status != NULL)
  {
    if (keys == NULL)
    {
      myStatus |= API_STATUS_INFO_KEY_NOTFOUND;
    }
    *status = myStatus;
  }
  return keys;
}

/**
 * Destroy the BGPSec Key
 * 
 * @param key The BGPSecKey to be destroyed.
 */
static void _ks_freeKey(BGPSecKey* key)
{
  if (key != NULL)
  {
    free(key->keyData);
    free(key);
  }
}

/** 
 * Generate a KeyStorage element.
 * 
 * @param key The key to be added. Here a copy of the Key will be stored!
 * @param status The status of the generation.
 * 
 * @return a new key storage element or NULL if an error occurred - see status.
 */
static KS_Key_Element* _ks_createKS_Element(BGPSecKey* key, bool convert,
                                            bool isPrivate, sca_status_t* status)
{  
  KS_Key_Element* elem = malloc(sizeof(KS_Key_Element));
  sca_status_t myStatus = API_STATUS_OK;
  
  if (elem != NULL)
  {
    memset(elem, 0, sizeof(KS_Key_Element));
    // Store the minimal information.
    elem->asn = key->asn;
    memcpy(elem->ski, key->ski, SKI_LENGTH);
    
    elem->derKey = malloc(sizeof(BGPSecKey*));
    if (elem->derKey != NULL)
    {
      // Now copy the key into it.
      elem->derKey[0] = _ks_clone(key);
      if (elem->derKey[0] != NULL)
      {
        elem->noKeys = 1;
        // create the array space for the ec_key
        elem->ec_key = malloc(sizeof(EC_KEY*));
        if (elem->ec_key != NULL)
        {
          elem->ec_key[0] = NULL;
          if (convert)
          {
            if (elem->derKey[0]->keyData != NULL)
            {
              if (sca_loadKey(elem->derKey[0], isPrivate, &myStatus) == API_SUCCESS)
              {  
                elem->ec_key[0] = _ks_convertKey(elem->derKey[0]->keyData, 
                                                 elem->derKey[0]->keyLength, 
                                                 isPrivate, &myStatus);
              }
              if (elem->ec_key[0] == NULL)
              {
                _ks_freeKey(elem->derKey[0]);
                free(elem->derKey);
                free(elem->ec_key);
                free(elem);
                elem = NULL;
              }
            }
          }
          else
          {
            elem->ec_key[0] = NULL;
          }
        }
        else // Could not generate the ec_key array - free the key array and elem
        {      
          free(elem->derKey);
          elem->derKey = NULL;
          free(elem);
          elem = NULL;
          myStatus |= API_STATUS_ERR_INSUF_KEYSTORAGE;                
        }
      }
      else // could not clone the BGPSecKey - clean elem-key and elem
      {        
        free(elem->derKey);
        elem->derKey = NULL;
        free(elem);
        elem = NULL;
        myStatus |= API_STATUS_ERR_INSUF_KEYSTORAGE;                
      }
    }
    else // Could not generate the key array - free elem
    {
      free(elem);
      elem = NULL;
      myStatus |= API_STATUS_ERR_INSUF_KEYSTORAGE;
    }
  }
  else
  {
    myStatus |= API_STATUS_ERR_INSUF_KEYSTORAGE;
  }
  
  if (status != NULL)
  {
    *status = myStatus;
  }
  
  return elem;
}

/**
 * Remove the element from the storage
 * 
 * @param storage The key storage
 * @param head The head index.
 * @param elem The element to be removed
 */
static void _ks_freeKS_Elem(KeyStorage* storage, int head,
                            KS_Key_Element* elem)
{
  storage->size -= elem->noKeys;
  
  if (elem->prev != NULL) // elem is the head
  {
    elem->prev = elem->next;
  }
  else
  {
    storage->head[head] = elem->next; // move head to the next one
  }
  
  if (elem->next != NULL) 
  {
    elem->next->prev = elem->prev;
  }
 
  // Now free the allocated memory
  int kIdx = 0;
  for (; kIdx < elem->noKeys; kIdx++)
  {
    _ks_freeKey(elem->derKey[kIdx]);
    elem->derKey[kIdx] = NULL;
    if (elem->ec_key[kIdx] != NULL)
    {
      EC_KEY_free(elem->ec_key[kIdx]);
      elem->ec_key[kIdx] = NULL;
    }
  }
  free(elem->derKey);
  free(elem->ec_key);
  memset(elem, 0, sizeof(KS_Key_Element));
  free(elem);
}

/**
 * Initialized the key storage
 * 
 * @param storage The key storage to be initialized
 * @param algoID The algorithm ID
 * @param isPrivate indicate if the storage contains private keys.
 */
void ks_init(KeyStorage* storage, u_int8_t algoID, bool isPrivate)
{
  if (storage != NULL)
  {
    storage->algorithmID = algoID;
    storage->isPrivate = isPrivate;
    storage->size = 0;
    storage->head = malloc(sizeof(KS_Key_Element*) * KS_BUCKETS);
    memset (storage->head, 0, sizeof(KS_Key_Element*) * KS_BUCKETS);
  }
}

/**
 * Empty the storage if necessary and free the allocated memory.
 * 
 * @param storage The storage to be freed.
 */
void ks_release(KeyStorage* storage)
{
  if (storage != NULL)
  {
    ks_empty(storage);
    if (storage->head != NULL)
    {
      free (storage->head);
    }      
    free(storage);
  }
}

/**
 * Delete the key from the given KeyStorage. In case the provided key does only 
 * contain algoID, ASN, and SKI all keys found with this match are deleted. In 
 * case a stored DER key is part of the key, only the stored version with a 100%
 * binary match will be deleted.
 * the key parameter will not be modified as long as it is different from the 
 * stored version. In case it is the same instance, it will be changed / 
 * deleted,
 * 
 * the following USER status can be returned:
 * 
 * API_STATUS_ERR_USER1: Key algorithm ID does not match the storage Algorithm ID
 * API_STATUS_ERR_NO_DATA: One of the provided parameter was NULL
 * 
 * @param storage The storage where the key is stored in
 * @param key The BGPSecKey to be deleted - the given key will not be touched, 
 *            the stored version will. If both are the exact same, then the 
 *            provided key is deleted as well. 
 * @param status an OUT value that provides more information.
 * 
 * @return API_SUCESS (1) otherwise API_FAILED (0 - see status). 
 */
int ks_delKey(KeyStorage* storage, BGPSecKey* key, sca_status_t* status)
{
  int retVal = API_SUCCESS; 
  int myStatus = API_STATUS_OK;
  int             bucket = 0;
  KS_Key_Element* elem   = NULL;
  
  if (storage != NULL && key != NULL)
  {
    if (key->algoID == storage->algorithmID)
    {
      bucket = _ks_getBucket(key->asn);
      elem = storage->head[bucket];
    }
    else
    {
      // Algorithm ID does not match.
      myStatus = API_STATUS_ERR_USER1;
    }
  }
  else
  {
    // Some data missing.
    myStatus = API_STATUS_ERR_NO_DATA;
  }
    
  if (elem != NULL)
  {
    bool deleted = false;
    while (elem != NULL)
    {
      if (elem->asn < key->asn)
      {
        // Move forward in the list
        elem = elem->next;
        continue;
      }
      if (elem->asn > key->asn)
      {
        // Key Not found
        myStatus = API_STATUS_INFO_KEY_NOTFOUND;
        elem = NULL;
        break;
      }

      // ASN Element found - check ski
      if (memcmp(elem->ski, key->ski, SKI_LENGTH) != 0)
      {
        // No match, move on
        elem = elem->next;
        continue;
      }
      
      // ASN and ski match
      // Now if key has a DER key delete only the DER portion, otherwise delete 
      // the complete element.
      int idx = 0;
      if (key->keyData != NULL)
      {
        //Find the correct key version to delete.
        for (; idx < elem->noKeys; idx++)
        {
          if (deleted)
          {
            // move the current key to the previous emptied position
            elem->derKey[idx-1] = elem->derKey[idx];
            elem->ec_key[idx-1] = elem->ec_key[idx];
            elem->derKey[idx] = NULL;
            elem->ec_key[idx] = NULL;
          }
          else
          {  
            if (elem->derKey[idx]->keyLength == key->keyLength)
            {
              if (memcmp(elem->derKey[idx], key->keyData, key->keyLength))
              {
                // Now delete this version
                if (elem->ec_key != NULL)
                {
                  // This array is is malloc'ed
                  free(elem->ec_key);
                }
                _ks_freeKey(elem->derKey[idx]);
                elem->derKey[idx] = NULL;
                deleted = true;
              }
            }
          }
        }
        if (deleted)
        {
          if (elem->noKeys == 1)
          {
            // This was the only key, remove the complete elemnt
            _ks_freeKS_Elem(storage, bucket, elem);
          }
          else
          {
            // some more duplicate keys exist. 
            elem->noKeys--;
            storage->size--;
            // Now resize
            void** dk = realloc(elem->derKey, sizeof(BGPSecKey*) + elem->noKeys);
            if (dk != NULL)
            {
              elem->derKey = (BGPSecKey**)dk;
            }
            void** ek = realloc(elem->ec_key, sizeof(EC_KEY*) + elem->noKeys);
            if (ek != NULL)
            {
              elem->ec_key = (EC_KEY**)ek;
            }
          }
        }
      }
      else
      {
        // DER is NULL so delete the complete element.
        storage->size -= elem->noKeys;
        _ks_freeKS_Elem(storage, bucket, elem);
        deleted = true;
      }
      elem = NULL;
    }
  }
  
  if (status != NULL)
  {
    *status = myStatus;
  }
  return retVal;
}

/** 
 * Free all Key Storage elements and *associated memory that was generated
 * within the storage.
 * 
 * @param storage The storage to be emptied
 */
void ks_empty(KeyStorage* storage)
{
  if (storage != NULL)
  {
    if (storage->head != NULL)
    { // Should NOT be NULL
      int idx = 0;
      for (; idx < KS_BUCKETS; idx++)
      {
        while (storage->head[idx] != NULL)
        {
          _ks_freeKS_Elem(storage, idx, storage->head[idx]);
        }
      }
    }
  }
  if (storage->size != 0)
  {
    sca_debugLog(LOG_WARNING, "Key storage could not be emptied! [%p]\n", 
                 storage);
  }
}

/**
 * Store a copy of the the key in the given KeyStorage. In case the passed 
 * BGPSECkey only contains the ASN, algorithm ID and the SKI this implementation
 * will use the srxCryptoAPI's sca_loadKey function. In case the key could
 * not be loaded the return value will be FAILED and the status flag will be 
 * set to Key not Found.
 * 
 * API_STATUS_ERR_USER1: Wrong algorithmID
 * API_STATUS_INFO_USER1: Duplicate Key
 * API_STATUS_INFO_KEY_NOT_FOUND: In case the real key is supposed to be located
 *                                in the srx-crypto-api's keyvolt but could not
 *                                be found there.
 * 
 * @param storage The storage where the key is stored in
 * @param key The BGPSecKey to be stored.
 * @param status an OUT value that provides more information.
 * @param convert if true then convert the DER key into the EC_KEY
 * 
 * @return API_SUCESS if it could be stored, otherwise API_FAILED. 
 */
int ks_storeKey(KeyStorage* storage, BGPSecKey* key, sca_status_t* status, 
                bool convert)
{
  sca_status_t myStatus = API_STATUS_OK;
  int  retVal   = API_SUCCESS;
  int  bucket   = 0;
         
  if (storage != NULL && key != NULL)
  {
    if (key->algoID == storage->algorithmID)
    {
      // The asn is in big endian format, 
      bucket = _ks_getBucket(key->asn);    
    }
    else
    {
      // Algorithm ID does not match.
      myStatus = API_STATUS_ERR_USER1;
    }
  }
  else
  {
    // Some data missing.
    myStatus = API_STATUS_ERR_NO_DATA;
  }
  
  if (storage->head[bucket] != NULL)
  {
    // we have to find the position to insert the new key
    KS_Key_Element* elem = storage->head[bucket];
    while (elem != NULL)
    {
      if (elem->asn < key->asn)
      {
        if (elem->next != NULL)
        {
          elem = elem->next;
          continue;
        }
        // add as last element          
        storage->size++;
        elem->next = _ks_createKS_Element(key, convert, storage->isPrivate, 
                                          &myStatus);
        elem->next->prev = elem;
        break;
      }

      if (elem->asn > key->asn)
      {
        // insert before the element
        KS_Key_Element* newElem = _ks_createKS_Element(key, convert, 
                                                 storage->isPrivate, &myStatus);
        storage->size++;
        newElem->next = elem;
        newElem->prev = elem->prev;
        elem->prev    = newElem;
        if (newElem->prev != NULL)
        {
          newElem->prev->next = newElem;
        }
        else
        {
          // new head
          storage->head[bucket] = newElem;
        }
        break;
      }

      // as numbers are a match. check ski
      if (memcmp(elem->ski, key->ski, SKI_LENGTH) == 0)
      {
        // check if the key already exist.
        int  kIdx = 0;
        bool inserted = false;

        // Go through all internal keys (most likely only one) and check if it 
        // is already stored.
        for (; kIdx < elem->noKeys && !inserted; kIdx++)
        {
          if (elem->derKey[kIdx]->keyLength == key->keyLength)
          {
            // check if the key is already stored
            if (memcmp(elem->derKey[kIdx]->keyData, key->keyData, key->keyLength) == 0)
            {
              // duplicate key
              inserted = true; // stop the for loop
              myStatus |= API_STATUS_INFO_USER1;
            }
          }
        }

        // If not inserted then we have an SKI collision and we need to add it
        if (!inserted)
        {
          // add one more key / ec_key
          elem->noKeys++;
          // Re-allocate the internal arrays.
          BGPSecKey** dk = realloc(elem->derKey, sizeof(BGPSecKey*) * elem->noKeys);
          EC_KEY** ek = realloc(elem->ec_key, sizeof(EC_KEY*) * elem->noKeys);
                    
          if (dk != NULL && ek != NULL)
          {
            storage->size++;
            elem->derKey = dk;
            elem->ec_key = ek;
            elem->derKey[elem->noKeys-1] = _ks_clone(key);
            elem->ec_key[elem->noKeys-1] = _ks_convertKey(key->keyData, 
                                 key->keyLength, storage->isPrivate, &myStatus);
            inserted = true;
          }
          else
          {
            // not enough memory for the ec_key, shrink the key back
            myStatus |= API_STATUS_ERR_INSUF_KEYSTORAGE;
            elem->noKeys--;
            if (dk != NULL)
            {
              elem->derKey = realloc(dk, sizeof(BGPSecKey*) * elem->noKeys);
            }
            if (ek != NULL)
            {
              elem->ec_key = realloc(ek, sizeof(EC_KEY*) * elem->noKeys);
            }
          }
        }
        break; // The while (elem != NULL) loop.
      }
      else
      {
        // move to the next or add as last.
        if (elem->next != NULL)
        {
          elem = elem->next;
        }
        else
        {
          storage->size++;
          elem->next = _ks_createKS_Element(key, convert, storage->isPrivate, 
                                            &myStatus);
          break; // The while (elem != NULL) loop.
        }
      }
    }
  }
  else
  {
    // we have a new head
    storage->size++;
    storage->head[bucket] = _ks_createKS_Element(key, convert, 
                                                 storage->isPrivate, &myStatus);
  }
  
  if (status != NULL)
  {
    *status = myStatus;
  }
  
  return retVal = ((myStatus & API_STATUS_ERROR_MASK) != 0) ? API_FAILURE
                                                            : API_SUCCESS;
}