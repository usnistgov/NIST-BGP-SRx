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
 * @version 0.2.0.2
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.0.2 - 2016/06/29 - oborchert
 *            * Added missing include file.
 *  0.2.0.0 - 2016/06/08 - oborchert
 *            * Fixed error in freeASInfo
 *          - 2016/05/10 - oborchert
 *            * Fixed compiler warnings BZ950
 *  0.1.1.0 - 2016/05/04 - oborchert
 *            * Fixed a bug in insertElement which returned the false value.
 *          - 2016/03/28 - oborchert
 *            * Modified loadSKI to prepare for public and private keys.
 *            * Added key type (private/public) to TASCompare and the respective
 *              methods
 *          - 2016/03/11 - oborchert
 *            * Adjusted type TASCompare, which had the types wrong as well as 
 *              the order.
 *            * BZ#880 Fixed method getInfo which returned wrong info object.
 *  0.1.0.0 - 2015/08/07 - oborchert
 *            * Created File.
 */
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <malloc.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include "antd-util/linked_list.h"
#include "antd-util/printer.h"
#include "ASList.h"

#define MAX_ASLIST_STR 255

/**
 * This struct is used internally for the comparison of TASInfo. It is s subset
 * of TASInfo that contains only data needed for the comparison and can be
 * mapped on top of TASInfo.
 */
typedef struct
{
  bool      isPublic;
  u_int8_t  algoID;
  u_int32_t asn;
} __attribute__((packed)) TASCompare;

/**
 * Compared el1 and el2. The following values are returned:
 * [ -1: el1 &lt; el2 ]
 * [  0: el1 == el2 ]
 * [  1: el1 &gt; el2 ]
 * Compared will be the asn and algoID - NOT the SKI
 * 
 * @param e1 First element to compare
 * @param e2 Second element to compare
 * 
 * @return -1, 0, or 1 see description above.
 */
int _cmpListElement (void* e1, void* e2)
{
  int retVal = 0;
  TASCompare* comp1 = (TASCompare*)e1;
  TASCompare* comp2 = (TASCompare*)e2;
  
  // first compare ASN
  if (comp1->asn < comp2->asn)
  {
    retVal = -1;
  }
  else if (comp1->asn > comp2->asn)
  {
    retVal = 1;
  }
  else // comp1->asn == comp2->asn
  {
    // both asn are the same, now compare algoID
    if (comp1->algoID < comp2->algoID)
    {
      retVal = -1;
    }
    else if (comp1->algoID > comp2->algoID)
    {
      retVal = 1;
    }
    else // comp1->algoID == comp2->algoID
    {
      if (comp1->isPublic != comp2->isPublic)
      {
        retVal = comp1->isPublic ? 1 : -1;
      }
    }
  }
  
  return retVal;
}

/**
 * Insert the given element into the list and return "true" on success.
 * It is possible to have the same element inserted twice!!
 * 
 * @param list the list to insert the element into.
 * @param asn the AS number - will be stored in the format given.
 * @param algoID the algorithm ID
 * @param isPublic indicates if the stored element will hold a public (true) or
 *                a private (false) key.
 * @param ski The SKI.
 * 
 * @return true if the element could be inserted.
 */
bool insertElement(TASList* list, u_int32_t asn, u_int8_t algoID, bool isPublic, 
                   u_int8_t* ski)
{
  TASInfo* asinfo = malloc(sizeof(TASInfo));
  memset(asinfo, 0, sizeof(TASInfo));
  
  asinfo->key.asn    = asn;
  asinfo->key.algoID = algoID;
  asinfo->isPublic   = isPublic;
          
  if (ski != NULL)
  {
    memcpy(&asinfo->key.ski, ski, SKI_LENGTH);
  }
  
  if (!insertListElem((List*)list, asinfo, _cmpListElement))
  {
    printf("ERROR: Could not insert list element!\n");
    freeASInfo(asinfo);
    asinfo = NULL;
  }
    
  return asinfo != NULL;
}

/**
 * Retrieve the requested element. The first ASN info
 * found where the asn, algoID, and key type (private/public) matches will be 
 * returned.
 * 
 * @param list the list where all ASes are stored in.
 * @param asn The AS number - In network format
 * @param algoID the algorithmID
 * @param isPrivate if the key is private (true) or public (false)
 * 
 * @return the requested AS info element or NULL.
 */
TASInfo* getListInfo(TASList* list, u_int32_t asn, u_int8_t algoID, 
                     bool isPrivate)
{
  // Fix BZ880: the compare was twisted, compare info to needle, not the other 
  // way around.
  
  TASCompare needle;
  needle.isPublic = !isPrivate;
  needle.asn      = asn;
  needle.algoID   = algoID;

  TASInfo* info = NULL;
  int cRes = -2;
  
  if (list != NULL)
  {
  
    ListElem* ptr = list->head;
    
    // Initial Compare
    cRes = -2;

    // @TODO: A speedup could be achieved by using middle pointers and determining 
    // a closer start pointer than head.  

    // Run through the list until the element is found or it can be determined 
    // the element does not exist.
    
    // The assumption here is the list is sorted ascending, We start at the head 
    // so the smallest stored info, 
    while ( cRes < 0 && ptr != NULL)
    {
      info = (TASInfo*)ptr->elem;
      cRes = _cmpListElement(info, &needle);
      ptr = ptr->next;
    }
  }

  return (cRes != 0) ? NULL : info;
}

/**
 * Parse the list of AS:SKI values and load it into memory. For each key type 
 * one element will be generated. The AS numbers in the file are in human 
 * readable form but stored in BGPSecKey in network format.
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
                    bool loadPublic, bool loadPrivate)
{
  FILE *fPtr = fopen(fName, "r");
  char line[1024];
  int read = 0;
  
  u_int32_t asn;
  u_int8_t  ski[SKI_LENGTH];
  u_int32_t idx = 0;
  u_int8_t* ptr;
  bool      skipLine = false;
    
  if (fPtr)
  {
    if (asList == NULL)
    {
      asList = (TASList*)createList();
    }
    memset (&ski, 0, SKI_LENGTH); // initialize to prevent security issues
    
    while (fgets(line, 1024, fPtr) != NULL)
    {
      skipLine = false;
      read = strlen(line);
      if (read > SKI_HEX_LENGTH)
      {
        asn = 0;
        memset(ski, 0, SKI_LENGTH);
        
        for (idx = 0; idx < read; idx++)
        {
          switch (line[idx])
          {
            case '0' ... '9':
              asn = (asn * 10) + (line[idx] - '0');
              break;
            case ' ':
              ptr = (u_int8_t*)line;
              ptr += idx + 1;
              char* valStr = (char*)ptr;
              for (idx=0; idx < SKI_LENGTH; idx++)
              {                
                ski[idx] = au_hexToByte(valStr);
                valStr += 2;
              }
              idx = read;
              break;
            case '#':
              if (idx == 0)
              {
                // Skipp Line if # occurs as first character
                idx = read;
                skipLine = true;
                continue; // the for loop
              }
            default:
              break;
          }
        }
        if (!skipLine)
        {
          // Convert ASN into network format
          asn = htonl(asn);
          if (loadPublic)
          {
            // Generate a public key entry
            insertElement(asList, asn, algoID, true, (u_int8_t*)&ski);
          }
          if (loadPrivate)
          {
            // Generate a private key entry
            insertElement(asList, asn, algoID, false, (u_int8_t*)&ski);            
          }
        }
      }
    }
    fclose(fPtr);
  }
  else
  {
    printf ("ERROR: Cannot find keylist file '%s'\n", fName);
  }
  
  return asList;
}

/**
 * Print the given ASInfo instance. THe asn will be printed in human readable
 * host format.
 *  
 * @param c1 The initial character (+) if needed
 * @param c2 The down line character if more is to come (|)
 * @param asInfo The ASInfo to be printed.
 */
void printASInfo(char* c1, char* c2, TASInfo* asInfo)
{
  char dataStr[MAX_ASLIST_STR];
  memset(&dataStr, '\0', MAX_ASLIST_STR);
  
  printf ("%sASInfo\n", c1);
  if (asInfo == NULL)
  {
    printf ("%s  (NULL)\n", c2);
    return;
  }
  u_int32_t asn = ntohl(asInfo->key.asn);
  printf ("%s  +--ASN:        %u (%u.%u)\n", c2, asn, 
                                                 asn >> 16, 
                                                 asn & 0xFFFF);
  printf ("%s  +--AlgoID:     %u\n", c2, asInfo->key.algoID);
  au_binToHexString(asInfo->key.ski, SKI_LENGTH, dataStr);
  au_printHexAligned("%s  +--SKI:        %s\n",
                    "%s  |              %s\n", c2, dataStr, true);
  printf ("%s  +--KeyLength:  %u\n", c2, asInfo->key.keyLength);  
  au_binToHexString(asInfo->key.keyData, asInfo->key.keyLength, dataStr);
  au_printHexAligned("%s  +--keyData:    %s\n",
                     "%s  |              %s\n", c2, dataStr, true);
  printf ("%s  +--isPublic:   %s\n", c2, asInfo->isPublic ? "true" : "false");
  au_binToHexString(asInfo->ec_key, asInfo->ec_key_len, dataStr);
  au_printHexAligned("%s  +--ec_key:     %s\n",
                     "%s  |              %s\n", c2, dataStr, true);
  printf ("%s  +--ec_key_len: %u\n", c2, asInfo->ec_key_len);  
}

/**
 * Print the given ASList.
 * 
 * @param list The list to be printed.
 */
void printList(TASList* list)
{
  printf ("ASList\n");
  if (list == NULL)
  {
    printf ("  (NULL)\n");
  }
  else
  {
    ListElem* lelem = list->head;
    while (lelem != NULL)
    {
      if (lelem->next == NULL)
      {
        printASInfo("  +--", "     ", (TASInfo*)lelem->elem);
      }
      else
      {
        printASInfo("  +--", "  |  ", (TASInfo*)lelem->elem);      
      }
      lelem = lelem->next;
    }
  }
}

/**
 * Create an TASInfo element and set the initial values.
 * 
 * @param asn the ASN
 * @param algoID the Algorithm IP
 * @param ski the 20 byte SKI
 * 
 * @return The TASInfo instance or NULL
 */
TASInfo* createASInfo(u_int32_t asn, u_int8_t algoID, char* ski)
{
  TASInfo* info = malloc(sizeof(TASInfo));
  if (info != NULL)
  {
    memset(info, 0, sizeof(TASInfo));
    info->key.asn    = asn;
    info->key.algoID = algoID;
    if (ski != NULL)
    {
      int maxLen = strlen(ski) > sizeof(info->key.ski) ? sizeof(info->key.ski)
                                                       : strlen(ski);
      memcpy(info->key.ski, ski, maxLen);
    }
  }
  
  return info;
}

/**
 * Free the memory allocated by the AS info element. It is assumed the memory
 * is allocated using OPENSSL_malloc. Therefore this method uses OPENSSL_free.
 * 
 * @param info The element to be freed.
 */
void freeASInfo(void* info)
{
  TASInfo*   asinfo = (TASInfo*)info;
  if (asinfo != NULL)
  {
    if (asinfo->key.keyData != NULL)
    {
      OPENSSL_free(asinfo->key.keyData);
    }
    if (asinfo->ec_key != NULL)
    {
      EC_KEY_free(asinfo->ec_key);
    }
    memset(asinfo, 0, sizeof(TASInfo));
    
    free(info);
  }
}

/**
 * Free the ASList recursively.
 * 
 * @param asList The AS list to be freeed.
 */
void freeASList(TASList* asList)
{
  if (asList == NULL)
  {
    return;
  }
  
  emptyList((List*)asList, true, freeASInfo);
  free(asList);
}