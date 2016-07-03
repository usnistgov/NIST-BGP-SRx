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
 * ASNTokenizer allows to retrieve all AS numbers from a string containing 
 * a list of AS numbers. The separator between AS numbers can be any character 
 * except 0-9 and "." dot. Other than in strtok the input string will NOT be 
 * altered.
 *
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *   0.1.0 - 2015/08/04 - oborchert
 *           * Created File.
 */
#include <string.h>
#include "ASNTokenizer.h"

/**
 * Data structure for global tokenizer (not thread safe)
 */
tASNTokenizer globalTokenizer;

/**
 * Generate a global ASN tokenizer.
 * 
 * @param string the String containing the AS numbers
 */
void asntok(char* string)
{
  asntok_th(string, &globalTokenizer);
}

/**
 * Generate a global ASN tokenizer.
 * 
 * @param string the String containing the AS numbers
 * @param globalTokenizer The tokenizer to use internally. This allows being
 *                        threadsafe
 * 
 */
void asntok_th(char* string, tASNTokenizer* tokenizer)
{
  tokenizer->string = string;
  tokenizer->strPtr = string;
}


/**
 * Return the next asn number and write it into "asn"
 * 
 * @param asn The address of the variable where to write the value of the asn
 *            into
 * 
 * @return true if a token was found, otherwise false. 
 */
bool asntok_next(u_int32_t* asn)
{
  u_int32_t tmpASN = *asn;
  bool retval = asntok_next_th(&tmpASN, &globalTokenizer);
  *asn = tmpASN;
  return retval;
}

/**
 * Return the next asn number and write it into "asn"
 * 
 * @param asn The address of the variable where to write the value of the asn
 *            into
 * @param globalTokenizer the tokenizer to be used
 * 
 * @return true if a token was found, otherwise false.
 */
bool asntok_next_th(u_int32_t* asn, tASNTokenizer* tokenizer)
{
  if (tokenizer->strPtr == NULL)
  {
    return false;
  }
  int strLen = strlen(tokenizer->strPtr);
  u_int16_t highBytes = 0;
  u_int32_t locASN = 0;
  bool go = strLen > 0;
  bool found = false;
  while (go)
  {
    char c = *tokenizer->strPtr;
    switch (c)
    {
      case '0' ... '9':
        found = true;
        locASN = (locASN * 10) + (*(tokenizer->strPtr) - '0');
        break;
      case '.':
        highBytes = locASN;
        locASN = 0;
        break;
      default:        
        go = !found;
        break;
    }
    strLen--;
    go = go && (strLen > 0);
    tokenizer->strPtr++;
  }
  
  if (found)
  {
    locASN = locASN | (highBytes << 16);
    *asn = locASN;
  }
  return found;
}

/**
 * Reset the global tokenizer to the beginning of the string.
 */
void asntok_reset()
{
  asntok_reset_th(&globalTokenizer);
}

/**
 * Reset the given tokenizer to the beginning of the string.
 */
void asntok_reset_th(tASNTokenizer* tokenizer)
{
  tokenizer->strPtr = tokenizer->string;
}

/**
 * Initialized the global tokenizer to be empty.
 */
void asntok_clear()
{
  asntok_clear_th(&globalTokenizer);
}

/**
 * Initialized the given tokenizer to be empty.
 * 
 * @param tokenizer the Tokenizer to be emptied.
 */
void asntok_clear_th(tASNTokenizer* tokenizer)
{
  tokenizer->string = NULL;
  tokenizer->strPtr = NULL;
}
