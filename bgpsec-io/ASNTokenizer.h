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

#include <sys/types.h>
#include <stdbool.h>

#ifndef ASNTOKENIZER_H
#define	ASNTOKENIZER_H

typedef struct {
  char* string;
  char* strPtr;
} tASNTokenizer;


/**
 * Generate a global ASN tokenizer.
 * 
 * @param string the String containing the AS numbers
 */
void asntok(char* string);

/**
 * Generate a global ASN tokenizer.
 * 
 * @param string the String containing the AS numbers
 * @param globalTokenizer The tokenizer to use internally. This allows being
 *                        threadsafe
 * 
 */
void asntok_th(char* string, tASNTokenizer* tokenizer);

/**
 * Return the next asn number and write it into "asn"
 * 
 * @param asn The address of the variable where to write the value of the asn
 *            into
 * 
 * @return true if a token was found, otherwise false.
 */
bool asntok_next(u_int32_t* asn);

/**
 * Return the next asn number and write it into "asn"
 * 
 * @param asn The address of the variable where to write the value of the asn
 *            into
 * @param globalTokenizer the tokenizer to be used
 * 
 * @return true if a token was found, otherwise false.
 */
bool asntok_next_th(u_int32_t* asn, tASNTokenizer* tokenizer);

/**
 * Reset the globale tokenizer to the beginning of the string.
 */
void asntok_reset();

/**
 * Reset the given tokenizer to the beginning of the string.
 * 
 * @param tokenizer The tokenizer to be reset
 */
void asntok_reset_th(tASNTokenizer* tokenizer);
  
/**
 * Initialized the global tokenizer to be empty.
 */
void asntok_clear();

/**
 * Initialized the given tokenizer to be empty.
 * 
 * @param tokenizer the Tokenizer to be emptied.
 */
void asntok_clear_th(tASNTokenizer* tokenizer);

#endif	/* ASNTOKENIZER_H */

