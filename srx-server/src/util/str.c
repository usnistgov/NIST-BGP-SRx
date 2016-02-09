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
 * This file contains string utilities.
 *
 * @version 0.2.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 *   0.0.0 - 2010/04/26 - pgleichm
 *           * Code Created
 *   0.2.0 - 2011/01/07 - oborchert
 *           * Changelog added with version 0.2.0 and date 2011/01/07
 *           * Version tag added
 *           * Added trim, trim_right, trim_left
 * -----------------------------------------------------------------------------
 */

#include <string.h>
#include <ctype.h>
#include "util/str.h"

char* chomp(char* str)
{
  int pos = strlen(str) - 1;
  for (; pos >= 0; pos--)
  {
    if (isspace(str[pos]) == 0)
    {
      break;
    }
    str[pos] = '\0';
  }
  return str;
}

char* trim(char* str)
{
  char* out = str;
  out = rtrim(out);
  out = ltrim(out);
  return out;
}

char* rtrim(char* str)
{
  char* endChar = strrchr(str, '\0');
  // Start scanning from end until first non space is found
  while (endChar > str && isspace(*(endChar-1)))
  {
    --endChar;
  }
  *endChar='\0'; // Terminate the new String

  return str;
}

char* ltrim(char* str)
{
  // Determine string termination
  char* endChar = strrchr(str, '\0');
  // Scan forward until first non space is found.
  while (str < endChar && isspace(*str))
  {
    str++;
  }

  return str;
}

