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
 * We would appreciate acknowledgement if the software is used.
 * 
 * NIST ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" CONDITION AND
 * DISCLAIM ANY LIABILITY OF ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING
 * FROM THE USE OF THIS SOFTWARE.
 * 
 * 
 * This software might use libraries that are under GNU public license or
 * other licenses. Please refer to the licenses of all libraries required 
 * by thsi software.
 *
 */
/**
 * @file debug.c
 * @date Created: 12/28/2009
 */

#include <stdio.h>
#include <ctype.h>
#include "debug.h"

/** Number of Bytes per line (multiple of 4) */
#define BYTES_PER_LINE  16
/** Number of groups */
#define BYTES_PER_GROUP 4

void dumpHex(FILE* stream, void* data, int size) {
  uint8_t* bytes  = (uint8_t*)data;
  int      idx, cnum;

  while (size > 0) {
    fprintf(stream, "%04lX [", (bytes - (uint8_t*)data));
    
    // Last line
    cnum = size < BYTES_PER_LINE ? size : BYTES_PER_LINE;

    // Hex
    for (idx = 0; idx < cnum; idx++) {
      fprintf(stream, "%02X", bytes[idx]);
      
      // New group - but not at the end of the line
      if ((idx % BYTES_PER_GROUP == BYTES_PER_GROUP - 1)
          && (idx + 1 < cnum)) {
        fputc(' ', stream);
      }
    }

    // Fill
    if (cnum < BYTES_PER_LINE) {
      idx = (BYTES_PER_LINE - cnum); // Characters less
      idx = (idx / BYTES_PER_GROUP) + idx * 2;
      fprintf(stream, "%*c", idx, ' ');
    }

    // ASCII
    fprintf(stream, "] ");
    for (idx = 0; idx < cnum; idx++) {
      fputc(isprint(bytes[idx]) ? bytes[idx] : '.', stream);

    }
    fprintf(stream, "\n");

    bytes += cnum;
    size  -= cnum;
  }
}

bool stringToFile(const char* filename, bool append, const char* str) {
  FILE* fh;

  fh = fopen(filename, append ? "at" : "wt");
  if (fh == NULL) {
    return false;
  }
  fputs(str, fh);
  fclose(fh);
  return true;
}

