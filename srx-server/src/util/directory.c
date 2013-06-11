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
/*
 * 04/26/2010
 */

#include <stdio.h>
#ifdef unix
  #include <unistd.h>
#endif
#include "directory.h"

bool fileIsReadable(const char* path) {
#ifdef unix
  return (access(path, R_OK) == 0);
#else
  FILE* fh;
  bool  readable;

  fh = fopen(path, "r");
  readable = (fh != NULL);
  fclose(fh);
  return readable;
#endif
}

