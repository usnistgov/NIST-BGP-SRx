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
 * File contains methods to test API.
 * 
 * @version 0.1.2.2
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 *   0.1.2.2 - 2016/03/25 - oborchert
 *             * Fixed BZ898 which caused the test tool not to read the provided
 *               configuration file.
 *   0.1.2.0 - 2015/12/01 - oborchert
 *             * Removed unused header bgpsec_openssl/bgpsec_openssh.h
 *           - 2015/11/03 - oborchert
 *             * Removed ski and algoID from struct BGPSecSignData, both data 
 *               fields are part of the BGPSecKey structure. (BZ795)
 *             * modified function signature of sign_with_id (BZ788)
 *   0.1.0   - October 7, 2015 - oborchert
 *             * Moved file back into project.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <openssl/bio.h>
#include "srx/srxcryptoapi.h"

/* informational */
#define LOG_ERR     3
/* informational */
#define LOG_INFO    6
/* debug-level messages */
#define LOG_DEBUG   7 
 /* The maximum number of keys */
#define MAX_NO_KEYS   10
/* The number of as paths */
#define MAX_NO_ASPATH 3

#ifndef SYSCONFDIR
#define SYSCONFDIR "."
#endif

#define CONF_FILE SYSCONFDIR "/srxcryptoapi.conf"

/**
 * Similar to assert except no ERROR will be thrown.
 * @param assertion
 */
static void report(bool assertion)
{
  if (!assertion)
  {
    printf("\n********************* ASSERT FAILED *************************\n");
  }
}

#define NO_KEYS 5

static void _checkParams(int argc, char** argv, SRxCryptoAPI* crypto)
{
  int idx = 0;
  
  if (crypto != NULL)
  {    
    for (; idx < argc - 1; idx++)
    {
      if (argv[idx][0] == '-' )
      {
        if (strlen(argv[idx]) > 1)
        {
          switch (argv[idx][1])
          {
            case 'c' : 
              idx++;
              if (idx < argc) // flipped variables BZ898
              {
                crypto->configFile = argv[idx];
              }
              break;
            default:
              break;
          }
        }
      }
    }
  }
  
  if (crypto->configFile == NULL)
  {
    crypto->configFile = CONF_FILE;        
  }
}

int main(int argc, char** argv)
{     
  SRxCryptoAPI* crypto = malloc(sizeof(SRxCryptoAPI));
  memset (crypto, 0, sizeof(SRxCryptoAPI));
  
  _checkParams(argc, argv, crypto);
  int initVal = 0;
  sca_status_t status = API_STATUS_OK;
  initVal = srxCryptoInit(crypto, &status);

  // For now just to disable the compiler warning
  report (true);
    
  if (initVal)
  {
    printf ("API initialized!\n");
  }
  else
  {
    printf ("Failure initializing API!\n");
  }
  
  status = API_STATUS_OK;
  srxCryptoUnbind(crypto, &status);
  free(crypto);
  printf ("done\n");
  return 0;
}