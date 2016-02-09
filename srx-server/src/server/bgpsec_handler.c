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
 *
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Added Changelog
 *            * Fixed speller in documentation header
 * 0.1.0    - 2010/04/15 -pgleichm
 *            * Code created. 
 */

#include "server/bgpsec_handler.h"
#include "util/log.h"

bool createBGPSecHandler(BGPSecHandler* self, KeyCache* keyCache,
                         const char* serverHost, int serverPort) 
{
  LOG(LEVEL_DEBUG, FILE_LINE_INFO 
                 " createBGPSecHandler is not implemented yet - returns true!");
  self->keyCache = keyCache;
  return true;
}

void releaseBGPSecHandler(BGPSecHandler* self) 
{
  LOG(LEVEL_DEBUG, 
      FILE_LINE_INFO "releaseBGPSecHandler is not implemented yet!");
}

bool loadPrivateKey(BGPSecHandler* self, const char* filename) 
{
  LOG(LEVEL_DEBUG, 
      FILE_LINE_INFO "loadPrivateKey is not implemented yet!");
  return true;
}

uint8_t validateSignature(BGPSecHandler* self) 
{
  LOG(LEVEL_DEBUG, FILE_LINE_INFO 
                  " validateSignature is not implemented yet - returns valid!");
  return SRx_RESULT_VALID;
}

bool createSignature(BGPSecHandler* self) 
{
  LOG(LEVEL_DEBUG, FILE_LINE_INFO 
                   " createSignature is not implemented yet - returns false!");
  return false;
}

