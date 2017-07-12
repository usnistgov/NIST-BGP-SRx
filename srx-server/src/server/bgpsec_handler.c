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
 * @version 0.5.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.5.0.0  - 2017/07/08 - oborchert
 *            * Added some more memory housekeeping to validateSignature
 *          - 2017/07/05 - oborchert
 *            * Moved validation into this handler (renamed validateSignature 
 *              into validateUpdate)
 *            * Updated cache creation function - removed unused parameters
 *          - 2017/06/16 - kyehwanl
 *            * Added dealing with SCA
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Added Changelog
 *            * Fixed speller in documentation header
 * 0.1.0    - 2010/04/15 -pgleichm
 *            * Code created.
 */

#include "server/bgpsec_handler.h"
#include "server/main.h"
#include "util/log.h"

bool createBGPSecHandler(BGPSecHandler* self, KeyCache* keyCache)
{
  LOG(LEVEL_DEBUG, FILE_LINE_INFO
                 " createBGPSecHandler is not implemented yet - returns true!");
  self->keyCache = keyCache;
  self->srxCAPI = getSrxCAPI();
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

/**
 * Validates the given bgpsec update data.
 *
 * The return value is SRx_RES_VALID or SRx_RES_INVALID
 *
 * @param self The BGPsec Handler itself
 * @param update the given update to be validated
 * 
 * @return SRx_RES_VALID or SRx_RES_INVALID
 */
uint8_t validateSignature(BGPSecHandler* self, UC_UpdateData* update)
{
  u_int8_t retVal = SRx_RESULT_DONOTUSE;
  
  /* making Validation pdu */
  SCA_BGPSecValidationData valdata;
  memset(&valdata, 0, sizeof(SCA_BGPSecValidationData));
  valdata.myAS             = update->myAS;
  valdata.status           = API_STATUS_OK;
  valdata.bgpsec_path_attr = (u_int8_t*)update->bgpsec_path;
  valdata.nlri             = &update->nlri;

  /* call API's validate call */
  retVal = (self->srxCAPI->validate(&valdata) == API_VALRESULT_VALID)
            ? SRx_RESULT_VALID
            : SRx_RESULT_INVALID;

  // Free possible generated hash data
  if (valdata.hashMessage[0] != NULL)
  {
    if (!self->srxCAPI->freeHashMessage(valdata.hashMessage[0]))
    {
      free(valdata.hashMessage[0]);
    }
    valdata.hashMessage[0] = NULL;
  }
  if (valdata.hashMessage[1] != NULL)
  {
    if (!self->srxCAPI->freeHashMessage(valdata.hashMessage[1]))
    {
      free(valdata.hashMessage[1]);
    }
    valdata.hashMessage[1] = NULL;
  }

  return retVal;
}

bool createSignature(BGPSecHandler* self)
{
  LOG(LEVEL_DEBUG, FILE_LINE_INFO
                   " createSignature is not implemented yet - returns false!");
  return false;
}

