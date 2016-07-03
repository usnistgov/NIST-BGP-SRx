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
 * @version 0.2.0.2
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 * 0.2.0.2 - 2016/06/29 - oborchert
 *           * Removed function __createSCAPrefix - not used anymore.
 *         - 2016/06/27 - oborchert
 *           * Fixed some printout issues.
 * 0.2.0.1 - 2016/06/24 - oborchert
 *           * Solved issues with iBGP sessions.
 * 0.2.0.0 - 2016/05/13 - oborchert
 *           * Added maximum processing of updates. BZ961
 *         - 2016/05/10 - oborchert
 *           * Removed unused code
 *           * Moved srxcryptoapi generation into the CAPI processing. This is
 *             the only place where it is being used. For loading keys capi 
 *             does not need to be initialized.
 *         - 2016/05/06 - oborchert
 *           * Modified main to first load the parameters and then load CAPI
 *           * Added capability to use customized srx-scrypto-api config file.
 * 0.1.1.0 - 2016/03/09 - oborchert
 *           * removed un-used test method process.
 *         - 2016/03/09 - oborchert
 *           * Fixed some bugs - mainly in signature generation.
 * 0.1.0.0 - 2015/07/31 - oborchert
 *           * Created File.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>
#include <libconfig.h>
#include <time.h>
#include <readline/chardefs.h>
#include <openssl/ossl_typ.h>
#include <netinet/in.h>
#include <linux/rtnetlink.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <srx/srxcryptoapi.h>
#include <math.h>
#include "ASList.h"
#include "updateStackUtil.h"
#include "antd-util/prefix.h"
#include "antd-util/stack.h"
#include "antd-util/printer.h"
#include "bgp/BGPHeader.h"
#include "bgp/BGPSession.h"
#include "bgp/BGPFinalStateMachine.h"
#include "bgp/printer/BGPHeaderPrinter.h"
#include "bgp/printer/BGPUpdatePrinter.h"
#include "bgp/printer/BGPPrinterUtil.h"
#include "bgpsec/BGPSecPathBin.h"
#include "bgpsec/Crypto.h"
#include "cfg/configuration.h"
#include "cfg/cfgFile.h"
#include "player/player.h"

/** Only be used as parameter for preloadKeys */
#define LOAD_KEYS_PRIVATE true
/** Only be used as parameter for preloadKeys */
#define LOAD_KEYS_PUBLIC  false
/** For time measurement */
#define TIME_BILLION 1000000000L

/**
 * Contains a linked list of AS numbers including the assigned BGPSEC keys.
 */
static TASList* asList = NULL;

/**
 * This struct is used for CAPI mode statistics
 */
typedef struct
{
  u_int64_t totalTime;
  u_int32_t totalSegments;
} BIO_Statistics;

/**
 * Compare the given byte streams byte by byte.
 * 
 * @param m1 the first byte stream to compare
 * @param m2 the second byte stream to compare
 * @param length the length of the byte streams
 * 
 * @return 0 if both memory blocks are same, otherwise the number of bytes that
 *         are the same.
 */
int myCompare(u_int8_t* m1, u_int8_t* m2, int length)
{
  int idx;
  for (idx = 0; idx < length; idx++)
  {
    if (*m1 != *m2)
    {
      break;
    }
    m1++;
    m2++;
  }
  
  return idx != length ? ++idx : 0;
}

/**
 * Print the given message as an error. If msg is NULL a generic message will be
 * printed.
 * 
 * @param msg The error message or NULL
 */
void _errorParam(char* msg)
{
  if (msg == NULL)
  {
    printf("Error in parameters!\n");
  }
  else
  {
    printf("ERROR: %s\n", msg);
  }
}

/**
 * Start the BGP router session
 * 
 * @param params The program parameters
 * 
 * @return the exit value.
 */
static int _runBGPRouterSession(PrgParams* params)
{
    // perform BGP  
  BGPSession* session = createBGPSession(1024, &params->bgpConf, NULL);
  // Configure BGP requirements - set all true except route refresh
  memset (&(session->bgpConf.capConf), 1, sizeof(BGP_Cap_Conf));
  session->bgpConf.capConf.bgpsec_snd_v6 = false;
  session->bgpConf.capConf.bgpsec_rcv_v6 = false;
  session->bgpConf.capConf.route_refresh = false;
  session->bgpConf.capConf.mpnlri_v6     = false;
  session->run = true;
  
  bool useGlobalMemory = true;
  u_int8_t binBuff[SESS_MIN_MESSAGE_BUFFER];
  memset(&binBuff, 0, sizeof(binBuff));
  BGPSEC_IO_Buffer ioBuff;
  memset(&ioBuff, 0, sizeof(ioBuff));
  ioBuff.data     = (u_int8_t*)&binBuff;
  ioBuff.dataSize = sizeof(binBuff);
          
  u_int8_t msgBuff[SESS_MIN_MESSAGE_BUFFER]; //10KB Message Size
  memset(&msgBuff, 0, sizeof(msgBuff));
  
// start BGP session
  pthread_t bgp_thread;
  
  if (pthread_create(&bgp_thread, NULL, runBGP, session))
  {
    printf ("Error creating BGP thread!\n");
    return EXIT_FAILURE;
  }
  
  BGP_PathAttribute*   bgpPathAttr = NULL;
  BGP_UpdateMessage_1* bgp_update  = NULL;
  int               stopTime       = session->bgpConf.disconnectTime;
  bool              hasBinTraffic  = params->binInFile[0] != '\0';
  bool              inludeStdIn = true;
  bool              sendData    = (!isUpdateStackEmpty(params, inludeStdIn) 
                                   || hasBinTraffic) 
                                  && (params->maxUpdates != 0);

  UpdateData*       update   = NULL;
  BGPSEC_PrefixHdr* prefix   = NULL;
  BGPSEC_IO_Record  record;
  memset (&record, 0, sizeof(BGPSEC_IO_Record));
  
  // Prepare reading from file as well.
  FILE* dataFile = NULL;
  if (hasBinTraffic)
  {
    dataFile = fopen(params->binInFile, "r");
    hasBinTraffic = dataFile != NULL;
    if (hasBinTraffic)
    {
      hasBinTraffic = !feof(dataFile);
    }
  }
        
  while (session->run)
  {
    // Sleep in 1 second intervals until BGP session is established.
    if (session->fsm.state != FSM_STATE_ESTABLISHED)
    {
      sleep(1);
      continue;
    }    
                
    // Now session is established, first send all updates in the stack then
    // all stdin data followed by binary in data
    while (session->fsm.state == FSM_STATE_ESTABLISHED && sendData)
    {
      prefix      = NULL;
      bgpPathAttr = NULL;
      bgp_update  = NULL;

      // set for the next run.      
      sendData = --params->maxUpdates != 0;
      bool useMPNLRI = params->bgpConf.useMPNLRI;
      bool iBGP = session->bgpConf.asn == session->bgpConf.peerAS;
      
      // First check the stack and stdin
      if (!isUpdateStackEmpty(params, inludeStdIn))
      {
        record.recordType = BGPSEC_IO_TYPE_BGPSEC_ATTR;
        update    = (UpdateData*)popStack(&params->updateStack);

        if (update != NULL)
        {
          // the following pointer points into globally managed memory and
          // therefore does not need to be freed
          prefix = (BGPSEC_PrefixHdr*)&update->prefixTpl;
          bgpPathAttr = (BGP_PathAttribute*)generateBGPSecAttr(useGlobalMemory, 
                      update->pathStr, NULL, &session->bgpConf, prefix, asList);
          // if bgpsec attribute could not be generated use AS_PATH and no 
          // MPNLRI encoding for V4 prefixes
          useMPNLRI = useMPNLRI & (bgpPathAttr != NULL);
          
          if (bgpPathAttr == NULL)
          {
            // Now this can have two reasons:
            // (1) The signing failed -> check for mode NS_BGP4 as fallback
            // (2) This is an origination and it is an iBGP session -> BGP4
            //     In the case it is an iBGP session and no origin announcement
            //     then the bgpsec attribute was generated up to this router
            //     and we do not end up here.
            bool iBGP_Announcement = false;
            if ((strlen(update->pathStr) == 0) && iBGP)
            {
              // Now we do need to generate the BGP4 update regardless what is
              // scripted in the ns_mode (fallback for missing signatures)
              iBGP_Announcement = true;
            }
            if (   iBGP_Announcement
                || (session->bgpConf.algoParam.ns_mode == NS_BGP4))
            {            
              // Use the buffer normally used for the binary stream, it will
              // be fine.
              // Generate an BPP4 packet.
              // added iBGP detection.
              bgpPathAttr = generateBGP_PathAttr(session->bgpConf.asn, iBGP,
                                  update->pathStr, binBuff, 
                                  SESS_MIN_MESSAGE_BUFFER);
            }
          }
        }        
      }
      else if (hasBinTraffic)
      {
        inludeStdIn = false;
        hasBinTraffic = loadData(dataFile, htonl(session->bgpConf.asn), 
                                 htonl(session->bgpConf.peerAS), 
                                 BGPSEC_IO_TYPE_ALL, &record, &ioBuff);
        if (hasBinTraffic)
        {
          switch (record.recordType)
          {
            case BGPSEC_IO_TYPE_BGPSEC_ATTR:
                // Prepare the attribute memory
              bgpPathAttr = (BGP_PathAttribute*)ioBuff.data;
              prefix = (BGPSEC_PrefixHdr*)&record.prefix;
              break;
            case BGPSEC_IO_TYPE_BGP_UPDATE:
              useMPNLRI = false; // No MPNLRI for V4 addresses and AS_PATH
              bgp_update = (BGP_UpdateMessage_1*)ioBuff.data;
              break;
            default:
              printf("ERROR: Invalid record type [%u]!\n", record.recordType);
              break;
          }
        }
      }
      else
      {
        sendData = false;
      }
        
      if (bgpPathAttr != NULL)
      {
        // Set no mpnlri if iBGP session. Will be overwritten for V6
        u_int32_t locPref = iBGP ? BGP_UPD_A_FLAGS_LOC_PREV_DEFAULT : 0;
        createUpdateMessage(msgBuff, sizeof(msgBuff), bgpPathAttr, 
                            BGP_UPD_A_FLAGS_ORIGIN_INC, locPref,
                            params->bgpConf.bgpIdentifier, prefix, useMPNLRI);
        // Maybe store the update ?????          
        bgp_update = (BGP_UpdateMessage_1*)msgBuff;
      }
      
      if (bgp_update != NULL)
      {
        sendUpdate(session, bgp_update);        
      }
      
      // Free the update information if it still exists. Don't do it earlier
      // because if the update was used, the prefix links to it.
      if (update != NULL)
      {
        freeUpdateData(update);
        update = NULL;        
      }      
    }
    
    // the BGP session will take care of hold timer and disconnect timers.
    if (session->bgpConf.disconnectTime != 0)
    {
      if (stopTime-- == 0)
      {
        // initiate a stop by switching the FSM
        printf ("Initiating session shutdown to AS %u\n", 
                session->bgpConf.peerAS);
        session->run = false;
      }
      else if (session->fsm.state == FSM_STATE_ESTABLISHED && !sendData)
      {
        // We reached the end of sending data, now just wait.
        sleep(1);
        continue;
      }
    }
  }

  if (dataFile)
  {
    fclose(dataFile);
    dataFile = NULL;
  }  
  
  void* retVal = NULL;
  pthread_join(bgp_thread, &retVal);
  
  if (retVal != NULL)
  {
    printf("ERROR %i\n", *((int* )retVal));
  }
  
  freeBGPSession(session);
  freeData((u_int8_t*)bgpPathAttr);
  
  return EXIT_SUCCESS;
}

// This struct is currently a dirty hack until a struct is provided by 
// srxcryptoapi
typedef struct {
  u_char family;
  u_char prefixlen;
  union
  {
    u_char prefix;
    struct in_addr prefix4;
#ifdef HAVE_IPV6
    struct in6_addr prefix6;
#endif /* HAVE_IPV6 */
    struct
    {
      struct in_addr id;
      struct in_addr adv_router;
    } lp;
    u_char val[8];
  } u __attribute__ ((aligned (8)));
} bgpsec_openssl_prefix;

////////////////////////////////////////////////////////////////////////////////
//  CAPI Processing
////////////////////////////////////////////////////////////////////////////////
/**
 * process the BGPSec Path attribute and call the SRxCryptoAPI for validation.
 * 
 * @param capi The SrxCryptoApi to test.
 * @param params The program parameters containing all session information.
 * @param prefix The prefix of the update (network format)
 * @param pathAttr The path attribute itself. (network format)
 * @param elapsedTime OUT - The time it took to process the validation.
 * @param status Returns the status flag from the validation process.
 * 
 * @return the validation result as specified in SrxCryptoApi
 */
static int __capiProcessBGPSecAttr(SRxCryptoAPI* capi, PrgParams* params, 
                                   BGPSEC_PrefixHdr* prefix, 
                                   BGPSEC_PathAttribute* pathAttr,
                                   u_int64_t* elapsedTime, sca_status_t* status)
{
  SCA_BGPSecValidationData valdata;
  memset (&valdata, 0, sizeof(SCA_BGPSecValidationData));
  
  // Here the myAS is the peer, not me because we call the validate out of the
  // peer's perspective
  valdata.myAS   = htonl(params->bgpConf.peerAS);  
  valdata.bgpsec_path_attr = (u_int8_t*)pathAttr;
  valdata.nlri   = (SCA_Prefix*)prefix;
  valdata.status = API_STATUS_OK;

//  printBGPSEC_PathAttr(pathAttr, NULL, false);
  int valResult = API_VALRESULT_INVALID;
  
  // Check if keys need to be registered
  if (params->bgpConf.algoParam.pubKeysStored > 0)
  {
    int idx = 0; 
    sca_status_t keyStatus = API_STATUS_OK;
    int regResult = API_SUCCESS;
    for (; idx < params->bgpConf.algoParam.pubKeysStored; idx++)
    {
      regResult = capi->registerPublicKey(params->bgpConf.algoParam.pubKey[idx], 
                                          &keyStatus);
      if (regResult == API_FAILURE)
      {
        if ((keyStatus & API_STATUS_ERROR_MASK) > 0)
        {
          printf("ERROR: Registering public key:\n");
          sca_printStatus(keyStatus);
        }
      }      
    }
  }
  
  // INCLUDING TIME MEASUREMENT
  u_int64_t elapsed;  
  struct timespec start;
  struct timespec end;
  clock_gettime(CLOCK_MONOTONIC, &start);

  // Call Validator
  valResult = capi->validate(&valdata);
  
  clock_gettime(CLOCK_MONOTONIC, &end);
  elapsed = TIME_BILLION 
            * (end.tv_sec - start.tv_sec)
            + end.tv_nsec - start.tv_nsec;
  
  if (elapsedTime != NULL)  
  {
      *elapsedTime = elapsed;
  }
    
  if (valResult == API_VALRESULT_INVALID)
  {
    if (params->bgpConf.printOnInvalid)
    {
      printf("Path validation: INVALID\n");
      sca_printStatus(valdata.status);
    }
  }
  
  if (status != NULL)
  {
    *status = valdata.status;
  }
  
  // The digest needs to be free'd
  int idx;
  for (idx = 0; idx < 2; idx++)
  {
    if (valdata.hashMessage[idx] != NULL)
    {
      capi->freeHashMessage(valdata.hashMessage[idx]);
      valdata.hashMessage[idx] = NULL;
    }
  }
  
  return valResult;  
}

/**
 * Clean the public keys in the session parameter
 * 
 * @param params the session parameter 
 */
static void __cleanPubKeys(PrgParams* params)
{
  // Use global data
  if (params->bgpConf.algoParam.pubKeysStored != 0)
  {
    // clean the key array
    memset(params->bgpConf.algoParam.pubKey, 0, 
           params->bgpConf.algoParam.pubKeysStored * sizeof(BGPSecKey*));
    params->bgpConf.algoParam.pubKeysStored = 0;
  }  
}

/**
 * Register the keys found in the binary file with the SRxCryptoAPI.
 * 
 * @param capi The API module
 * @param ioBuff The keys.
 */
static void __capiRegisterPublicKeys(SRxCryptoAPI* capi, 
                                     BGPSEC_IO_Buffer* ioBuff)
{
  u_int16_t* wordVal = (u_int16_t*)ioBuff->keys;
  u_int16_t  length = *wordVal;
  u_int8_t*  ptr = ioBuff->keys + sizeof(u_int16_t);
  
  BGPSEC_IO_KRecord* kRecord = NULL;
  BGPSecKey          bgpsec_key;
  sca_status_t       myStatus;
  
  while (length != 0)
  {    
    kRecord = (BGPSEC_IO_KRecord*)ptr;

    ptr    += sizeof(BGPSEC_IO_KRecord);
    length -= sizeof(BGPSEC_IO_KRecord);
    
    bgpsec_key.algoID    = kRecord->algoID;
    bgpsec_key.asn       = kRecord->asn;
    memcpy(bgpsec_key.ski, kRecord->ski, SKI_LENGTH);
    bgpsec_key.keyLength = ntohs(kRecord->keyLength);
    bgpsec_key.keyData   = ptr;    
    ptr    += bgpsec_key.keyLength;
    length -= bgpsec_key.keyLength;
    
    if (capi->registerPublicKey(&bgpsec_key, &myStatus) == API_FAILURE)
    {
      printf ("ERROR: Registering public Keys!\n");        
      sca_printStatus(myStatus);
      break;
    }
  }
}

/**
 * Run the SRxCryptoAPI test calls.
 * 
 * @param params The program parameters
 * @param capi The SRx Crypto API
 * 
 * @return the exit value.
 */
static int _runCAPI(PrgParams* params, SRxCryptoAPI* capi)
{
  UpdateData*           update   = NULL;
  BGPSEC_PathAttribute* pathAttr = NULL;
  BGPSEC_PrefixHdr*     prefix   = NULL;
  
  BGPSEC_IO_Buffer ioBuff;
  memset (&ioBuff, 0, sizeof(BGPSEC_IO_Buffer));
  ioBuff.data     = malloc(MAX_DATABUF);
  ioBuff.dataSize = MAX_DATABUF;
  ioBuff.keys     = malloc(MAX_DATABUF);
  ioBuff.keySize  = MAX_DATABUF;
    
  int   valResult  = 0;
  
  // First, run the update Stack
  int error       = 0;
  int keyNotFound = 0;
  int invalid     = 0;
  int processed   = 0;
  __cleanPubKeys(params);
  
  BIO_Statistics statistics[2];
  memset (statistics, 0, sizeof(BIO_Statistics)*2);
  
  sca_status_t valStatus = API_STATUS_OK;
  u_int32_t    segments  = 0;
  u_int64_t    elapsed   = 0;
          
  while (!isUpdateStackEmpty(params, true) && (params->maxUpdates != 0))
  {
    params->maxUpdates--;
    update   = (UpdateData*)popStack(&params->updateStack);
    prefix   = (BGPSEC_PrefixHdr*)&update->prefixTpl;  
    
    segments = 0;
    pathAttr = (BGPSEC_PathAttribute*)generateBGPSecAttr(true, update->pathStr, 
                                                         &segments,
                                                         &params->bgpConf, 
                                                         prefix, asList);
    elapsed   = 0;
    valStatus = API_STATUS_OK;
    valResult = __capiProcessBGPSecAttr(capi, params, prefix, pathAttr,&elapsed,
                                        &valStatus);
    
    statistics[valResult].totalTime      += elapsed;
    statistics[valResult].totalSegments  += segments;
    
    // TODO: Check if cleanup is still needed.
    __cleanPubKeys(params);
    
    switch (valResult)
    {
      case API_VALRESULT_INVALID:
        invalid++;
        if ((valStatus & API_STATUS_ERROR_MASK) != 0)
        {
          error++;
        }
        else if ((valStatus & API_STATUS_INFO_KEY_NOTFOUND) != 0)
        {
          keyNotFound++;
        }
        processed++;
        break;
      case API_VALRESULT_VALID:
        processed++;
        break;
      default:
        processed++;
        printf("ERROR: API reports undefined validation result for update '%s'!\n", 
               update->pathStr);
        break;
    }
    freeUpdateData(update);          
  }
  
  if (params->binInFile[0] != '\0')
  {
    // Read all data from binary in file
    FILE* dataFile = fopen(params->binInFile, "r");
    BGPSEC_IO_Record record;
    BGPSEC_PathAttribute* pathAttr = NULL;
    // re-initialize the data buffer
    memset (ioBuff.data, 0, ioBuff.dataSize);
    
    if (dataFile)
    { 
      // re-initialize the data buffer.
      memset (ioBuff.data, 0, MAX_DATABUF);
      memset (ioBuff.keys, 0, MAX_DATABUF);
      
      // Make sure no previously stored keys are still in the cache      
      __cleanPubKeys(params);
      u_int32_t asn    = htonl(params->bgpConf.asn);
      u_int32_t peerAS = htonl(params->bgpConf.peerAS);
      while (loadData(dataFile, asn, peerAS, BGPSEC_IO_TYPE_BGPSEC_ATTR, 
                      &record, &ioBuff) 
             && (params->maxUpdates != 0))
      {
        params->maxUpdates--;
        pathAttr  = (BGPSEC_PathAttribute*)ioBuff.data;
        prefix    = (BGPSEC_PrefixHdr*)&record.prefix;
        __capiRegisterPublicKeys(capi, &ioBuff);
        
        elapsed       = 0;
        valStatus     = API_STATUS_OK;
        valResult     = __capiProcessBGPSecAttr(capi, params, prefix, pathAttr,
                                                &elapsed, &valStatus);
        
        statistics[valResult].totalSegments += ntohl(record.noSegments);
        statistics[valResult].totalTime     += elapsed;
        
        // TODO: Check if cleanup is still needed.
         __cleanPubKeys(params);               
         
        switch (valResult)
        {
          case API_VALRESULT_INVALID:
            invalid++;
            if ((valStatus & API_STATUS_ERROR_MASK) != 0)
            {
              error++;
            }
            else if ((valStatus & API_STATUS_INFO_KEY_NOTFOUND) != 0)
            {
              keyNotFound++;
            }
          case API_VALRESULT_VALID:
            processed++;
            break;
          default:
            processed++;
            printf("ERROR: API reports undefined validation result.\n");
            break;
        }        
        
        // re-initialize the beginning of the data buffer that contains the 
        // length field of data stored in the buffer.
        memset (ioBuff.data, 0, sizeof(BGPSEC_PathAttribute));
        memset (ioBuff.keys, 0, 2);        
      }
      fclose(dataFile);
      dataFile = 0;
    }  
    else
    {
      printf("ERROR: Could not open input file '%s'\n", params->binInFile);
    }
  }
  
  char* title[2] = {"Invalid\0", "Valid\0"};
  u_int64_t avgTimeUpd        = 0;
  u_int64_t avgTimePerSegment = 0;
  float     avgNoSegments     = 0.0;
  u_int32_t valid             = processed - invalid;
  int idx = 0;
  for (; idx <= API_VALRESULT_VALID; idx++)
  {
    processed = idx == API_VALRESULT_VALID ? valid : invalid;
    printf ("\nStatistics %s:\n=====================\n", title[idx]);
    avgTimeUpd = processed != 0 ? statistics[idx].totalTime / processed
                                : 0;
    avgTimePerSegment = statistics[idx].totalSegments != 0 
                        ? statistics[idx].totalTime / statistics[idx].totalSegments 
                        : 0;
    
    avgNoSegments = processed != 0 ? statistics[idx].totalSegments / processed 
                                   : 0;
  
    printf ("  %d updates (%u segments) in %llu ns processed\n", processed, 
            statistics[idx].totalSegments, 
            (long long unsigned int)statistics[idx].totalTime);
    printf ("  - average time per update:  %llu ns\n", 
            (long long unsigned int)avgTimeUpd);
    printf ("  - average time per segment: %llu ns\n", 
            (long long unsigned int)avgTimePerSegment);
    printf ("  - average number of segments per update: %1.2f\n", 
            avgNoSegments);
    if (idx == API_VALRESULT_INVALID)
    {
      if (error > 0)
      {
        printf (" - Invalid updates due to errors: %d\n", error);
      }
      if (keyNotFound > 0)
      {
        printf (" - Invalid updates due to missing key: %d\n", keyNotFound);
      }
    }
    else
    {
      double d = avgTimePerSegment > 0  ? floor(1000000000 / avgTimePerSegment)
                                        : 0;
      printf ("  - segments per second: %1.0f\n", d);      
    }
    printf ("\n");
  }
  free (ioBuff.data);
  ioBuff.dataSize = 0;
  free (ioBuff.keys);
  ioBuff.keySize = 0;

  return EXIT_SUCCESS;
}

/**
 * Generate the data and store it into a file.
 * 
 * @param params The program parameters.
 * @param type the type of traffic to be generated, BGP Updates or just the
 *        attribute
 * 
 * @return The exit code.
 */
static int _runGEN(PrgParams* params, u_int8_t type)
{
  int retVal = EXIT_SUCCESS;
  u_int8_t msgBuff[SESS_MIN_MESSAGE_BUFFER]; //10KB Message Size
  memset(&msgBuff, 0, SESS_MIN_MESSAGE_BUFFER);

  if (params->binOutFile[0] != '\0')
  {
    FILE* outFile = params->appendOut ? fopen(params->binOutFile, "a")
                                      : fopen(params->binOutFile, "w");
    if (outFile)
    {
      // move to function that also reads from stdin
      UpdateData* update = NULL;
      BGPSEC_PathAttribute* bgpsecPathAttr = NULL;
      BGPSEC_PrefixHdr* prefix = NULL;
      BGPSEC_IO_StoreData store;
      int attrSize     = 0;
      int msgLen       = 0;
      
      while (!isUpdateStackEmpty(params, true) && (params->maxUpdates != 0))
      {
        params->maxUpdates--;
        update = (UpdateData*)popStack(&params->updateStack);
        prefix = (BGPSEC_PrefixHdr*)&update->prefixTpl;
        
        // Use global data
        if (params->bgpConf.algoParam.pubKeysStored != 0)
        {
          // clean the key array
          memset(params->bgpConf.algoParam.pubKey, 0, 
                 params->bgpConf.algoParam.pubKeysStored * sizeof(BGPSecKey*));
          params->bgpConf.algoParam.pubKeysStored = 0;
        }
                
        u_int32_t segmentCount = 0;
        bool iBGP = params->bgpConf.asn == params->bgpConf.peerAS;
        u_int32_t locPref = iBGP ? BGP_UPD_A_FLAGS_LOC_PREV_DEFAULT : 0;
        bgpsecPathAttr = (BGPSEC_PathAttribute*)generateBGPSecAttr(true, 
                       update->pathStr, &segmentCount, &params->bgpConf, prefix, 
                       asList);        
        if (bgpsecPathAttr != NULL)
        {
          // Include the attribute header information.
          attrSize = ntohs(bgpsecPathAttr->attrLength)
                       + sizeof(BGPSEC_PathAttribute);
          store.prefix       = prefix;
          store.usesFake     = params->bgpConf.algoParam.fakeUsed;
          store.numKeys      = params->bgpConf.algoParam.pubKeysStored;
          store.keys         =  store.numKeys != 0 
                                ? params->bgpConf.algoParam.pubKey : NULL;
          store.segmentCount = segmentCount;
          switch (type)
          {            
            case BGPSEC_IO_TYPE_BGPSEC_ATTR:
              store.dataLength   = attrSize;
              store.data         = (u_int8_t*)bgpsecPathAttr;
              if (!storeData(outFile, BGPSEC_IO_TYPE_BGPSEC_ATTR, 
                             params->bgpConf.asn, params->bgpConf.peerAS, 
                             &store))
              {
                printf("ERROR: Error writing path %s\n", update->pathStr);
              }
              break;
              
            case BGPSEC_IO_TYPE_BGP_UPDATE:
              msgLen = createUpdateMessage(msgBuff, sizeof(msgBuff), 
                                 (BGP_PathAttribute*)bgpsecPathAttr, 
                                 BGP_UPD_A_FLAGS_ORIGIN_INC,
                                 locPref, params->bgpConf.bgpIdentifier, prefix, 
                                 params->bgpConf.useMPNLRI);
              store.dataLength = msgLen;
              store.data       = (u_int8_t*)msgBuff;
              if (!storeData(outFile, BGPSEC_IO_TYPE_BGP_UPDATE, 
                             params->bgpConf.asn, params->bgpConf.peerAS, 
                             &store))
              {
                printf("ERROR: Error writing path %s\n", update->pathStr);
              }
              break;
              
            default:
              printf("ERROR: Invalid type[%u]\n", type);              
          }                
        }

        freeUpdateData(update);          
      }
      fclose(outFile);
    }
  }
  else
  {
    printf("ERROR: Cannot generate data, out file is missing!\n");
    printSyntax();
    retVal = EXIT_FAILURE;
  }  
  
  return retVal;
}

/**
 * Do a preliminary sanity check of the provided settings.
 * 
 * @param params the program parameters
 * @param exitVal pointer to the return value
 * 
 * @return true if the program is good to continue or false otherwise
 */
static bool _checkSettings(PrgParams* params, int* exitVal)
{
  bool keepGoing = true;

  if (params->createCfgFile)
  {
    if (!generateFile((char*)params->newCfgFileName))
    {
      printf("ERROR: Could not generate configuration file \"%s\"\n",
              params->newCfgFileName);
      keepGoing = false;
      *exitVal  = EXIT_FAILURE;
    }
    else
    {
      printf("Configuration file \"%s\" successfully generated!\n",
              params->newCfgFileName);
      *exitVal  = EXIT_SUCCESS;
    }
    keepGoing = false;
  } 
  else
  {
    switch (params->type)
    {
      case OPM_GEN_B:
      case OPM_GEN_C:
        if (params->binOutFile[0] == '\0')
        {
          _errorParam("GEN mode but no output file specified!!");
          keepGoing = false;
        }
        if (params->binInFile[0] != '\0')
        {
          _errorParam("No binary input file allowed in GEN mode!!");
          keepGoing = false;          
        }
        break;
      default:
        break;
    }
  }
  
  return keepGoing;
}

/*
 * Start the BGPIO program
 */
int main(int argc, char** argv) 
{
  // First load parametrers  
  PrgParams params;
  initParams(&params);
  
  SRxCryptoAPI* capi = NULL;
  
  int  retVal = parseParams(&params, argc, argv);
  bool keepGoing = true;
  bool printDone = true;
  
  switch (retVal)
  {
    case -1: // ERROR
      _errorParam(params.errMsgBuff);
    case 0:  // Help screen and version number
      keepGoing = false;
      printDone = false;
      break;
    default:
      // All went well, Check for Input settings
      keepGoing = _checkSettings(&params, &retVal);
      break;
  }
    
  if (keepGoing)
  {
    printf ("Starting %s...\n", PACKAGE_STRING);
    // initialize the main memory;
    initData();

    // @TODO: line below can be deleted once srxcrytpoapi is configured correctly   
    params.bgpConf.algoParam.addPubKeys = false;

    switch (params.type)
    {
      case OPM_BGP:
        if (!isUpdateStackEmpty(&params, true))
        {
          // Traffic will be generated here = keys are needed.
          // pre-load all PRIVATE keys.
          asList = preloadKeys(params.skiFName, params.keyLocation, 
                               params.preloadECKEY, 
                               params.bgpConf.algoParam.algoID, k_private);
          #ifdef DEBUG
            printList(asList);
          #endif
        }
        if (checkBGPConfig(&params))
        {
          retVal = _runBGPRouterSession(&params);
        }
        else
        {
          printf("ERROR: Cannot run BGP router session!\n");
          printSyntax();
        }
        break;
      case OPM_CAPI:
        // Now initialize the SRxCryptoAPI
        capi = malloc(sizeof(SRxCryptoAPI));
        memset(capi, 0, sizeof(SRxCryptoAPI));
        
        if (params.capiCfgFileName[0] != '\0')
        {
          capi->configFile = params.capiCfgFileName;
        }
  
        sca_status_t status = API_STATUS_OK;
        int initVal = srxCryptoInit(capi, &status);
        if (initVal == API_FAILURE)
        {
          free(capi);
          capi = NULL;
          au_printERR("Could not initialize SRxCryptoAPI - status 0x%X\n", status);
          sca_printStatus(status);
          retVal = EXIT_FAILURE;
        }
        else
        {
          params.bgpConf.algoParam.addPubKeys = true;
          if (!isUpdateStackEmpty(&params, true))
          {
            // Traffic will be generated here = keys are needed.
            // pre-load all PUBLIC and PRIVATE keys.      
            asList = preloadKeys(params.skiFName, params.keyLocation, 
                                 params.preloadECKEY, 
                                 params.bgpConf.algoParam.algoID, k_both);
          }
          retVal = _runCAPI(&params, capi);

          sca_status_t status;
          srxCryptoUnbind(capi, &status);
          free(capi);
        }
        break;
      case OPM_GEN_C:
        params.bgpConf.algoParam.addPubKeys = true;
        // pre-load all keys.
        asList = preloadKeys(params.skiFName, params.keyLocation, 
                             params.preloadECKEY, 
                             params.bgpConf.algoParam.algoID, k_both);
      case OPM_GEN_B:
        if (asList == NULL)
        {
          // pre-load all PRIVATE keys.
          asList = preloadKeys(params.skiFName, params.keyLocation, 
                               params.preloadECKEY, 
                               params.bgpConf.algoParam.algoID, k_private);
        }
        #ifdef DEBUG
          printList(asList);
        #endif
        retVal = _runGEN(&params, params.type == OPM_GEN_B 
                                  ? BGPSEC_IO_TYPE_BGP_UPDATE
                                  : BGPSEC_IO_TYPE_BGPSEC_ATTR);
        break;
      default:
        printf("ERROR: Undefined operation!\n");
        break;
    }
  }
  
  // Release the global memory
  releaseData();
  
  cleanupParams(&params, false);
  
  freeASList(asList);
  CRYPTO_cleanup_all_ex_data();
  if (printDone)
  {
    printf("Done.\n");
  }
  return (retVal != 0) ? 1 : 0;    
}
