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
 * @version 0.2.1.12
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.1.12- 2024/06/11 - oborchert
 *            * Fixed speller in message when using parameter -C <file>
 *  0.2.1.11- 2021/10/26 - oborchert
 *            * Modified the STARTUP_MSG string.
 *            * Added switch to reduce the above warning message.
 *            2021/10/22 - oborchert
 *            * Added STARTUP_MSG to the main message!
 *  0.2.1.10- 2021/09/27 - oborchert
 *            * Ignore B4 scripted updates for CAPI processing.
 *            * Ignore updates where signing failed during CAPI processing with
 *              DROP and BGP4 fallback selected.
 *            * Added BGP-4 scripted, and sign error BGP-4/DROP to statistics
 *            * Fixed formating in Statistics CAPI output.
 *  0.2.1.9 - 2021/09/24 - oborchert
 *            * Added information to output when configuration file is generated
 *              using parameter -C.
 *  0.2.1.5 - 2021/05/20 - oborchert
 *            * Fixed bug in preparation for storing the BGPsec Path Attribute 
 *              data. The issue was that not the BGPsec Path data was handed to 
 *              the store function but the address of the pointer to the data.
 *            * For debug purpose the function __capiRegisterPublicKeys now 
 *              returns the number of keys registered.
 *            * Removed incorrect error message when registration of faulty key
 *              fails in __capiProcessBGPSecAttr.
 *  0.2.1.4 - 2021/03/29 - oborchert
 *            * Changed naming from all uppercase to BGPsec-IO
 *  0.2.1.3 - 2021/03/26 - oborchert
 *            * Renamed attribute inludeStdIn into includeStdIn
 *  0.2.1.0 - 2018/11/29 - oborchert
 *            * Removed merge comments in version control.
 *          - 2018/03/09 - AntaraTek
 *            * Fixed BUG with CAPI, sessionIdx must be set to SESSION_ZERO
 *              until some configuration is added otherwise no public keys are
 *              registered in CAPI.
 *          - 2018/01/16 - oborchert
 *            * Added DEF_PACKING and TODO for location on where to use it.
 *          - 2018/01/10 - oborchert
 *           * Continued working on multi session handling.
 *           * Updated code to reflect changes in structure of BGP_SessionConf 
 *         - 2018/01/10 - oborchert
 *           * Fixed TO DO tag.
 *         - 2018/01/09 - oborchert
 *           * Allow first session to be used in a multi session configuration.
 *         - 2017/12/26 - oborchert
 *           * Added some cleanup regarding multi session configuration
 *         - 2017/12/20 - oborchert
 *           * Added processing of multi sessions.
 *         - 2017/12/11 - oborchert
 *           * Added capability to scan interfaces for their IP addresses.
 *         - 2017/12/05 - oborchert
 *           * Removed un-used method myCompare
 *           * Added capability to use an update as BGP4 only
 *         - 2017/10/12 - oborchert
 *           * Added define BIO_KEYSOURCE
 *         - 2017/09/05 - oborchert
 *           * BZ1212, update code to be compatible with SCA 0.3.0
 * 0.2.0.22- 2018/06/18 - oborchert
 *           * Fixed memory leak in _runBGPRouterSession. long as path was not 
 *             freed.
 * 0.2.0.16- 2018/04/22 - oborchert
 *           * Disabled buffering of stdout and stderr printout in main method.
 * 0.2.0.11- 2018/03/22 - oborchert
 *           * Fixed issues with 4 byte ASN.
 * 0.2.0.10- 2017/09/01 - oborchert
 *           * Removed not used variables.
 * 0.2.0.7 - 2017/05/03 - oborchert
 *           * Next hop for IPv4 prefixes was not generated due to incorrect
 *              reading of the afi value. 
 *         - 2017/04/28 - oborchert
 *           * Fixed BUG where sending IPv6 BGPsec updates was incorrectly 
 *             decided depending on IPv4 negotiation rather than IPv6.
 *         - 2017/04/27 - oborchert
 *           * BZ1153 Fixed storing of bgpsec path attribute in GEN-C mode.
 *         - 2017/03/22 - oborchert
 *           * Modified the display of the used K to not use a string but to 
 *             use the real byte stream.
 *         - 2017/03/20 - oborchert
 *           * BZ1043: Added DEBUG section for flow control.
 *         - 2017/03/17 - oborchert
 *           * Added code to generate BGP4 updates if bgpsec is not negotiated
 *             for the particular update type (IPv4/IPv6).
 *             This only applies to updates that are generated "on the fly". 
 *             Pre-stored updates still are send regardless of the negotiation.
 * 0.2.0.5 - 2017/02/01 - oborchert
 *           * Moved session configuration (capabilities) to the session 
 *             creation.
 *         - 2017/01/30 - oborchert
 *           * Added extended message processing and configuration of 
 *             capabilities.
 *         - 2016/11/15 - oborchert
 *           * Extended previous modification to allow generation of BGPSec Path
 *             Attributes with one byte of length.
 *         - 2016/11/01 - oborchert
 *           * Replaced BGPSEC_PathAttribute with BGPSEC_Ext_PathAttribute.
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
#include <arpa/inet.h>
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
#include "antd-util/log.h"

/** The first configured session. */
#define SESSION_ZERO 0

/** The only BGPsec path attribute - To Be deleted in future versions!!!. */
#define ONLY_BGPSEC_PATH  0
/** Only a single BGPsec path attribute. */
#define BGPSEC_PATH_COUNT 1

/** Only be used as parameter for preloadKeys */
#define LOAD_KEYS_PRIVATE true
/** Only be used as parameter for preloadKeys */
#define LOAD_KEYS_PUBLIC  false
/** For time measurement */
#define TIME_BILLION 1000000000L

/** Used as key source for BGPsec-IO bin: 1111 1100 dec: 252 */
#define BIO_KEYSOURCE 0xFC

/** Used to display upon starting the tool */
#define STARTUP_MSG "******************************************************\n" \
                    " WARNING:  This software is for test purposes only.\n" \
                    " It can generate live protocol exchanges with routers\n" \
                    " using synthetic data for BGP and RPKI.  It is not \n" \
                    " intended to be used in a production environment.\n" \
                    "******************************************************\n\n"
#define STARTUP_MSG_SUPPRESSED \
                    "INFO: Important WARNING message suppressed - Restart " \
                    "without parameter '--suppress-warning'!\n"

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
 * This function frees malloc-ed space or wipes it if it is protected and 
 * initialized the array itself.
 * 
 * @param bgpPathAttr  The array containing attrCount bgpPathAttr elements.
 * @param attrCount    The number elements in the array
 * @param mem_1        Start address of protected memory not to be freed
 * @param mem_2        end address of protected memory not to be freed
 * 
 * @since 0.2.0.11
 */
static void __sanitizePathAttribtueArray(BGP_PathAttribute** bgpPathAttr, 
                                         int attrCount, 
                                         u_int8_t* mem_1, u_int8_t* mem_2)
{
  int       idx      = 0;
  u_int8_t* attrPtr  = NULL;
  int       attrSize = 0;
  
  for (; idx < attrCount; idx++)
  {
    attrPtr = (u_int8_t*)bgpPathAttr[idx];
    if (attrPtr != NULL)
    {
      if ((mem_1 <= attrPtr) && (mem_2 >= attrPtr))
      {
        // attribute located in protected memory, just wipe it to zero
        attrSize = getPathAttributeSize(bgpPathAttr[idx]);
        memset(attrPtr, 0, attrSize);
      }
      else
      {
        freeData(attrPtr);
      }
      bgpPathAttr[idx] = NULL;
    }
  }
}

/**
 * Start the BGP router session
 * 
 * @param params The program parameters
 * @param sessionNr The configuration number of hte session to be started.
 * 
 * @return the exit value.
 */
static int _runBGPRouterSession(PrgParams* params, int sessionNr)
{
    // perform BGP
  BGP_SessionConf* bgpConf = params->sessionConf[sessionNr];
  BGPSession* session = createBGPSession(1024, bgpConf, NULL);
  session->run = true;
  
  bool useGlobalMemory = true;
  int binBuffSize      = SESS_MIN_MESSAGE_BUFFER;
  u_int8_t binBuff[binBuffSize];
// TODO: Check if &binBuff or just binBuff (also check why init 1 and not 0
  memset(binBuff, 1, binBuffSize);
  
  BGPSEC_IO_Buffer ioBuff;
  memset(&ioBuff, 0, sizeof(ioBuff));
  ioBuff.data     = binBuff;
  ioBuff.dataSize = binBuffSize;
          
  u_int8_t msgBuff[SESS_MIN_MESSAGE_BUFFER]; //10KB Message Size
  memset(&msgBuff, 0, sizeof(msgBuff));
  
// start BGP session
  pthread_t bgp_thread;
  
  if (pthread_create(&bgp_thread, NULL, runBGP, session))
  {
    printf ("Error creating BGP thread!\n");
    return EXIT_FAILURE;
  }
  
  // This attribute is needed if AS4_PATH attribute us needed.
  int                 maxAttrCount = 2;
  int                 pathAttrPos  = 0;
  BGP_PathAttribute** bgpPathAttr  = malloc(  maxAttrCount 
                                            * sizeof(BGP_PathAttribute*));
  memset (bgpPathAttr, 0, (maxAttrCount * sizeof(BGP_PathAttribute*)));
  // Used to count the number of used BGP Path attributes;
  
  BGP_UpdateMessage_1* bgp_update  = NULL;
  int               stopTime       = session->bgpConf->disconnectTime;
  bool              hasBinTraffic  = params->binInFile[0] != '\0';
  bool              includeStdIn    = sessionNr == 0;
  // @TODO: The stack empty call might need the session number to 
  //        figure which update stack is asked for. Also hasBinTraffic should
  //        only be considered for session 0
  bool              sendData    = (!isUpdateStackEmpty(params, sessionNr, 
                                                       includeStdIn) 
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
  
  int updatesSend = 0;
  
  // Helper to allow generation of more than one path attribute.
  // for now AS4_PATH and AS_PATH for unsupported AS4 speakers.
  u_int8_t* buffPtr = NULL;
        
  while (session->run)
  {
    // Sleep in 1 second intervals until BGP session is established.
    if (session->fsm.state != FSM_STATE_ESTABLISHED)
    {
      sleep(1);
      continue;
    }    
                
    bool bgpsec_v4_negotiated =   session->bgpConf->capConf.bgpsec_snd_v4 
                                & session->bgpConf->peerCap.bgpsec_rcv_v4;
    bool bgpsec_v6_negotiated =   session->bgpConf->capConf.bgpsec_snd_v6 
                                & session->bgpConf->peerCap.bgpsec_rcv_v6;
    bool doBGPSEC = true;

    // useAS4 is used for BGP4 updates and the usage depends on the negotiation 
    // with the peer and out own capability.
    bool useAS4      =    session->bgpConf->peerCap.asn_4byte 
                       && session->bgpConf->capConf.asn_4byte;
    int  as4AttrSize = 0;

    // Now session is established, first send all updates in the stack then
    // all stdin data followed by binary in data
    while (session->fsm.state == FSM_STATE_ESTABLISHED && sendData)
    {
      prefix      = NULL;
      buffPtr     = binBuff + binBuffSize;
      __sanitizePathAttribtueArray(bgpPathAttr, maxAttrCount, 
                                   binBuff, buffPtr);
      buffPtr     = binBuff;
      pathAttrPos = 0; // Max 2
      as4AttrSize = 0;
      bgp_update  = NULL;

      // set for the next run.      
      sendData = --params->maxUpdates != 0;
      bool useMPNLRI = session->bgpConf->useMPNLRI;
      bool iBGP = session->bgpConf->asn == session->bgpConf->peerAS;
      
      // First check the stack and stdin
      if (!isUpdateStackEmpty(params, sessionNr, includeStdIn))
      {
        record.recordType = BGPSEC_IO_TYPE_BGPSEC_ATTR;
        update    = (UpdateData*)popStack(&session->bgpConf->updateStack);

        if (update != NULL)
        {
          // the following pointer points into globally managed memory and
          // therefore does not need to be freed
          prefix = (BGPSEC_PrefixHdr*)&update->prefixTpl;
          
          // Let us figure out if we can generate bgpsec at all (configuration)
          // 1: figure out if we are V4 or V6
          // 2: is bgpsec negotiated?
          switch (ntohs(prefix->afi))
          {
            case AFI_V4:
              doBGPSEC = bgpsec_v4_negotiated && !update->bgp4_only;
              break;
            case AFI_V6:
              doBGPSEC = bgpsec_v6_negotiated && !update->bgp4_only;
              break;
            default:
              doBGPSEC = false;
              break;
          }
          
          bgpPathAttr[pathAttrPos] = doBGPSEC 
                                     ? (BGP_PathAttribute*)generateBGPSecAttr(
                                        NULL, useGlobalMemory, update->pathStr, 
                                        NULL, session->bgpConf, prefix, 
                                        asList, params->onlyExtLength)
                                     : NULL;
          // if bgpsec attribute could not be generated use AS_PATH and no 
          // MPNLRI encoding for V4 prefixes
          useMPNLRI = useMPNLRI & (bgpPathAttr[pathAttrPos] != NULL);
          
          if (bgpPathAttr[pathAttrPos] == NULL)
          {
            // Now this can have two reasons:
            // (1) The signing failed -> check for mode NS_BGP4 as fallback
            // (2) This is an origination and it is an iBGP session -> BGP-4
            //     In the case it is an iBGP session and no origin announcement
            //     then the bgpsec attribute was generated up to this router
            //     and we do not end up here.
            // (3) BGPsec is not negotiated.
            bool iBGP_Announcement = false;
            if ((strlen(update->pathStr) == 0) && iBGP)
            {
              // Now we do need to generate the BGP4 update regardless what is
              // scripted in the ns_mode (fallback for missing signatures)
              iBGP_Announcement = true;
            }
            if (   iBGP_Announcement
                || (session->bgpConf->algoParam.ns_mode == NS_BGP4)
                || !doBGPSEC)
            {            
              // Use the buffer normally used for the binary stream, it will
              // be fine.
              // Generate an BPP4 packet.
              // added iBGP detection.
              if (!useAS4)
              {
                // Peer does not support AS4 path. Check is as path contains 
                // ASN's that exceed 2 bytes.
                bool  has4ByteASN = false;
                char* longPath = convertAsnPath(update->pathStr, 
                                                update->asSetStr, &has4ByteASN);
                if (has4ByteASN) //AS path contains 4byte ASN
                {
                  bgpPathAttr[pathAttrPos] 
                                 = generateBGP_PathAttr(BGP_UPD_A_TYPE_AS4_PATH,
                                              session->bgpConf->asn, true, iBGP, 
                                              longPath, update->asSetStr,
                                              buffPtr, SESS_MIN_MESSAGE_BUFFER);
                  if (bgpPathAttr[pathAttrPos] != NULL)
                  {
                    as4AttrSize =getPathAttributeSize(bgpPathAttr[pathAttrPos]);
                    buffPtr += as4AttrSize;
                    pathAttrPos++;
                  }
                  else
                  {
                    RAISE_ERROR("Could not generate an AS4_PATH attribute for"
                                " path '%s'", update->pathStr);
                  }
                }
                // Fix Memory Leak
                if (longPath != NULL)
                {
                  free(longPath);
                  longPath = NULL;
                }
              }
              if (pathAttrPos < maxAttrCount)
              {
                char* longPath = convertAsnPath(update->pathStr, NULL, NULL);
                bgpPathAttr[pathAttrPos] 
                                  = generateBGP_PathAttr(BGP_UPD_A_TYPE_AS_PATH,
                                            session->bgpConf->asn, useAS4, iBGP, 
                                            longPath, update->asSetStr,
                                            buffPtr, SESS_MIN_MESSAGE_BUFFER);
                // Fix Memory Leak.
                if (longPath != NULL)
                {
                  free(longPath);
                  longPath = NULL;
                }
                if (bgpPathAttr[pathAttrPos] == NULL)
                {
                  RAISE_ERROR("Could not generate an AS_PATH attribute for"
                              " path '%s'", update->pathStr);                
                }
              }
              else
              {
                // Something went horrobly wrong.
                RAISE_ERROR("The number of BGP path attributes exceeds the "
                            "maximum of %i BGP path attributes.", maxAttrCount);                                
              }
            }
          }
        }        
      }
      else if (hasBinTraffic)
      {
        includeStdIn = false;
        hasBinTraffic = loadData(dataFile, htonl(session->bgpConf->asn), 
                                 htonl(session->bgpConf->peerAS), 
                                 BGPSEC_IO_TYPE_ALL, &record, &ioBuff);
        if (hasBinTraffic)
        {
          switch (record.recordType)
          {
            case BGPSEC_IO_TYPE_BGPSEC_ATTR:
                // Prepare the attribute memory
              bgpPathAttr[0] = (BGP_PathAttribute*)ioBuff.data;
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
        
      if (bgpPathAttr[pathAttrPos] != NULL)
      {
        // Set no mpnlri if iBGP session. Will be overwritten for V6
        u_int32_t locPref = iBGP ? BGP_UPD_A_FLAGS_LOC_PREV_DEFAULT : 0;
        if (ntohs(prefix->afi) == AFI_V4)
        {
          createUpdateMessage(msgBuff, sizeof(msgBuff), 
                              (pathAttrPos+1), bgpPathAttr, 
                              BGP_UPD_A_FLAGS_ORIGIN_INC, locPref,
                              &session->bgpConf->nextHopV4, prefix, useMPNLRI,
                              update->validation);
          if (session->bgpConf->prefixPacking)
          {
            // @TODO: Peek into update stack and see if next update is IPv4 and
            //        has same AS_PATH.
          }
        }
        else
        {
          createUpdateMessage(msgBuff, sizeof(msgBuff), 
                              (pathAttrPos+1), bgpPathAttr, 
                              BGP_UPD_A_FLAGS_ORIGIN_INC, locPref,
                              &session->bgpConf->nextHopV6, prefix, useMPNLRI,
                              update->validation);
        }
        // Maybe store the update ?????          
        bgp_update = (BGP_UpdateMessage_1*)msgBuff;
      }
      
      if (bgp_update != NULL)
      {
        sendUpdate(session, bgp_update, SESS_FLOW_CONTROL_REPEAT);
        updatesSend++;
#ifdef DEBUG
        if (updatesSend % 1000 == 0)
        {
          printf("Updates send: %'d\n", updatesSend);
        }
#endif
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
    if (session->bgpConf->disconnectTime != 0)
    {
      if (stopTime-- == 0)
      {
        // initiate a stop by switching the FSM
        printf ("Initiating session shutdown to AS %u\n", 
                session->bgpConf->peerAS);
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
  buffPtr = binBuff + binBuffSize;
  __sanitizePathAttribtueArray(bgpPathAttr, maxAttrCount, binBuff, buffPtr);
  memset (bgpPathAttr, 0, (maxAttrCount  * sizeof(BGP_PathAttribute*)));
  free(bgpPathAttr);
  
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
 * Process the BGPSec Path attribute and call the SRxCryptoAPI for validation.
 * CAPI Processing is only done on the first session configuration.
 * 
 * @param capi The SrxCryptoApi to test.
 * @param params The program parameters containing all session information.
 * @param prefix The prefix of the update (network format)
 * @param pathAttr The path attribute itself. (network format)
 * @param elapsedTime OUT - The time it took to process the validation.
 * @param status Returns the status flag from the validation process.
 * 
 * @return the validation result as specified in SrxCryptoAPI
 */
static int __capiProcessBGPSecAttr(SRxCryptoAPI* capi, PrgParams* params, 
                                   BGPSEC_PrefixHdr* prefix, 
                                   BGP_PathAttribute* pathAttr,
                                   u_int64_t* elapsedTime, sca_status_t* status)
{
  SCA_BGPSecValidationData valdata;
  memset (&valdata, 0, sizeof(SCA_BGPSecValidationData));
  BGP_SessionConf* bgpConf = params->sessionConf[0];
  
  // Here the myAS is the peer, not me because we call the validate out of the
  // peer's perspective
  valdata.myAS   = htonl(bgpConf->peerAS);  
  valdata.bgpsec_path_attr = (u_int8_t*)pathAttr;
  valdata.nlri   = (SCA_Prefix*)prefix;
  valdata.status = API_STATUS_OK;

//  printBGPSEC_PathAttr(pathAttr, NULL, false);
  int valResult = API_VALRESULT_INVALID;
  
  // Check if keys need to be registered
  if (bgpConf->algoParam.pubKeysStored > 0)
  {
    int idx = 0;
    int skiIdx=0;
    sca_status_t keyStatus = API_STATUS_OK;
    int regResult = API_SUCCESS;
    int expResult = API_SUCCESS;
    for (; idx < bgpConf->algoParam.pubKeysStored; idx++)
    {
      expResult = (bgpConf->algoParam.pubKey[idx]->keyData 
                   != bgpConf->algoParam.fake_key.keyData) ? API_SUCCESS 
                                                            : API_FAILURE;
      regResult = capi->registerPublicKey(bgpConf->algoParam.pubKey[idx], 
                                          BIO_KEYSOURCE, &keyStatus);
      if (regResult != expResult)
      {
        if (expResult == API_SUCCESS)
        {
          // It was expected that the registration is successful.
          if ((keyStatus & API_STATUS_ERROR_MASK) > 0)
          {
            printf("ERROR: Registering public key:\n");
            sca_printStatus(keyStatus);
          }
        }
        else
        {
          // It was expected that the registration failed but it did not!!!
          printf("ERROR: Registering public key was successful where it should"
                 " have failed!!!:\n");
          printf("SKI [");
          for (skiIdx = 0; skiIdx < SKI_LENGTH; skiIdx++)
          {
            printf(" %02X", bgpConf->algoParam.pubKey[idx]->ski[skiIdx]);
          }
          printf("\n");
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
    if (bgpConf->printOnInvalid)
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
 * Clean the public keys stored in the session configuration
 * 
 * @param params the sessions configuration
 */
static void __cleanPubKeys(BGP_SessionConf* bgpConf)
{
  // Use global data
  if (bgpConf->algoParam.pubKeysStored != 0)
  {
    // clean the key array
    memset(bgpConf->algoParam.pubKey, 0, 
           bgpConf->algoParam.pubKeysStored * sizeof(BGPSecKey*));
    bgpConf->algoParam.pubKeysStored = 0;
  }  
}

/**
 * Register the keys found in the binary file with the SRxCryptoAPI.
 * 
 * @param capi The API module
 * @param ioBuff The keys.
 * 
 * @return the number of keys registered.
 */
static int __capiRegisterPublicKeys(SRxCryptoAPI* capi, 
                                    BGPSEC_IO_Buffer* ioBuff)
{
  u_int16_t* wordVal = (u_int16_t*)ioBuff->keys;
  u_int16_t  length = *wordVal;
  u_int8_t*  ptr = ioBuff->keys + sizeof(u_int16_t);
  
  BGPSEC_IO_KRecord* kRecord = NULL;
  BGPSecKey          bgpsec_key;
  sca_status_t       myStatus;
  
  int keysRegistered = 0;
  
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
    
    if (capi->registerPublicKey(&bgpsec_key, BIO_KEYSOURCE, &myStatus) 
        == API_FAILURE)
    {
      printf ("ERROR: Registering public Keys!\n");        
      sca_printStatus(myStatus);
      break;
    }
    keysRegistered++;
  }
  
  return keysRegistered;
}

/**
 * Run the SRxCryptoAPI test calls - Only using the first configured session.
 * 
 * @param params The program parameters
 * @param capi The SRx Crypto API
 * 
 * @return the exit value.
 */
static int _runCAPI(PrgParams* params, SRxCryptoAPI* capi)
{
  UpdateData*               update   = NULL;
  BGP_PathAttribute*        pathAttr = NULL;
  BGPSEC_PrefixHdr*         prefix   = NULL;
  BGP_SessionConf*          bgpConf  = params->sessionConf[0];
  
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
  // Counter for found BGP-4 updates.
  int bgp4updates   = 0;
  // In case signature could not be make.
  int nullSigDropedUpdates = 0;
  int nullSigBGP4Updates   = 0;
  __cleanPubKeys(bgpConf);
  
  BIO_Statistics statistics[2];
  memset (statistics, 0, sizeof(BIO_Statistics)*2);
  
  sca_status_t valStatus = API_STATUS_OK;
  u_int32_t    segments  = 0;
  u_int64_t    elapsed   = 0;
  Stack*       updateStack = &params->sessionConf[SESSION_ZERO]->updateStack;
          
  while (!isUpdateStackEmpty(params, SESSION_ZERO, true) 
         && (params->maxUpdates != 0))
  {
    params->maxUpdates--;
    update   = (UpdateData*)popStack(updateStack);
    if (update->bgp4_only)
    {
      // Do not further process this UPDATE, BGP-4 UPDATES are note processed
      // by BGPsec
      bgp4updates++;
      continue;
    }
    prefix   = (BGPSEC_PrefixHdr*)&update->prefixTpl;  
    
    segments = 0;
    pathAttr = (BGP_PathAttribute*)generateBGPSecAttr(capi, true, 
                                                      update->pathStr, 
                                                      &segments,
                                                      bgpConf, 
                                                      prefix, asList,
                                                      params->onlyExtLength);
    if (pathAttr == NULL)
    {
      // Collect for statistics 
      switch (bgpConf->algoParam.ns_mode)
      {
        case NS_DROP:
          nullSigDropedUpdates++;
          break;
        case NS_BGP4:
          nullSigBGP4Updates++;
          break;
        default:
          printf("ERROR: Enexpected Null Signature ns_mode value for '%s'!\n", 
                 update->pathStr);
          break;          
      }
      continue;
    }
    elapsed   = 0;
    valStatus = API_STATUS_OK;
    valResult = __capiProcessBGPSecAttr(capi, params, prefix, pathAttr,&elapsed,
                                        &valStatus);
    
    statistics[valResult].totalTime      += elapsed;
    statistics[valResult].totalSegments  += segments;
    
    // @TODO: Check if cleanup is still needed.
    __cleanPubKeys(bgpConf);
    
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
    BGP_PathAttribute* pathAttr = NULL;
    // re-initialize the data buffer
    memset (ioBuff.data, 0, ioBuff.dataSize);
    
    if (dataFile)
    { 
      // re-initialize the data buffer.
      memset (ioBuff.data, 0, MAX_DATABUF);
      memset (ioBuff.keys, 0, MAX_DATABUF);
      
      // Make sure no previously stored keys are still in the cache      
      __cleanPubKeys(bgpConf);
      u_int32_t asn    = htonl(bgpConf->asn);
      u_int32_t peerAS = htonl(bgpConf->peerAS);
      while (loadData(dataFile, asn, peerAS, BGPSEC_IO_TYPE_BGPSEC_ATTR, 
                      &record, &ioBuff) 
             && (params->maxUpdates != 0))
      {
        params->maxUpdates--;
        pathAttr  = (BGP_PathAttribute*)ioBuff.data;
        prefix    = (BGPSEC_PrefixHdr*)&record.prefix;
        int registered = __capiRegisterPublicKeys(capi, &ioBuff);
        
        elapsed       = 0;
        valStatus     = API_STATUS_OK;
        valResult     = __capiProcessBGPSecAttr(capi, params, prefix, pathAttr,
                                                &elapsed, &valStatus);
        
        statistics[valResult].totalSegments += ntohl(record.noSegments);
        statistics[valResult].totalTime     += elapsed;
        
        // @TODO: Check if cleanup is still needed.
         __cleanPubKeys(bgpConf);               
         
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
        memset (ioBuff.data, 0, sizeof(BGPSEC_Ext_PathAttribute));
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
  printf ("\nSkiped CAPI Validation Statistics:\n=============================="
          "======\n");
  printf ("  %d scripted BGP-4 update%sfound\n", bgp4updates, 
          bgp4updates != 1 ? "s " : " "); 
  if ((nullSigBGP4Updates+nullSigDropedUpdates) != 0)
  {
    switch (bgpConf->algoParam.ns_mode)
    {
      case NS_BGP4:
        printf ("  %d signing error: fallback -> create BGP-4 update%s\n", 
                nullSigBGP4Updates, nullSigBGP4Updates != 1 ? "s " : " "); 
        break;
      case NS_DROP:
        printf ("  %d signing error: fallback -> drop update%s\n", 
                nullSigDropedUpdates, nullSigDropedUpdates != 1 ? "s " : " "); 
        break;
    }
  }
  printf ("\n");

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
        printf ("  - Invalid updates due to errors: %d\n", error);
      }
      if (keyNotFound > 0)
      {
        printf ("  - Invalid updates due to missing key: %d\n", keyNotFound);
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
  ioBuff.data = NULL;
  ioBuff.dataSize = 0;
  free (ioBuff.keys);
  ioBuff.keys = NULL;
  ioBuff.keySize = 0;

  return EXIT_SUCCESS;
}

/**
 * Generate the data and store it into a file - This is done only for the 
 * first session configuration.
 * 
 * @param params The program parameters.
 * @param type the type of traffic to be generated, BGP Updates 
 *             (BGPSEC_IO_TYPE_BGP_UPDATE) or just the attribute
 *             (BGPSEC_IO_TYPE_BGPSEC_ATTR).
 * 
 * @return The exit code.
 */
static int _runGEN(PrgParams* params, u_int8_t type)
{
  int retVal = EXIT_SUCCESS;
  u_int8_t msgBuff[SESS_MIN_MESSAGE_BUFFER]; //10KB Message Size
  memset(&msgBuff, 0, SESS_MIN_MESSAGE_BUFFER);
  BGP_SessionConf* bgpConf = params->sessionConf[0];

  if (params->binOutFile[0] != '\0')
  {
    FILE* outFile = params->appendOut ? fopen(params->binOutFile, "a")
                                      : fopen(params->binOutFile, "w");
    if (outFile)
    {
      // move to function that also reads from stdin
      UpdateData* update = NULL;
      BGP_PathAttribute* bgpsecPathAttr[] = {NULL};
      BGPSEC_PrefixHdr* prefix = NULL;
      BGPSEC_IO_StoreData store;
      int msgLen         = 0;
      
      while (   !isUpdateStackEmpty(params, SESSION_ZERO, true) 
             && (params->maxUpdates != 0))
      {
        params->maxUpdates--;
        update = (UpdateData*)popStack(&params->sessionConf[SESSION_ZERO]->updateStack);
        prefix = (BGPSEC_PrefixHdr*)&update->prefixTpl;
        
        // Use global data
        if (bgpConf->algoParam.pubKeysStored != 0)
        {
          // clean the key array
          memset(bgpConf->algoParam.pubKey, 0, 
                 bgpConf->algoParam.pubKeysStored * sizeof(BGPSecKey*));
          bgpConf->algoParam.pubKeysStored = 0;
        }
                
        u_int32_t segmentCount = 0;
        bool iBGP = bgpConf->asn == bgpConf->peerAS;
        u_int32_t locPref = iBGP ? BGP_UPD_A_FLAGS_LOC_PREV_DEFAULT : 0;
        bgpsecPathAttr[ONLY_BGPSEC_PATH] = 
                          (BGP_PathAttribute*)generateBGPSecAttr(NULL, true, 
                                update->pathStr, &segmentCount, bgpConf, prefix, 
                                asList, params->onlyExtLength);        
        if (bgpsecPathAttr[ONLY_BGPSEC_PATH] != NULL)
        {
          // Include the attribute header information.
          store.prefix       = prefix;
          store.usesFake     = bgpConf->algoParam.fakeUsed;
          store.numKeys      = bgpConf->algoParam.pubKeysStored;
          store.keys         =  store.numKeys != 0 
                                ? bgpConf->algoParam.pubKey : NULL;
          store.segmentCount = segmentCount;
          void* nextHop = NULL;
          switch (type)
          {            
            case BGPSEC_IO_TYPE_BGPSEC_ATTR:
              store.dataLength   = getPathAttributeSize(
                                              bgpsecPathAttr[ONLY_BGPSEC_PATH]);
              store.data         = (u_int8_t*)bgpsecPathAttr[ONLY_BGPSEC_PATH];
              if (!storeData(outFile, BGPSEC_IO_TYPE_BGPSEC_ATTR, 
                             bgpConf->asn, bgpConf->peerAS, &store))
              {
                printf("ERROR: Error writing path %s\n", update->pathStr);
              }
              break;
              
            case BGPSEC_IO_TYPE_BGP_UPDATE:
              nextHop = (ntohs(prefix->afi) == AFI_V4)
                        ? (void*)&bgpConf->nextHopV4
                        : (void*)&bgpConf->nextHopV6;
              msgLen = createUpdateMessage(msgBuff, sizeof(msgBuff),
                         BGPSEC_PATH_COUNT, (BGP_PathAttribute**)bgpsecPathAttr, 
                         BGP_UPD_A_FLAGS_ORIGIN_INC, locPref, nextHop, prefix, 
                         bgpConf->useMPNLRI, update->validation);
              store.dataLength = msgLen;
              store.data       = (u_int8_t*)msgBuff;
              if (!storeData(outFile, BGPSEC_IO_TYPE_BGP_UPDATE, 
                             bgpConf->asn, bgpConf->peerAS, 
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
    // Only the first session configuration is used.    
    BGP_SessionConf* bgpConf = params->sessionConf[0];
    
    u_int32_t asn     = bgpConf->asn > 0 
                          ? bgpConf->asn 
                          : DEF_LOCAL_ASN;
    char*     peerIP  = bgpConf->peer_addr.sin_addr.s_addr > 0 
                          ? inet_ntoa(bgpConf->peer_addr.sin_addr)
                          : DEF_PEER_IP;
    u_int32_t peerASN = bgpConf->peerAS > 0
                          ? bgpConf->peerAS
                          : DEF_PEER_ASN;    
    
    if (!generateFile((char*)params->newCfgFileName, params->iface, asn, 
                      peerIP, peerASN))
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
      printf("Verify the key file settings and correct them if necessary!\n");
      *exitVal  = EXIT_SUCCESS;
    }
    keepGoing = false;
  } 
  else
  {
    switch (params->type)
    {
      case OPM_BGP:
        break;
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
      default:
        if (params->sessionCount != 1)
        {
          _errorParam("Multiple sessions can only be used in BGP mode!!");
          keepGoing = false;                    
        }
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
  // First load parameters  
  PrgParams params;
  initParams(&params);
  
  // Disable printout buffering.
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
  
  SRxCryptoAPI* capi = NULL;
  
  int  retVal = parseParams(&params, argc, argv);
  bool keepGoing = true;
  bool printDone = true;
  bool inclSTDIO = true;
  int  sessIdx  = 0;
  
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
    postProcessUpdateStack(&params);
    
    printf ("Starting %s...\n\n", PACKAGE_STRING);
    // Print message on standard error so it is visible on the screen.
    if (!params.suppressWarning)
    {
      fprintf (stderr, "%s", STARTUP_MSG);
    }
    else
    {
      fprintf (stderr, "%s", STARTUP_MSG_SUPPRESSED);
    }
    
    BGP_SessionConf* bgpConf = NULL;
    for (sessIdx = 0; sessIdx < params.sessionCount; sessIdx++)
    {
      bgpConf = params.sessionConf[sessIdx];
      if ( (bgpConf->algoParam.sigGenMode == SM_BIO_K1)
           || (bgpConf->algoParam.sigGenMode == SM_BIO_K2) )
      {
        char str[STR_MAX];
        memset(str, '\0', STR_MAX);
        CRYPTO_k_to_string(str, STR_MAX, bgpConf->algoParam.sigGenMode);
        printf ("WARNING: Signatures in session %i will be generated using "
                "constant k=%s\n", sessIdx, str);
      }      
      // @TODO: line below can be deleted once srxcrytpoapi is configured 
      // correctly
      bgpConf->algoParam.addPubKeys = false;
    }
    sessIdx = SESSION_ZERO;
    
    // initialize the main memory;
    initData();
    
    // Set session configuration to first session.
    bgpConf = params.sessionConf[0];
    
    switch (params.type)
    {
      case OPM_BGP:
        // @TODO: Maybe create loop for more than one sessions.
        for (sessIdx = 0; sessIdx < params.sessionCount; sessIdx++)
        {
#ifndef SUPPORT_MULTI_SESSION     
          if (sessIdx > 0)
          {
            printf ("WARNING: Multi Session is not enabled yet, skip "
                    "session[%i]!\n", sessIdx);
            continue;
          }
#endif
          inclSTDIO = (sessIdx == 0);
          bgpConf = params.sessionConf[sessIdx];
          if (!isUpdateStackEmpty(&params, sessIdx, inclSTDIO))
          {
            // Traffic will be generated here = keys are needed.
            // pre-load all PRIVATE keys.
            asList = preloadKeys(asList, params.skiFName, params.keyLocation, 
                                 params.preloadECKEY, 
                                 bgpConf->algoParam.algoID, k_private);
            #ifdef DEBUG
              printList(asList);
            #endif
          }
          if (checkBGPConfig(&params))
          {
            retVal = _runBGPRouterSession(&params, sessIdx);
          }
          else
          {
            printf("ERROR: Cannot run BGP router session!\n");
            printSyntax();
          }
        }
        break;
      case OPM_CAPI:
        // Now initialize the SRxCryptoAPI        
        // For CAPI at this point we only use the first specified session
        sessIdx = SESSION_ZERO;
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
          bgpConf->algoParam.addPubKeys = true;
          if (!isUpdateStackEmpty(&params, sessIdx, inclSTDIO))
          {
            // Traffic will be generated here = keys are needed.
            // pre-load all PUBLIC and PRIVATE keys.      
            asList = preloadKeys(asList, params.skiFName, params.keyLocation, 
                                 params.preloadECKEY, 
                                 bgpConf->algoParam.algoID, k_both);
          }
          retVal = _runCAPI(&params, capi);

          sca_status_t status;
          srxCryptoUnbind(capi, &status);
          free(capi);
          capi = NULL;
        }
        break;
      case OPM_GEN_C:
        bgpConf->algoParam.addPubKeys = true;
        // pre-load all keys.
        asList = preloadKeys(asList, params.skiFName, params.keyLocation, 
                             params.preloadECKEY, 
                             bgpConf->algoParam.algoID, k_both);
      case OPM_GEN_B:
        if (asList == NULL)
        {
          // pre-load all PRIVATE keys.
          asList = preloadKeys(asList, params.skiFName, params.keyLocation, 
                               params.preloadECKEY, 
                               bgpConf->algoParam.algoID, k_private);
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
  
  // Release the session configurations
  // @TODO: Seems not to free the configuration at all.
  if (params.sessionCount != 0)
  {
    //freeBGPSessionConf
    for (sessIdx = 0; sessIdx < params.sessionCount; sessIdx++)
    {
      memset(params.sessionConf[sessIdx], 0, sizeof(BGP_SessionConf));
      free(params.sessionConf[sessIdx]);
      params.sessionConf[sessIdx] = NULL;    
    }
    memset(params.sessionConf, 0, 
           params.sessionCount * sizeof(BGP_SessionConf*));
    free(params.sessionConf);
    params.sessionConf  = NULL;
    params.sessionCount = 0;
  }
  
  cleanupParams(&params, false);
  
  freeASList(asList);
    
  CRYPTO_cleanup_all_ex_data();
  if (printDone)
  {
    printf("Done.\n");
  }
  return (retVal != 0) ? 1 : 0;    
}
