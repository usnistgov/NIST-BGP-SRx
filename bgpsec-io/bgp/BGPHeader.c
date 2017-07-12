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
 * This API contains a simple BGP speaker that can open a BGP session and
 * send BGP updates. It keeps the session open as long as the program is running 
 * or for a pre-determined time after the last update is send.
 * 
 * @version 0.2.0.7
 *   
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.0.7 - 2017/04/27 - oborchert
 *            * Fixed BUG in BGP-4 AS_PATH with more than 255 AS numbers in the
 *              path. (BZ1154)
 *          - 2017/02/16 - oborchert
 *            * Fixed bug in next hop IPv6.
 *          - 2017/02/10 - oborchert
 *            * Updated code to reflect modification of bgp identifier stored in
 *              network rather than host format.
 *  0.2.0.5 - 2016/11/15 - oborchert
 *            * Fixed BZ1053 - always use 4 bytes for IPv4 next hop in MPNLRI.
 *          - 2016/10/21 - oborchert
 *            * BZ1026: Due to a change in the capability data structure the 
 *              construction code for capabilities needed to be changed slightly
 *              as well. (The structure on the wire was not modified!)
 *  0.2.0.2 - 2016/06/26 - oborchert
 *            * Fixed bug in wrong ASN during open message when AS is 4 byte
 *              ASN (BZ994).
 *  0.2.0.1 - 2016/06/24 - oborchert
 *            * Modified function generateBGP_PathAttr to allow detection of
 *              iBGP sessions.
 *  0.2.0.0 - 2016/05/12 - oborchert
 *            * Modified nexthop to u_int64_t in header of createUpdate
 *            * Fixed BUG 935: needed some more fixing with the prefix.
 *          - 2016/05/11 - oborchert
 *            * Fixed BZ960: Invalid next hop IP encoding
 *          - 2016/05/10 - oborchert
 *            * Fixed compiler warnings BZ950
 *          - 2016/05/06 - oborchert
 *            * Removed unnecessary printouts. (BZ: 946)
 *  0.1.1.0 - 2016/04/27 - oborchert
 *            * Fixed some possible segmentation faults.
 *          - 2016/04/26 - oborchert
 *            * Added as path conversion (10p2 -> 10 10)
 *          - 2016/04/21 - oborchert
 *            * Added indicator if fake signature was used.
 *            * Added generation of BGP_PathAttribute.
 *          - 2016/04/15 - oborchert
 *            * Fixed function cpyBGPSecAddrMem which had invalid type of afi.
 *          - 2015/08/13 - oborchert
 *            * Created File.
 */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include <math.h>
#include <malloc.h>
#include <sys/types.h>
#include "antd-util/prefix.h"
#include "ASNTokenizer.h"
#include "updateStackUtil.h"
#include "bgp/BGPHeader.h"
#include "bgp/BGPSession.h"
#include "printer/BGPPrinterUtil.h"

////////////////////////////////////////////////////////////////////////////////
//  OPEN MESSAGE
////////////////////////////////////////////////////////////////////////////////

/**
 * Generate an open message and fill the given buffer. The buffer needs to be
 * of sufficient size. The return value will provide the size in bytes the open 
 * message consumes or if less than 0 the number of bytes needed to generate the
 * open message.
 * 
 * @param buff The pre-allocated memory of sufficient size
 * @param config The configuration needed for the open message.
 * 
 * @return the number of bytes used or if less than 0 the number of bytes missed
 */
int createOpenMessage(u_int8_t* buff, int buffSize, BGP_SessionConf* config)
{
  if (config == NULL)
  {
    printf ("ERROR: OpenMessage - Configuration == NULL");
    return 0;
  }
  int pHdrLen = sizeof(BGP_OpenMessage_OptParam);
  int paramLength = 0 
    + (config->capConf.mpnlri_v4     ? sizeof(BGP_Cap_MPNLRI) + pHdrLen   : 0)
    + (config->capConf.mpnlri_v6     ? sizeof(BGP_Cap_MPNLRI) + pHdrLen   : 0)
    + (config->capConf.asn_4byte     ? sizeof(BGP_Cap_AS4) + pHdrLen      : 0)
    + (config->capConf.route_refresh ? sizeof(BGP_Cap_RREFRESH) + pHdrLen : 0)
    + (config->capConf.extMsgSupp    ? sizeof(BGP_Cap_ExtMsgSupport) + pHdrLen 
                                                                     : 0)
    + (config->capConf.bgpsec_rcv_v4 ? sizeof(BGP_Cap_BGPSEC) + pHdrLen   : 0)
    + (config->capConf.bgpsec_rcv_v6 ? sizeof(BGP_Cap_BGPSEC) + pHdrLen   : 0)
    + (config->capConf.bgpsec_snd_v4 ? sizeof(BGP_Cap_BGPSEC) + pHdrLen   : 0)
    + (config->capConf.bgpsec_snd_v6 ? sizeof(BGP_Cap_BGPSEC) + pHdrLen   : 0);
            
  int requiredLength = sizeof(BGP_OpenMessage) 
                       + paramLength;
  if (buffSize < requiredLength)
  {
    return buffSize - requiredLength;
  }
  
  // the memset can be removed later on for speed up.
  memset (buff, 0, buffSize);
  BGP_OpenMessage* openMsg = (BGP_OpenMessage*)buff;
  memset (openMsg->messageHeader.marker, BGP_MARKER_VAL, BGP_MARKER_SIZE);
  openMsg->messageHeader.length = htons(requiredLength);
  openMsg->messageHeader.type   = BGP_T_OPEN;
  
  openMsg->version         = BGP_VERSION;
  // Now check if ASN can be mapped to 4 byte ASN?
  if (config->asn == (config->asn & 0xFFFF))
  {
    openMsg->my_as         = htons((u_int16_t)config->asn);
    // otherwise it will be set to 23456 - the asn will be set in the capabilities attribute
  }
  else
  {
    openMsg->my_as         = htons(23456);
  }
  openMsg->hold_time       = htons(config->holdTime);
  openMsg->bgp_identifier  = config->bgpIdentifier;
  openMsg->opt_param_len   = paramLength;
  buff += sizeof(BGP_OpenMessage);

  BGP_Cap_MPNLRI*           mpnlri   = NULL;
  BGP_Cap_AS4*              as4      = NULL;
  BGP_Cap_BGPSEC*           bgpsec   = NULL;  
  BGP_Cap_RREFRESH*         rrefresh = NULL;
  BGP_Cap_ExtMsgSupport*    extMsg   = NULL;
  BGP_OpenMessage_OptParam* optParam = NULL;
          
  // Announce MPNLRI encoding IPv4
  if (config->capConf.mpnlri_v4)
  {
    optParam = (BGP_OpenMessage_OptParam*)buff;
    optParam->param_type = BGP_T_CAP;
    optParam->param_len  = sizeof(BGP_Cap_MPNLRI);    
    buff += sizeof(BGP_OpenMessage_OptParam);
    
    mpnlri = (BGP_Cap_MPNLRI*)buff;
    mpnlri->capHdr.cap_code     = BGP_CAP_T_MPNLRI;
    mpnlri->capHdr.cap_length   = LEN_CAP_MPNLRI;
    mpnlri->afi                 = htons(AFI_V4);
    mpnlri->reserved            = RESERVED_ZERO;
    mpnlri->safi                = SAFI_UNICAST;
    buff += sizeof(BGP_Cap_MPNLRI);
  }

  // Announce MPNLRI encoding IPv6
  if (config->capConf.mpnlri_v6)
  {
    optParam = (BGP_OpenMessage_OptParam*)buff;
    optParam->param_type = BGP_T_CAP;
    optParam->param_len  = sizeof(BGP_Cap_MPNLRI);    
    buff += sizeof(BGP_OpenMessage_OptParam);
    
    mpnlri = (BGP_Cap_MPNLRI*)buff;
    mpnlri->capHdr.cap_code     = BGP_CAP_T_MPNLRI;
    mpnlri->capHdr.cap_length   = LEN_CAP_MPNLRI;
    mpnlri->afi                 = htons(AFI_V6);
    mpnlri->reserved            = RESERVED_ZERO;
    mpnlri->safi                = SAFI_UNICAST;
    buff += sizeof(BGP_Cap_MPNLRI);
  }

  // Announce Route Refresh
  if (config->capConf.route_refresh)
  {
    optParam = (BGP_OpenMessage_OptParam*)buff;
    optParam->param_type = BGP_T_CAP;
    optParam->param_len  = sizeof(BGP_Cap_RREFRESH);    
    buff += sizeof(BGP_OpenMessage_OptParam);
    
    rrefresh = (BGP_Cap_RREFRESH*)buff;
    rrefresh->capHdr.cap_code   = BGP_CAP_T_RREFRESH;
    rrefresh->capHdr.cap_length = LEN_CAP_RREFRESH;
    buff += sizeof(BGP_Cap_RREFRESH);
  }
  
  // Announce Extended Message Support
  if (config->capConf.extMsgSupp)
  {
    optParam = (BGP_OpenMessage_OptParam*)buff;
    optParam->param_type = BGP_T_CAP;
    optParam->param_len  = sizeof(BGP_Cap_ExtMsgSupport);    
    buff += sizeof(BGP_OpenMessage_OptParam);
    
    extMsg = (BGP_Cap_ExtMsgSupport*)buff;
    extMsg->capHdr.cap_code   = BGP_CAP_T_EXT_MSG_SUPPORT;
    extMsg->capHdr.cap_length = LEN_CAP_EXT_MSG_SUPPORT;
    buff += sizeof(BGP_Cap_RREFRESH);
  }
  
  // Announce 4 byte ASN
  if (config->capConf.asn_4byte)
  {
    optParam = (BGP_OpenMessage_OptParam*)buff;
    optParam->param_type = BGP_T_CAP;
    optParam->param_len  = sizeof(BGP_Cap_AS4);    
    buff += sizeof(BGP_OpenMessage_OptParam);
    
    as4 = (BGP_Cap_AS4*)buff;
    as4->capHdr.cap_code     = BGP_CAP_T_AS4;
    as4->capHdr.cap_length   = LEN_CAP_AS4;
    as4->myAS                = htonl(config->asn);
    buff += sizeof(BGP_Cap_AS4);
  }

  // Announce BGPSEC for both, sending, receiving, IPv4 and IPv6
  // The receiving could be stripped because the player does drop traffic.
  if (config->capConf.bgpsec_snd_v4)
  {
    optParam = (BGP_OpenMessage_OptParam*)buff;
    optParam->param_type = BGP_T_CAP;
    optParam->param_len  = sizeof(BGP_Cap_BGPSEC);    
    buff += sizeof(BGP_OpenMessage_OptParam);
    
    bgpsec = (BGP_Cap_BGPSEC*)buff;
    bgpsec->capHdr.cap_code     = BGP_CAP_T_BGPSEC;
    bgpsec->capHdr.cap_length   = LEN_CAP_BGPSEC;
    bgpsec->firstOctet          =   (BGPSEC_VERSION << ADDR_IP_V4) 
                                  | (BGPSEC_DIR_SND << 3);
    bgpsec->afi                 = htons(AFI_V4);
    buff += sizeof(BGP_Cap_BGPSEC);
  }

  if (config->capConf.bgpsec_rcv_v4)
  {
    optParam = (BGP_OpenMessage_OptParam*)buff;
    optParam->param_type = BGP_T_CAP;
    optParam->param_len  = sizeof(BGP_Cap_BGPSEC);
    buff += sizeof(BGP_OpenMessage_OptParam);
    
    bgpsec = (BGP_Cap_BGPSEC*)buff;
    bgpsec->capHdr.cap_code     = BGP_CAP_T_BGPSEC;
    bgpsec->capHdr.cap_length   = LEN_CAP_BGPSEC;
    bgpsec->firstOctet          =   (BGPSEC_VERSION << ADDR_IP_V4) 
                                  | (BGPSEC_DIR_RCV << 3);
    bgpsec->afi                 = htons(AFI_V4);
    buff += sizeof(BGP_Cap_BGPSEC);
  }
  
  if (config->capConf.bgpsec_snd_v6)
  {
    optParam = (BGP_OpenMessage_OptParam*)buff;
    optParam->param_type = BGP_T_CAP;
    optParam->param_len  = sizeof(BGP_Cap_BGPSEC);
    buff += sizeof(BGP_OpenMessage_OptParam);
    
    bgpsec = (BGP_Cap_BGPSEC*)buff;
    bgpsec->capHdr.cap_code     = BGP_CAP_T_BGPSEC;
    bgpsec->capHdr.cap_length   = LEN_CAP_BGPSEC;
    bgpsec->firstOctet          =   (BGPSEC_VERSION << ADDR_IP_V4) 
                                  | (BGPSEC_DIR_SND << 3);
    bgpsec->afi                 = htons(AFI_V6);
    buff += sizeof(BGP_Cap_BGPSEC);
  }

  if (config->capConf.bgpsec_rcv_v6)
  {
    optParam = (BGP_OpenMessage_OptParam*)buff;
    optParam->param_type = BGP_T_CAP;
    optParam->param_len  = sizeof(BGP_Cap_BGPSEC);
    buff += sizeof(BGP_OpenMessage_OptParam);
    
    bgpsec = (BGP_Cap_BGPSEC*)buff;
    bgpsec->capHdr.cap_code     = BGP_CAP_T_BGPSEC;
    bgpsec->capHdr.cap_length   = LEN_CAP_BGPSEC;
    bgpsec->firstOctet          =   (BGPSEC_VERSION << ADDR_IP_V4) 
                                  | (BGPSEC_DIR_RCV << 3);
    bgpsec->afi                 = htons(AFI_V6);
    buff += sizeof(BGP_Cap_BGPSEC);
  }
  
  return requiredLength;
}

////////////////////////////////////////////////////////////////////////////////
//  KEEP ALIVE MESSAGE
////////////////////////////////////////////////////////////////////////////////

/**
 * Generate a keep alive message. The return value will provide the size in 
 * bytes the open message consumes or if less than 0 the number of bytes needed
 * to generate the open message.
 * 
 * @param buff The pre-allocated memory of sufficient size
 * @param maxLen The size of the buffer
 * 
 * @return the number of bytes used or if less than 0 the number of bytes missed
 */
int createKeepAliveMessge(u_int8_t* buff, int buffSize)
{
  int requiredLength = sizeof(BGP_KeepAliveMessage);
  if (buffSize < requiredLength)
  {
    return buffSize - requiredLength;
  }
  
  // the memset can be removed later on for speed up.
  memset (buff, 0, buffSize);
  BGP_MessageHeader* keepAliveMsg = (BGP_MessageHeader*)buff;
  
  memset (keepAliveMsg->marker, BGP_MARKER_VAL, BGP_MARKER_SIZE);
  keepAliveMsg->length = htons(requiredLength);
  keepAliveMsg->type   = BGP_T_KEEPALIVE;
  
  return requiredLength;
}

////////////////////////////////////////////////////////////////////////////////
//  NOTIFY MESSAGE
////////////////////////////////////////////////////////////////////////////////

/**
 * Generate a KeepAlive message. The buffer must be large enough to hold the 
 * complete message. the data size is calculated from the needed using the
 * buffer size.  
 * 
 * @param buff The buffer to store the message in
 * @param buffSize the size of the buffer
 * @param error the error code
 * @param subcode the subcode of the error
 * @param dataLength the length of the attached data
 * @param data the attached data
 * 
 * @return the number of bytes written or if less than 0 the number of bytes 
 *         missed
 */
int createNotificationMessage(u_int8_t* buff, int buffSize, 
                              u_int8_t error, u_int8_t subcode, 
                              u_int16_t dataLength, u_int8_t* data)
{
  int requiredLength = sizeof(BGP_NotificationMessage) + dataLength;
  if (buffSize < requiredLength)
  {
    return buffSize - requiredLength;
  }
  
  // the memset can be removed later on for speed up.
  memset (buff, 0, buffSize);
  BGP_NotificationMessage* notificationMsg = (BGP_NotificationMessage*)buff;
  
  memset (notificationMsg->messageHeader.marker, BGP_MARKER_VAL, 
          BGP_MARKER_SIZE);
  notificationMsg->messageHeader.length = htons(requiredLength);
  notificationMsg->messageHeader.type   = BGP_T_NOTIFICATION;
  
  notificationMsg->error_code = error;
  notificationMsg->sub_code   = subcode;
  
  if (dataLength > 0)
  {
    int offset = sizeof(BGP_NotificationMessage);
    u_int8_t* msgBuff = buff + offset;
    memcpy(msgBuff, data, dataLength);    
  }
  
  return requiredLength;  
}

////////////////////////////////////////////////////////////////////////////////
//  UPDATE MESSAGE
////////////////////////////////////////////////////////////////////////////////

/**
 * Generate the regular AS_PATH attribute. The Attribute uses 4 byte AS numbers.
 * 
 * @param myAsn     The own ASN to be inserted into the path.
 * @param iBGP      Indicate if the session is an iBGP session or nor.
 * @param asPathStr The AS path string
 * @param buff      The buffer where to write the attribute into.
 * @param buffSize  The maximum size of the buffer.
 * 
 * @return The buffer type casted to BGP_PathAttribte or NULL if the buffer is
 *         not large enough. 
 */
BGP_PathAttribute* generateBGP_PathAttr(u_int32_t myAsn, bool iBGP, 
                                        char* asPathStr, 
                                        u_int8_t* buff, int buffSize)
{
  int pLength = 0;  
  BGP_PathAttribute* asPath = NULL;  

  // Construct the AS_PATH string
  char* longPath = convertAsnPath(asPathStr);  
  if (!iBGP)
  {
    // Add myself to the path. BZ:922
    int digits = (int)(log10(myAsn)) + 2; // 1 for the blank and 1 to round up  
    char* myPath = malloc(strlen(longPath) + digits);
    sprintf (myPath, "%u %s%c", myAsn, longPath, '\0');
    free(longPath);
    longPath = myPath;  
  }

  tASNTokenizer tok;
  asntok_clear_th(&tok);
  asntok_th(longPath, &tok);
  u_int32_t asn;
  asPath = (BGP_PathAttribute*)buff;

  asPath->attr_flags     = BGP_UPD_A_FLAGS_TRANSITIVE;
  asPath->attr_type_code = BGP_UPD_A_TYPE_AS_PATH;

  buff += sizeof(BGP_PathAttribute);

  // First count all ASN's to check if we need an extended length field  
  while (asntok_next_th(&asn, &tok))
  {
    pLength++;
  }
  asntok_reset_th(&tok);

  // calculate  the length required for storing only the AS numbers.
  int length = pLength * 4;
  // calculate the number of segments needed to store the AS numbers
  int segments = (pLength > 0) ? (int)(pLength / 255) + 1 : 0;
  // calculate the total byte size needed to store the AS numbers including
  // the required header size for each needed AS_PathSegment
  int attrLength = segments * sizeof(BGP_Upd_AS_PathSegment) + length;

  if (attrLength > buffSize)
  {
    return NULL;
  }

  if (length > 255)
  {
    u_int16_t* wLength = (u_int16_t*)buff;
    *wLength = htons((u_int16_t)attrLength);
    asPath->attr_flags |= BGP_UPD_A_FLAGS_EXT_LENGTH;
    buff += 2;    
  }
  else
  {
    *buff = (u_int8_t)attrLength;
    buff++;
  }

  u_int32_t* asnPtr;

  while (segments > 0)
  {
    segments--;
    BGP_Upd_AS_PathSegment* pathSegment = (BGP_Upd_AS_PathSegment*)buff;
    pathSegment->segmentType    = BGP_UPD_A_FLAGS_ASPATH_AS_SEQ;
    pathSegment->segment_length = segments > 0 ? 255 : pLength;
    buff += sizeof(BGP_Upd_AS_PathSegment);
    int ct = 255;
    while (ct > 0 && pLength > 0)
    {
      pLength--;
      asnPtr = (u_int32_t*)buff;
      if (asntok_next_th(&asn, &tok))
      {
        *asnPtr = htonl(asn);
        buff += 4;
        ct--;
      }
      else
      {
        ct = 0;
      }
    }
  }
  if (longPath != NULL)
  {
    memset(longPath, '\0', strlen(longPath));
    free(longPath);
  }
  longPath = NULL;
  
  return asPath;
}

/**
 * Generate the BGPSEC update. The return value will provide the size in 
 * bytes the open message consumes or if less than 0 the number of bytes needed
 * to generate the open message.
 * The parameter useMPNLRI will be internally set to true for all IPv6
 * prefixes.
 * 
 * @param buff The   pre-allocated memory of sufficient size
 * @param buffSize   The size of the buffer
 * @param pathAttr   The buffer containing either the BGPSec path attribute or
 *                   the BGP4 ASpath attribute. (wire format)
 * @param origin     The origin of the prefix.
 * @param localPref  USe local pref attribute if > 0
 * @param nextHop    Pointer to nextHop address; Must be either a 
 *                   (struct sockaddr_in*) or (struct sockaddr_in6*) pointer.
 * @param nlri       The NLRI to be used. Depending on the AFI value it will be 
 *                   typecast to either BGPSEC_V4Prefix or BGPSEC_V6Prefix
 * @param useMPNLRI  Encode IPv4 prefixes as MPNLRI within the path attribute, 
 *                   otherwise V4 addresses will be added at the end as NLRI
 *                  
 * 
 * @return the number of bytes used or if less than 0 the number of bytes missed
 */
int createUpdateMessage(u_int8_t* buff, int buffSize, 
                        BGP_PathAttribute* pathAttr, u_int8_t origin,
                        u_int32_t localPref, void* nextHop, 
                        BGPSEC_PrefixHdr* nlri, bool useMPNLRI)
{
  int idx = 0; 
  
  if (ntohs(nlri->afi) == AFI_V6)
  {
    // IPv6 MUST be encoded in MPNLRI
    useMPNLRI = true;
  }  
  
  int sizePathAttr = getPathAttributeSize(pathAttr); // includes the header size;
  int sizeOrigin   = sizeof(BGP_Upd_Attr_Origin);
  int sizeMED      = sizeof(BGP_Upd_Attr_MED);
  int sizeLocPref  = localPref > 0 ? sizeof(BGP_Upd_Attr_LocPref) : 0;
  int sizeMPNLRI   = 0; // will be determined later if used
  
  int sizeNextHop  = useMPNLRI ? 0 : sizeof(BGP_Upd_Attr_NextHop);
      
  // length without the path attribute length. 
  // (adding values here, don't forget to adjust the attrLength at the end of
  //  this function. This caused me already some painful debugging.)
  int length =  sizeof(BGP_UpdateMessage_1)+sizeof(BGP_UpdateMessage_2)
              + sizePathAttr + sizeOrigin + sizeMED + sizeLocPref + sizeNextHop;
    
  // The buffer needs to be at least the required size. Most likely even a bit 
  // longer but if it is not even this length then stop right here and return 
  // with the number missing (as negative number))
  if (buffSize < length)
  {
    return buffSize - length;
  }
  
  // the memset can be removed later on for speed up.
  memset (buff, 0, buffSize);
  
  // Now set the header of the update
  BGP_UpdateMessage_1* update_hdr1 = (BGP_UpdateMessage_1*)buff;
  
  update_hdr1->messageHeader.length = 0; // will be set at the end
  memset (update_hdr1->messageHeader.marker, BGP_MARKER_VAL, BGP_MARKER_SIZE);
  update_hdr1->messageHeader.type   = BGP_T_UPDATE;
  
  // No routes to withdraw here.
  update_hdr1->withdrawn_routes_length = 0;
  
  // Now move the buffer to the next position. - no withdrawn updates that's why
  // we don't have to consider the withdrawn_routes_length 
  buff += sizeof(BGP_UpdateMessage_1); 
  
  // Move on tho the next template
  BGP_UpdateMessage_2* update_hdr2 = (BGP_UpdateMessage_2*)buff;
  
  // This will be updated along the way
  update_hdr2->path_attr_length = 0; // will be set at the end. 
  buff += sizeof(BGP_UpdateMessage_2); 
  
  // Set the ORIGIN
  BGP_Upd_Attr_Origin* attrOrigin     = (BGP_Upd_Attr_Origin*)buff;
  attrOrigin->pathattr.attr_flags     = BGP_UPD_A_FLAGS_TRANSITIVE;
  attrOrigin->pathattr.attr_type_code = BGP_UPD_A_TYPE_ORIGIN;
  attrOrigin->length = sizeof(attrOrigin->origin); //1;
  attrOrigin->origin = origin;
  buff += sizeOrigin;
         
  // Set MED (Optional)
  BGP_Upd_Attr_MED* attrMED = (BGP_Upd_Attr_MED*)buff;
  attrMED->pathattr.attr_flags     = BGP_UPD_A_FLAGS_OPTIONAL;
  attrMED->pathattr.attr_type_code = BGP_UPD_A_TYPE_MED;
  attrMED->length  = sizeof(attrMED->med); //4;
  attrMED->med     = 0;
  buff += sizeMED;
  
  // set Local Pref - Is only done for iBGP sessions
  if (localPref > 0)
  {
    BGP_Upd_Attr_LocPref* attrLocPref = (BGP_Upd_Attr_LocPref*)buff;
    attrLocPref->pathattr.attr_flags     = BGP_UPD_A_FLAGS_TRANSITIVE;
    attrLocPref->pathattr.attr_type_code = BGP_UPD_A_TYPE_LOC_PREF;
    attrLocPref->length    = sizeof(attrLocPref->localPref); // 4
    attrLocPref->localPref = htonl(localPref);
    buff += sizeLocPref;
  }
  
  if (!useMPNLRI)
  {
    // Set the next hop
    BGP_Upd_Attr_NextHop* attrNextHop    = (BGP_Upd_Attr_NextHop*)buff;
    attrNextHop->pathattr.attr_flags     = BGP_UPD_A_FLAGS_TRANSITIVE;
    attrNextHop->pathattr.attr_type_code = BGP_UPD_A_TYPE_NEXT_HOP;
    attrNextHop->length  = sizeof(attrNextHop->nextHop); //4;
    
    struct sockaddr_in* nh = (struct sockaddr_in*)nextHop;
    attrNextHop->nextHop = nh->sin_addr.s_addr; 
    buff += sizeNextHop;
  }
  else
  {
    // If MPNLRI set it here
    BGP_Upd_Attr_MPNLRI_1* attrMPNLRI_1 = (BGP_Upd_Attr_MPNLRI_1*)buff;
    attrMPNLRI_1->pathattr.attr_flags     = BGP_UPD_A_FLAGS_OPTIONAL;
    attrMPNLRI_1->pathattr.attr_type_code = BGP_UPD_A_TYPE_MP_REACH_NLRI;
    // Length will be calculated further down
    
    attrMPNLRI_1->afi  = nlri->afi;
    attrMPNLRI_1->safi = nlri->safi;
    
    // move the buffer to the next hop IP
    buff += sizeof(BGP_Upd_Attr_MPNLRI_1);

    if (ntohs(nlri->afi) == AFI_V4)
    {
      // if V4 don't use padding for the next hop
      attrMPNLRI_1->nextHopLen = 4;
      struct sockaddr_in* nh = (struct sockaddr_in*)nextHop;
      u_int32_t nextHopV4 = nh->sin_addr.s_addr;
      memcpy(buff, &nextHopV4, 4);
      buff += 4;    
    }
    else
    {
      // Use all 16 bytes. the address is already in network format, so 
      // just copy the array intot he buffer.
      attrMPNLRI_1->nextHopLen = 16;    
      struct sockaddr_in6* nh = (struct sockaddr_in6*)nextHop;
      memcpy (buff, nh->sin6_addr.__in6_u.__u6_addr8, 16);
      buff += 16;
    }
        
    
    // Now take care of the MPNLRI
    BGP_Upd_Attr_MPNLRI_2* attrMPNLRI_2 = (BGP_Upd_Attr_MPNLRI_2*)buff;
    attrMPNLRI_2->reserved = 0;
    attrMPNLRI_2->nlri.length = nlri->length;
    // Move the buffer
    buff += sizeof(BGP_Upd_Attr_MPNLRI_2);
    
    // Copy the NLRI into the buffer
    buff += cpyBGPSecAddrMem(nlri->afi, buff, nlri);
        
    // Now calculate the attribute length.
    attrMPNLRI_1->length = sizeof(attrMPNLRI_1->afi)
                          + sizeof(attrMPNLRI_1->safi)
                          + sizeof(attrMPNLRI_1->nextHopLen)
                          + attrMPNLRI_1->nextHopLen      /* for next hop ip */
                          + sizeof(attrMPNLRI_2->reserved)
                          + sizeof(attrMPNLRI_2->nlri.length)
                          + numBytes(attrMPNLRI_2->nlri.length);/* for prefix */
    
    sizeMPNLRI = getPathAttributeSize((BGP_PathAttribute*)attrMPNLRI_1);
    length += sizeMPNLRI;
  }
  
  // Now store the BGP(SEC) path attribute
  memcpy(buff, pathAttr, sizePathAttr);
  buff += sizePathAttr;
  
  // SET NLRI
  if (!useMPNLRI)
  {
    u_int8_t nlriLen = numBytes(nlri->length);
    *buff = nlri->length;
    buff++;
    cpyBGPSecAddrMem(nlri->afi, buff, nlri);
    length += nlriLen + 1; //
  }
  
  // Now set the correct length values.
  u_int16_t attrSize =   sizeOrigin + sizeMED + sizeLocPref + sizeMPNLRI 
                       + sizeNextHop + sizePathAttr;
  
  update_hdr2->path_attr_length     = htons(attrSize);
  update_hdr1->messageHeader.length = htons(length);
  
  return length;
}

////////////////////////////////////////////////////////////////////////////////
// UTILITY FUNCTIONS
////////////////////////////////////////////////////////////////////////////////

/**
 * Calculates the number of bytes needed to specify x bits.
 * This is used to shorten IP prefixes to the max number of bytes needed. A
 * /16 prefix only is 3 bytes of size with 1 byte for the length and 2 bytes for 
 * the IP portion. A /17-/14 prefix is 4 bytes with 1 for length and 3 for the
 * IP portion itself.
 * 
 * @param bits the number of bits.
 * 
 * @return return the number of bytes needed.
 */
u_int8_t numBytes(int bits)
{
  u_int8_t ret = bits / 8;
  if (bits % 8 > 0)
  {
    ret++;
  }
  return ret;
}

/**
 * Calculate the min number of bytes required to store the padded IPv4 address
 * 
 * @param ip4 the IPv4 Address
 * 
 * @return the number of bytes needed to store the value.
 */
//u_int8_t numBytesForIP4(u_int32_t ip4)
//{
//  u_int8_t retVal = 0;
//  retVal = (ip4 & 0xFFFFFFFF) == 0 ? 0 
//            : (ip4 & 0x00FFFFFF) == 0 ? 1
//              : (ip4 & 0x0000FFFF) == 0 ? 2
//                : (ip4 & 0x000000FF) == 0 ? 3 : 4;
//  
//  return retVal;
//}

/**
 * Calculate the min number of bytes required to store the padded IP address
 * 
 * @param ip the IPv4 or IPv6 Address
 * @param ipV4 Indicates if the address is an IPv4 address or IPv6 address.
 * 
 * @return the number of bytes needed to store the value.
 */
u_int8_t numBytesForIP(u_int64_t ip)
{
  u_int8_t retVal = 0;
  
  retVal = (ip & 0xFFFFFFFFFFFFFFFF) == 0 ? 0
           : (ip & 0x00FFFFFFFFFFFFFF) == 0 ? 1
              : (ip & 0x0000FFFFFFFFFFFF) == 0 ? 2
                 : (ip & 0x000000FFFFFFFFFF) == 0 ? 3
                    : (ip & 0x00000000FFFFFFFF) == 0 ? 4
                       : (ip & 0x0000000000FFFFFF) == 0 ? 5
                          : (ip & 0x000000000000FFFF) == 0 ? 6
                             : (ip & 0x00000000000000FF) == 0 ? 7 : 8;
  
  return retVal;
}

/**
 * Copy the address portion of the given prefix into the given buffer.
 * 
 * @param afi the address family identifier (AFI_V4 | AFI_V6 | ADDR_IP_V4 | ADDR_IP_V6)            
 * @param buff the buffer where to copy the data into
 * @param prefix the prefix where to copy the data from
 * 
 * @return the number of bytes copied.
 */
int cpyBGPSecAddrMem(u_int16_t afi, u_int8_t* buff, BGPSEC_PrefixHdr* prefix)
{
  int length = numBytes(prefix->length);
    
  // convert afi to host format if necessary
  if (afi && 0xFF00 != 0)
  {
    // here all acceptable values would only use the lower byte if in host 
    // format.
    afi = ntohs(afi);
  }
  
  switch (afi)
  {
    case AFI_V6:
    case ADDR_IP_V6:
      memcpy(buff, ((BGPSEC_V6Prefix*)prefix)->addr, length);
      break;
    case AFI_V4:
    case ADDR_IP_V4:
    default:
      memcpy(buff, ((BGPSEC_V4Prefix*)prefix)->addr, length);
      break;
  }
  
  return length;
}

/**
 * Calculate the complete size of the attribute
 * 
 * @param attribute The attribute whose size is requested
 * 
 * @return the complete size in bytes. 
 */
int getPathAttributeSize(BGP_PathAttribute* attribute)
{
  int        size = sizeof(BGP_PathAttribute);
  u_int16_t* wLen = NULL;
  u_int8_t*  ptr  = (u_int8_t*)attribute;
  ptr += sizeof(BGP_PathAttribute);
  if (attribute->attr_flags & BGP_UPD_A_FLAGS_EXT_LENGTH)
  {    
    wLen = (u_int16_t*)ptr;
    size += ntohs(*wLen) + 2;
  }
  else
  {
    size += *ptr + 1;    
  }
  
  return size;  
}
