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
 * This API contains a the headers and function to generate proper BGP messages.
 *
 * @version 0.2.0.1
 *   
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.0.1 - 2016/06/24 - oborchert
 *            * Modified function generateBGP_PathAttr to allow detection of
 *              iBGP sessions.
 *            * Added missing BGP_Upd_Attr_LocPref structure.
 *  0.2.0.0 - 2016/05/16 - oborchert
 *            * Added CEASE Notificatoin Subcodes RFC 4486
 *          - 2016/05/12 - oborchert
 *            * Modified nexthop to u_int64_t in header of createUpdate
 *  0.1.1.0 - 2016/04/21 - oborchert
 *            * Added indicator if fake signature was used.
 *            * Added generation of BGP_PathAttribute.
 *          - 2016/04/19 - oborchert
 *            * Added configuration for fallback methods in case the signature
 *              could not be generated.
 *          - 2016/04/15 - oborchert
 *            * Fixed function cpyBGPSecAddrMem which had invalid type of afi.
 *          - 2016/03/26 - oborchert
 *            * Added struct AlgoParam and extended BGPSession struct.
 *          - 2016/03/25 - oborchert
 *            * Added type BGP_Upd_Attr_NextHop
 *          - 2016/03/15 - oborchert
 *            * Modified numBytesForIP4 to numBytesForIP to also allow IPv6
 *  0.1.0.0 - 2015/08/13 - oborchert
 *            * Created File.
 */
#ifndef BGPHEADER_H
#define	BGPHEADER_H

#include <stdbool.h>
#include <netinet/in.h>
#include <sys/types.h>
#include "ASList.h"

#define IPSTR_LEN           255

// USED FOR DEBUGGING / PRINTING BGP MESSAGES
#define PRNT_MSG_COUNT 4
#define PRNT_MSG_OPEN          0
#define PRNT_MSG_UPDATE        1
#define PRNT_MSG_NOTIFICATION  2
#define PRNT_MSG_KEEPALIVE     3

// BGP MESSAGE TYPES
#define BGP_T_OPEN          1  
#define BGP_T_UPDATE        2
#define BGP_T_NOTIFICATION  3
#define BGP_T_KEEPALIVE     4



#define BGP_T_OPEN          1  
#define BGP_T_UPDATE        2
#define BGP_T_NOTIFICATION  3
#define BGP_T_KEEPALIVE     4

#define BGP_MARKER_VAL      0xFF
#define BGP_MARKER_SIZE     16
#define BGP_MAX_HDR_SIZE    10000
#define BGP_VERSION         4
#define BGP_MIN_OPEN_LENGTH 29

#define BGP_T_CAP           2
#define BGP_CAP_T_MPNLRI          1
#define BGP_CAP_T_RREFRESH        2
#define BGP_CAP_T_AS4            65
// 72 is in Conflict
// http://www.iana.org/assignments/capability-codes/capability-codes.xhtml
#define BGP_CAP_T_BGPSEC         72
#define BGP_CAP_T_RREFRESH_PRIV 128

#define LEN_CAP_MPNLRI      4
#define LEN_CAP_AS4         4
#define LEN_CAP_BGPSEC      3
#define LEN_CAP_RREFRESH    0

#define AFI_V4              1
#define AFI_V6              2  
#define RESERVED_ZERO       0
#define SAFI_UNICAST        1

#define BGPSEC_VERSION      0
#define BGPSEC_DIR_SND      0
#define BGPSEC_DIR_RCV      1

// RFC 4271 - 4.3
#define BGP_UPD_A_TYPE_ORIGIN   1
#define BGP_UPD_A_TYPE_AS_PATH  2 
#define BGP_UPD_A_TYPE_NEXT_HOP 3
#define BGP_UPD_A_TYPE_MED      4
#define BGP_UPD_A_TYPE_LOC_PREF 5
#define BGP_UPD_A_TYPE_ATOM_AGG 6
#define BGP_UPD_A_TYPE_AGGR     7
// RFC 4360 - 2
#define BGP_UPD_A_TYPE_EXT_COMM 16
// Will be BGPSEC RFC
#define BGP_UPD_A_TYPE_BGPSEC   30

// RFC 4760 - 3
#define BGP_UPD_A_TYPE_MP_REACH_NLRI 14

// Defines if the attribute is optional or not
#define BGP_UPD_A_FLAGS_OPTIONAL       0x80
// not set is NON_TRANSITIVE, set is TRANSITIVE (Well known needs transitive)
#define BGP_UPD_A_FLAGS_TRANSITIVE     0x40
// set is PARTIAL, not set is COMPLETE (well known and optional non trans must be not set)
#define BGP_UPD_A_FLAGS_PARTIAL        0x20
// defines it the length attribute is one octet or two octets
#define BGP_UPD_A_FLAGS_EXT_LENGTH     0x10
#define BGP_UPD_A_FLAGS_ORIGIN_IGP       0
#define BGP_UPD_A_FLAGS_ORIGIN_EGP       1
#define BGP_UPD_A_FLAGS_ORIGIN_INC       2
#define BGP_UPD_A_FLAGS_ASPATH_AS_SET    1
#define BGP_UPD_A_FLAGS_ASPATH_AS_SEQ    2
// some default local pref value - is default in quagga for iBGP session.
#define BGP_UPD_A_FLAGS_LOC_PREV_DEFAULT 100
// BGPSEC Attr: 0x90 (1 opt, 0 non-trans, 0 complete, 1 ext length)
#define BGP_UPD_A_FLAGS_BGPSEC         0x90

#define BGP_ERR1_MESSAGE_HEADER     1
#define BGP_ERR2_OPEN_MESSAGE       2
#define BGP_ERR3_UPDATE_MESSAGE     3
#define BGP_ERR4_HOLD_TIMER_EXPIRED 4
#define BGP_ERR5_FSM                5
#define BGP_ERR6_CEASE              6

#define BGP_ERR_SUB_UNDEFINED   0

#define BGP_ERR1_SUB_NOT_SYNC   1
#define BGP_ERR1_SUB_BAD_LENGTH 2
#define BGP_ERR1_SUB_BAD_TYPE   3

#define BGP_ERR2_SUB_VERSION             1
#define BGP_ERR2_SUB_BAD_PEERAS          2
#define BGP_ERR2_SUB_BAD_BGPIDENT        3
#define BGP_ERR2_SUB_UNSUPP_OPT_PARAM    4
#define BGP_ERR2_SUB_DEPRECATED          5
#define BGP_ERR2_SUB_UNACCEPTED_HOLDTIME 6

#define BGP_ERR3_SUB_MALFORMED_ATTR_LIST    1
#define BGP_ERR3_SUB_UNRECOG_WELLKNOWN_ATTR 2
#define BGP_ERR3_SUB_MISSING_WELLKNOWN_ATTR 3
#define BGP_ERR3_SUB_ATTR_FLAG_ERR          4
#define BGP_ERR3_SUB_ATTR_LEN_ERR           5
#define BGP_ERR3_SUB_INVALID_ORIGIN_ATTR    6
#define BGP_ERR3_SUB_DEPRECATED             7
#define BGP_ERR3_SUB_INVLAID_NEXT_HOP       8
#define BGP_ERR3_SUB_OPTIONAL_ATTR_ERR      9
#define BGP_ERR3_SUB_INVALID_NETWORK_FIELD  10
#define BGP_ERR3_SUB_MALFORMED_AS_PATH      11
// Possible future error codes:
#define BGP_ERR3_SUB_UNSUPPORTED_BGPSEC_VER  0

// RFC 4486 Subcodes for BGP Cease Notification Message
#define BGP_ERR6_SUB_MAX_NUM_PREFIXES       1
#define BGP_ERR6_SUB_ADMIN_SHUTDOWN         2
#define BGP_ERR6_SUB_PEER_DE_CONFIGURED     3
#define BGP_ERR6_SUB_ADMIN_RESET            4
#define BGP_ERR6_SUB_CONNECTION_REJECTED    5
#define BGP_ERR6_SUB_OTHER_CONFIG_CHANGE    6
#define BGP_ERR6_SUB_CONN_COLL_RESOLUTION   7
#define BGP_ERR6_SUB_OUT_OF_RESOURCES       8

typedef struct {
  u_int8_t  marker[BGP_MARKER_SIZE]; // must be set to 1
  u_int16_t length;
  u_int8_t  type;
} __attribute__((packed)) BGP_MessageHeader;

/* Open Message Format RFC4271 - 4.2 */
typedef struct {
  BGP_MessageHeader messageHeader;
  /* This 1-octet unsigned integer indicates the protocol version number of the 
   * message.  The current BGP version number is 4. */
  u_int8_t  version;
  /* This 2-octet unsigned integer indicates the Autonomous System number of 
   * the sender. */
  u_int16_t my_as;
  /* This 2-octet unsigned integer indicates the number of seconds the sender 
   * proposes for the value of the Hold Timer.  Upon receipt of an OPEN message, 
   * a BGP speaker MUST calculate the value of the Hold Timer by using the 
   * smaller of its configured Hold Time and the Hold Time received in the OPEN 
   * message.  The Hold Time MUST be either zero or at least three seconds.  An
   * implementation MAY reject connections on the basis of the Hold Time.  The 
   * calculated value indicates the maximum number of seconds that may elapse 
   * between the receipt of successive KEEPALIVE and/or UPDATE messages from 
   * the sender. */
  u_int16_t hold_time;
  /* This 4-octet unsigned integer indicates the BGP Identifier of the sender.
   * A given BGP speaker sets the value of its BGP Identifier to an IP address 
   * that is assigned to that BGP speaker.  The value of the BGP Identifier is 
   * determined upon startup and is the same for every local interface and BGP 
   * peer. */
  u_int32_t bgp_identifier;
  /* This 1-octet unsigned integer indicates the total length of the Optional 
   * Parameters field in octets.  If the value of this field is zero, no 
   * Optional Parameters are present. */
  u_int8_t  opt_param_len;
  // Followed by Optional parameters (variable)
} __attribute__((packed)) BGP_OpenMessage;

/* Optional Parameters RFC4271 - 4.2 */
typedef struct {
  u_int8_t param_type;
  u_int8_t param_len;
  // Followed by the parameter value (variable))
} __attribute__((packed)) BGP_OpenMessage_OptParam;

/* KeepAlive Message RFC 4271 - 4.4 */
typedef BGP_MessageHeader BGP_KeepAliveMessage;

typedef struct {
  BGP_MessageHeader messageHeader;
  u_int8_t  error_code;
  u_int8_t  sub_code;
  // Followed by data - the length of data depends on the error code and can be 
  // determined by the overall length of the packet specified in messageHeader.
} __attribute__((packed)) BGP_NotificationMessage;

/* Update Message RFC4271 - 4.3 */
typedef struct {
  BGP_MessageHeader messageHeader;
  u_int16_t withdrawn_routes_length; 
  // Variable withdrawn routes
} __attribute__((packed)) BGP_UpdateMessage_1;

typedef struct {
  u_int16_t path_attr_length;
  // Variable path attributes
} __attribute__((packed)) BGP_UpdateMessage_2;

/* BGP Update Path Attribute RFC4271 - 4.3 */
typedef struct {
  u_int8_t attr_flags;
  u_int8_t attr_type_code;
} __attribute__((packed)) BGP_PathAttribute;

/** BGP Capabilities RFC5492 */
typedef struct {
  /* the capability code RFC4271 - 4.2 */
  u_int8_t cap_code;
  /* length of the capability value */
  u_int8_t cap_length;
  // Followed by the capability
} __attribute__((packed)) BGP_Capabilities;

/** The capability for bgpsec encoding */
typedef struct {
  BGP_OpenMessage_OptParam paramHdr;
  BGP_Capabilities capHdr;
  u_int8_t  firstOctet; // 4 bit version (1), 1 bit direction, 3 bits reserved 0
  u_int16_t afi;        // 0 v6, 1 v4
} __attribute__((packed)) BGP_Cap_BGPSEC;

/** The capability for MPNLRI encoding */
typedef struct {
  BGP_OpenMessage_OptParam paramHdr;
  BGP_Capabilities capHdr;
  u_int16_t afi;       // 1 for IPv4; 0 IPv5
  u_int8_t  reserved;  // 0
  u_int8_t  safi;      // 1 for unicast
} __attribute__((packed)) BGP_Cap_MPNLRI;

/** The capability for route refresh */
typedef struct {
  BGP_OpenMessage_OptParam paramHdr;
  BGP_Capabilities capHdr; // length 0
} __attribute__((packed)) BGP_Cap_RREFRESH;

/* The data structure for the AS4 capability */
typedef struct {
  BGP_OpenMessage_OptParam paramHdr;
  BGP_Capabilities capHdr;
  u_int32_t myAS;
} __attribute__((packed)) BGP_Cap_AS4;

///// BGP UPDATE ATTRIBUTE STRUCTS
/* The origin structure */
typedef struct {
  BGP_PathAttribute pathattr;
  u_int8_t length; // 1 byte
  u_int8_t origin;
} __attribute__((packed)) BGP_Upd_Attr_Origin;

/* The AP_PATH structure */
typedef struct {
  u_int8_t  segmentType;    // The segment type AS_SET(1) or AS_SEQUENCE(2)
  u_int8_t  segment_length; // number of ASes, not octets.
  // Followed by the AS list
}__attribute__((packed)) BGP_Upd_AS_PathSegment;

/* The next hop structure */
typedef struct {
  BGP_PathAttribute pathattr;
  u_int8_t  length;  // 4 bytes
  u_int32_t nextHop; // NOT in network format!!!!
} __attribute__((packed)) BGP_Upd_Attr_NextHop;

/* The next hop structure */
typedef struct {
  BGP_PathAttribute pathattr;
  u_int8_t  length;  // 4 bytes
  u_int32_t med; 
} __attribute__((packed)) BGP_Upd_Attr_MED;

/* The local pref structure */
typedef struct {
  BGP_PathAttribute pathattr;
  u_int8_t  length;  // 7 bytes
  u_int32_t localPref;
} __attribute__((packed)) BGP_Upd_Attr_LocPref;

typedef struct {
  u_int8_t length;
  // the address (variable)
} __attribute__((packed)) BGP_Upd_Attr_NLRI;

/* The next hop structure */
typedef struct {
  BGP_PathAttribute pathattr; // Type code 14, optional non-transitive, extended length
  u_int8_t  length;           // 
  u_int16_t afi;
  u_int8_t  safi;
  u_int8_t  nextHopLen; // length in bytes of the padded address
  //followed by next hop (variable))
} __attribute__((packed)) BGP_Upd_Attr_MPNLRI_1;

typedef struct {
  u_int8_t reserved; // MUST be set to 0
  BGP_Upd_Attr_NLRI nlri;
} __attribute__((packed)) BGP_Upd_Attr_MPNLRI_2;


///// BGPSEC STRUCTS //////////////////////

typedef struct {
  BGP_PathAttribute pathattr;
  u_int16_t attrLength; // requires ext. length 0x10 set
} __attribute__((packed)) BGPSEC_PathAttribute;

typedef struct {
  u_int16_t length;  // contains the length of the entire SecurePath
  // Secure Path Segments follow, each path segment is the size of 
  // sizeof(TplSecurePathSegment)
} __attribute__((packed)) BGPSEC_SecurePath;

typedef struct {
  u_int8_t  pCount;
  u_int8_t  flags;
  u_int32_t asn;
} __attribute__((packed)) BGPSEC_SecurePathSegment;

typedef struct {
  u_int16_t length;
  u_int8_t  algoID;
} __attribute__((packed)) BGPSEC_SignatureBlock;

typedef struct {
  u_int8_t  ski[20];
  u_int16_t siglen;  
  // Signature in byte stream of length (siglen) follows
} __attribute__((packed)) BGPSEC_SignatureSegment;

////////////////////////////////////////////////////////////////////////////////
// Non wire Structs
////////////////////////////////////////////////////////////////////////////////

/* Maximum keys used per update and algorithm 
 * This number also restricts the number of unique ASes per update 
 * - arbitrarily large*/
#define MAX_KEYS_IN_UPDATE 300
// MAX signature size
#define MAX_SIG_BYTE_SIZE 255

// Used for configuring what to do if for what ever reason no signature can 
// be generated. This is not RFC code.
typedef enum {
  NS_DROP = 0,
  NS_FAKE = 1,
  NS_BGP4 = 2
} NullSignatureMode;

typedef struct _AlgoParam {
  /** pointer to next used algorithm. */
  struct _AlgoParam* next;
  /** Algorithm ID of the keys */
  u_int8_t algoID; 
  /** list of ASes where keys are available for. */
  TASList* asList;
  
  /** This information changed during runtime for each signing. In case 
   * addPubKeys == true each signing results in resetting the keysUsed and
   * key array.*/
  bool addPubKeys;
  /** Number of public keys stored in the pubKey array. */
  int pubKeysStored;
  /** key array of keys needed for verify calls. This array is intended to be 
   * used for CAPI or GEN-C mode to be able to pass the public keys to the API
   * call. NULL keys are allowed and pubKeysStored contains the number of keys
   * stored in the pubKey element.
   * The array contains the keys from pubKey[0]= keyOfLastAS to 
   * pubKey[n]= keyOfOriginAS
   */
  BGPSecKey* pubKey[MAX_KEYS_IN_UPDATE];
    
  /* Specify if fake signatures are allowed, BGP4 traffic should be generated or
   * if a null signature results in a dropped update.*/
  NullSignatureMode ns_mode;
  /** indicates if the fake signature was used. */
  bool fakeUsed;  
  u_int8_t  fake_sigLen;
  /* The fake signature (currently 255 bytes) */
  u_int8_t  fake_signature[MAX_SIG_BYTE_SIZE];
  // A Fake Key
  BGPSecKey fake_key;
} AlgoParam;

/** The configuration for the open message. For each attribute set to true a 
 *  capability will be send. */
typedef struct {
  bool mpnlri_v4;
  bool mpnlri_v6;
  bool asn_4byte;
  bool route_refresh;
  bool bgpsec_snd_v4;
  bool bgpsec_snd_v6;
  bool bgpsec_rcv_v4;
  bool bgpsec_rcv_v6;
} BGP_Cap_Conf;

/** General session configuration. */
typedef struct {
  /* ASN number. (host format) */
  u_int32_t asn;
  /* the BGP identifier */
  u_int32_t bgpIdentifier;
  /* The hold timer 0 or at least 3 */
  u_int16_t holdTime;
  /** Time in seconds to keep the session up after the last update is send. 
   * 0 - forever. */
  u_int16_t disconnectTime;  
  
  // @TODO: Add V6 support
  /** The peer server address ipv4 and port */
  struct sockaddr_in peer_addr; 
  /** The ASN of the peer. This must be set to assure we send the correct 
   * signed updates. (host format)*/
  u_int32_t peerAS;
  
  /** 
   * Defines if IPv4 prefixes will be encoded in MPNLRI format or not. 
   * Currently BGP routers do not encode V4 as MPNLRI even though they announce
   * the capability.
   */
  bool useMPNLRI;
  
  /** Print BGP messaged upon receive. (one for each, OPEN, UPDATE, KEEPALIVE, 
   *                                    and NOTIFICATION)*/
  bool printOnReceive[PRNT_MSG_COUNT];
  
  /** Print BGP messaged upon send. (one for each, OPEN, UPDATE, KEEPALIVE, 
   *                                 and NOTIFICATION)*/
  bool printOnSend[PRNT_MSG_COUNT];
  
  /** Specify if the polling information will be printed or not. */
  bool printPollLoop;
  
  /** Specify if status information will be printed on validation result 
   * INVALID. */
  bool printOnInvalid; 
  
  /* the capabilities configuration. */
  BGP_Cap_Conf capConf;
  
  /* The Algorithm Parameter */
  AlgoParam algoParam;
} BGP_SessionConf;

// @TODO: Remove
/** Session configuration for open message incl. capabilities. */
typedef struct {
  /** The BGP session configuration.*/
  BGP_SessionConf sessConf;
  /* the capabilities configuration. */
  BGP_Cap_Conf    capConf;
} BGP_OpenConf1;

/**
 * This struct is used for the nlri and MPnlri processing. It is to be used 
 * together with BGPSEC_V[4/6]Prefix. and can be put atop of one of the two
 * structures. It contains the header information.
 */
typedef struct
{
  u_int16_t afi;
  u_int8_t  safi;
  /* the prefix length, not the required bytes!!! */
  u_int8_t  length;
} __attribute__((packed)) BGPSEC_PrefixHdr;

/**
 * Contains teh IPv4 Prefix information.
 */
typedef struct
{
  BGPSEC_PrefixHdr prefix;
  u_int8_t addr[4];
} __attribute__((packed)) BGPSEC_V4Prefix;

/**
 * Contains the IPv6 prefix information.
 */
typedef struct
{
  BGPSEC_PrefixHdr prefix;
  u_int8_t addr[16];
} __attribute__((packed)) BGPSEC_V6Prefix;

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
int createOpenMessage(u_int8_t* buff, int buffSize, BGP_SessionConf* config);

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
int createKeepAliveMessge(u_int8_t* buff, int buffSize);

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
                              u_int16_t dataLength, u_int8_t* data);

/**
 * Generate the BGPSEC update. The return value will provide the size in 
 * bytes the open message consumes or if less than 0 the number of bytes needed
 * to generate the open message.
 * The parameter useMPNLRI will be internally set to true for all IPv6
 * prefixes.
 * 
 * @param buff The  pre-allocated memory of sufficient size
 * @param buffSize  The size of the buffer
 * @param pathAttr  The buffer containing either the BGPSec path attribute or the
 *                  BGP4 ASpath attribute. (wire format)
 * @param origin    The origin of the prefix.
 * @param localPref USe local pref attribute if > 0
 * @param nextHop   The next hop IP address. (HOST FORMAT)
 * @param nlri The  NLRI to be used. Depending on the AFI value it will be 
 *                  typecast to either BGPSEC_V4Prefix or BGPSEC_V6Prefix
 * @param useMPNLRI Encode IPv4 prefixes as MPNLRI within the path attribute, 
 *                  otherwise V4 addresses will be added at the end as NLRI
 *                  
 * 
 * @return the number of bytes used or if less than 0 the number of bytes missed
 */
int createUpdateMessage(u_int8_t* buff, int buffSize, 
                        BGP_PathAttribute* pathAttr, u_int8_t origin,
                        u_int32_t localPref, u_int64_t nextHop, 
                        BGPSEC_PrefixHdr* nlri, bool useMPNLRI);

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
                                        u_int8_t* buff, int buffSize);

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
u_int8_t numBytes(int bits);

/**
 * Calculate the min number of bytes required to store the padded IP address
 * 
 * @param ip the IPv4 or IPv4 Address
 * 
 * @return the number of bytes needed to store the value.
 */
u_int8_t numBytesForIP(u_int64_t ip);

/**
 * Copy the address portion of the given prefix into the given buffer.
 * 
 * @param afi the address family identifier (AFI_V4 | AFI_V6 | ADDR_IP_V4 | ADDR_IP_V6)
 * @param buff the buffer where to copy the data into
 * @param prefix the prefix where to copy the data from
 * 
 * @return the number of bytes copied.
 */
int cpyBGPSecAddrMem(u_int16_t afi, u_int8_t* buff, BGPSEC_PrefixHdr* prefix);

/**
 * Calculate the complete size of the attribute
 * 
 * @param attribute The attribute whose size is requested
 * 
 * @return the complete size in bytes. 
 */
int getPathAttributeSize(BGP_PathAttribute* attribute);

#endif	/* BGPHEADER_H */

