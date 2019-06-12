/*
 * zigbee.h: zigbee protocol, zigbee cluster library and zigbee smart energy
 *
 * This is free and unencumbered software released into the public domain.
 * See the UNLICENSE file or https://unlicense.org for more details.
 */

#ifndef ZIGBEE_H
#define ZIGBEE_H

/* Functions that you need to implement somewhere, if you use the Time cluster. */
int ZigbeeGetCurrentUtcTime(void);

enum {
  ZIGBEE_DEVICE_PROFILE_ID = 0x0000,
  ZIGBEE_SMART_ENERGY_PROFILE_ID = 0x0109,
};

typedef enum {
  ZIGBEE_BASIC_CLUSTER_ID = 0x0000,
  ZIGBEE_OTA_CLUSTER_ID = 0x0019,  /* [OTA] 5.2 Cluster list */
  ZIGBEE_TIME_CLUSTER_ID = 0x000A,
  ZIGBEE_PRICE_CLUSTER_ID = 0x0700,
  ZIGBEE_METERING_CLUSTER_ID = 0x0702,
  ZIGBEE_TUNNELING_CLUSTER_ID = 0x0704,
  ZIGBEE_KEY_ESTABLISHMENT_CLUSTER_ID = 0x0800,
} ZseClusterId;

typedef enum {
  ZIGBEE_MATCH_DESC_REQ = 0x0006,  /* [ZIGBEE] 2.4.3.1.7 Match_Desc_req */
  ZIGBEE_MATCH_DESC_RSP = 0x8006,  /* [ZIGBEE] 2.4.4.2.7 Match_Desc_rsp */
} ZigbeeZdoClusterId;

/*
 * Endpoint of the Zigbee Device Object that is implemented in all devices.
 * [ZIGBEE] 2.2.5.1.2 Destination Endpoint Field.
 * [ZIGBEE] 2.2.5.1.6 Source Endpoint Field.
 */
enum { ZIGBEE_ZDO_ENDPOINT = 0 };

/*
 * [ZCL] 2.4 General Command Frames
 */
typedef enum {
  ZCL_READ_ATTRIBUTES = 0,
  ZCL_READ_ATTRIBUTES_RESPONSE = 1,
  ZCL_REPORT_ATTRIBUTES = 10,
  ZCL_DEFAULT_RESPONSE = 11,
} ZclCommandId;

/* ZCL 2.5.2 Data Types */
enum {
  ZIGBEE_BITMAP8 = 0x18,
  ZIGBEE_BITMAP32 = 0x1B,
  ZIGBEE_UINT24 = 0x22,
  ZIGBEE_UINT48 = 0x25,
  ZIGBEE_ENUM8 = 0x30,
  ZIGBEE_ENUM16 = 0x31,
  ZIGBEE_UTCTIME = 0xE2,
};

/* ZCL 2.5.3 Status Enumerations */
enum {
  ZIGBEE_SUCCESS = 0x00,
  ZIGBEE_NOT_AUTHORIZED = 0x7E,
  ZIGBEE_MALFORMED_COMMAND = 0x80,
  ZIGBEE_UNSUPPORTED_ATTRIBUTE = 0x86,
  ZIGBEE_ABORT = 0x95,
  ZIGBEE_WAIT_FOR_DATA = 0x97,
  ZIGBEE_NO_IMAGE_AVAILABLE = 0x98,
};

/* ZSE A.2 New Attribute Reporting Status Indication */
enum { ZIGBEE_ATTRIBUTE_REPORTING_STATUS = 0xFFFE };

/* ZSE A.2.1 Attribute Reporting Status Attribute */
enum { ZIGBEE_ATTRIBUTE_REPORTING_COMPLETE = 1 };

void ZigbeeDerivePreconfiguredKey(void *preconfiguredKey, const void *installCode);

/* ZDO */

typedef struct {
  unsigned short nwkAddr;
  unsigned short profileId;
  unsigned short clusterId;
  unsigned char sequenceNumber;
} ZigbeeMatchDescReq;

int ZigbeeParseMatchDescReq(ZigbeeMatchDescReq *req, const void *payload, int length);

/* ZCL commands */

typedef struct {
  unsigned char endpoint;
  unsigned char encryption;
  unsigned short clusterId;
  unsigned short attributeIds[15];
} ZclReadAttributes;

void ZigbeeParseReadAttributes(ZclReadAttributes *attr, int clusterId, const void *payload, int length);
int ZigbeeBuildAttributeRecordStatus(void *record, int attributeId, int status);
int ZigbeeBuildAttributeRecordBitmap8(void *record, int attributeId, int value);
int ZigbeeBuildAttributeRecordBitmap32(void *record, int attributeId, int value);
int ZigbeeBuildAttributeRecordEnum8(void *record, int attributeId, int value);
int ZigbeeBuildAttributeRecordEnum16(void *record, int attributeId, int value);
int ZigbeeBuildAttributeRecordUtcTime(void *record, int attributeId, int value);

/*
 * ZCL Basic Cluster
 *
 * [ZCL] 3.2 Basic Cluster
 */

typedef enum {
  ZCL_PHYSICAL_ENVIRONMENT = 0x0011,  /* 8-bit enumeration */
} ZclBasicAttributeId;

/*
 * ZSE Time Cluster
 *
 * [ZCL] 3.12 Time Cluster
 */

typedef enum {
  ZCL_TIME = 0x0000,  /* UTC time, mandatory */
  ZCL_TIME_STATUS = 0x0001,  /* 8-bit bitmap, mandatory */
} ZclTimeAttributeId;

/*
 * ZSE Metering Cluster
 *
 * [ZSE] D.3 Metering Cluster
 */

typedef enum {
  ZSE_FUNCTIONAL_NOTIFICATION_FLAGS = 0x0000,  /* 32-bit bitmap */
} ZseMeteringAttributeId;

typedef enum {
  ZSE_MIRROR_REPORT_ATTRIBUTE_RESPONSE = 0x09,
} ZseMeteringClientCommandId;

/*
 * ZSE Price Cluster
 *
 * [ZSE] D.4 Price Cluster
 */

typedef enum {
  ZSE_COMMODITY_TYPE = 0x0300,  /* 8-bit enumeration */
} ZsePriceAttributeId;

/*
 * ZSE Key Establishment Cluster
 *
 * [ZSE] Annex C Key Establishment Cluster
 */

typedef enum {
  ZSE_KEY_ESTABLISHMENT_SUITE = 0x0000,  /* 16-bit enumeration */
} ZseKeyEstablishmentAttributeId;

/*
 * ZSE Table C-14 Parameters Used by Methods of the CBKE Protocol
 */
enum {
  /* Number of bytes of the CERTU and CERTV parameters */
  ZIGBEE_CBKE_SUITE2_CERT_SIZE = 74,
  ZIGBEE_CBKE_SUITE2_QE_SIZE = 37,
  ZIGBEE_CBKE_SUITE2_MAC_SIZE = 16,
};

enum {
  ZIGBEE_WAIT_INITIATE_KEY_ESTABLISHMENT_REQUEST,
  ZIGBEE_SEND_INITIATE_KEY_ESTABLISHMENT_RESPONSE,
  ZIGBEE_WAIT_EPHEMERAL_DATA_REQUEST,
  ZIGBEE_GENERATE_EPHEMERAL_DATA,
  ZIGBEE_GENERATING_EPHEMERAL_DATA,
  ZIGBEE_SEND_EPHEMERAL_DATA_RESPONSE,
  ZIGBEE_WAIT_CONFIRM_KEY_DATA_REQUEST,
  ZIGBEE_CALCULATE_SMAC,
  ZIGBEE_CALCULATING_SMAC,
  ZIGBEE_SEND_CONFIRM_KEY_DATA_RESPONSE,
  ZIGBEE_STORE_LINK_KEY,
  ZIGBEE_STORING_LINK_KEY,
  ZIGBEE_SEND_TERMINATE_KEY_ESTABLISHMENT,
};

typedef struct {
  unsigned char myCertificate[ZIGBEE_CBKE_SUITE2_CERT_SIZE];
  unsigned char partnerCertificate[ZIGBEE_CBKE_SUITE2_CERT_SIZE];
  unsigned char myEphemeralPublicKey[ZIGBEE_CBKE_SUITE2_QE_SIZE];
  unsigned char partnerEphemeralPublicKey[ZIGBEE_CBKE_SUITE2_QE_SIZE];
  unsigned char partnerMac[ZIGBEE_CBKE_SUITE2_MAC_SIZE];
  unsigned char initiatorMac[ZIGBEE_CBKE_SUITE2_MAC_SIZE];
  unsigned char responderMac[ZIGBEE_CBKE_SUITE2_MAC_SIZE];
  unsigned char state;
  unsigned char seqnum;  /* transaction sequence number */
  unsigned short partnerNodeId;
  unsigned char myEndpoint;
  unsigned char partnerEndpoint;
} ZigbeeKeyEstablishment;

void ZigbeeReceiveKeyEstablishmentServerCommand(ZigbeeKeyEstablishment *zke, int sourceAddress, int sourceEndpoint, const void *messageContents, int length);
int ZigbeeBuildKeyEstablishmentServerResponse(ZigbeeKeyEstablishment *zke, void *packet);

/*
 * ZigBee Over-the-Air Upgrading Cluster
 *
 * References:
 * [OTA] ZigBee Over-the-Air Upgrading Cluster, Revision 23, Version 1.1, ZigBee Document 095264r23, March 12 2014.
 * [ZSE] D.8 Over-the-Air Bootload Cluster
 */

typedef struct {
  unsigned char state;
  unsigned char endpoint;
  unsigned char seqnum;

  /* Query Next Image Response */
  unsigned char queryNextImageStatus;
  unsigned short manufacturerCode;
  unsigned short imageType;
  unsigned fileVersion;
  unsigned imageSize;

  /* Image Block Request */
  unsigned fileOffset;
  unsigned char maxDataSize;

  /* Image Block Response */
  unsigned char imageBlockStatus;
} ZigbeeOtaServer;

void ZigbeeReceiveOtaServerCommand(ZigbeeOtaServer *ota, unsigned char endpoint, const void *payload, int length);
int ZigbeeBuildOtaServerResponse(ZigbeeOtaServer *ota, void *payload);

/*
 * Implementation-specific data structures and functions.
 */

typedef struct {
  short destinationNode;
  short profileId;
  short clusterId;
  char sourceEndpoint;
  char destinationEndpoint;
  char encryption;
  char fragmentation;
  char fragmentNumber;
  char fragmentCount;
} ZigbeePacketInfo;

#endif  /* ZIGBEE_H */
