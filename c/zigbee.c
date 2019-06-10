/*
 * zigbee.c: zigbee protocol, zigbee cluster library and zigbee smart energy
 *
 * This is free and unencumbered software released into the public domain.
 * See the UNLICENSE file or https://unlicense.org for more details.
 */

#include "zigbee.h"

#include "crypto.h"

/* ZDO commands */

int ZigbeeParseMatchDescReq(ZigbeeMatchDescReq *req, const void *payload, int length) {
  int success = 0;
  if (length > 8) {
    req->sequenceNumber = ((unsigned char *)payload)[0];
    req->nwkAddr = ((unsigned char *)payload)[1] | ((unsigned char *)payload)[2] << 8;
    req->profileId = ((unsigned char *)payload)[3] | ((unsigned char *)payload)[4] << 8;
    int numInClusters = ((unsigned char *)payload)[5];
    if (numInClusters > 0) {
      req->clusterId = ((unsigned char *)payload)[6] | ((unsigned char *)payload)[7] << 8;
      success = 1;
    }
  }
  return success;
}

/* ZCL commands */

void ZigbeeParseReadAttributes(ZclReadAttributes *attr, int clusterId, const void *payload, int length) {
  int i;
  attr->clusterId = clusterId;
  for (i = 0; i < length / 2 && i < sizeof(attr->attributeIds) / sizeof(attr->attributeIds[0]); i++) {
    attr->attributeIds[i] = ((unsigned char *)payload)[i * 2] | ((unsigned char *)payload)[i * 2 + 1] << 8;
  }
  for ( ; i < sizeof(attr->attributeIds) / sizeof(attr->attributeIds[0]); i++) {
    attr->attributeIds[i] = 0xFFFF;
  }
}

int ZigbeeBuildAttributeRecordStatus(void *record, int attributeId, int status) {
  unsigned char *p = record;
  p[0] = attributeId;
  p[1] = attributeId >> 8;
  p[2] = status;
  return 3;
}

int ZigbeeBuildAttributeRecordBitmap8(void *record, int attributeId, int value) {
  unsigned char *p = record;
  p[0] = attributeId;
  p[1] = attributeId >> 8;
  p[2] = ZIGBEE_SUCCESS;
  p[3] = ZIGBEE_BITMAP8;
  p[4] = value;
  return 5;
}

int ZigbeeBuildAttributeRecordBitmap32(void *record, int attributeId, int value) {
  unsigned char *p = record;
  p[0] = attributeId;
  p[1] = attributeId >> 8;
  p[2] = ZIGBEE_SUCCESS;
  p[3] = ZIGBEE_BITMAP32;
  p[4] = value;
  p[5] = value >> 8;
  p[6] = value >> 16;
  p[7] = value >> 24;
  return 8;
}


int ZigbeeBuildAttributeRecordEnum8(void *record, int attributeId, int value) {
  unsigned char *p = record;
  p[0] = attributeId;
  p[1] = attributeId >> 8;
  p[2] = ZIGBEE_SUCCESS;
  p[3] = ZIGBEE_ENUM8;
  p[4] = value;
  return 5;
}

int ZigbeeBuildAttributeRecordEnum16(void *record, int attributeId, int value) {
  unsigned char *p = record;
  p[0] = attributeId;
  p[1] = attributeId >> 8;
  p[2] = ZIGBEE_SUCCESS;
  p[3] = ZIGBEE_ENUM16;
  p[4] = value;
  p[5] = value >> 8;
  return 6;
}

int ZigbeeBuildAttributeRecordUtcTime(void *record, int attributeId, int value) {
  unsigned char *p = record;
  p[0] = attributeId;
  p[1] = attributeId >> 8;
  p[2] = ZIGBEE_SUCCESS;
  p[3] = ZIGBEE_UTCTIME;
  p[4] = value;
  p[5] = value >> 8;
  p[6] = value >> 16;
  p[7] = value >> 24;
  return 8;
}

/*
 * ZSE Key Establishment Cluster
 *
 * [ZSE] Annex C Key Establishment Cluster
 */

void ZigbeeReceiveKeyEstablishmentServerCommand(ZigbeeKeyEstablishment *zke, int sourceAddress, int sourceEndpoint, const void *messageContents, int length) {
  int i;
  const unsigned char *p = messageContents;
  int seqnum = p[1];
  int commandId = p[2];
  if (commandId == 0) {  /* Initiate Key Establishment Request */
    if (zke->state == ZIGBEE_WAIT_INITIATE_KEY_ESTABLISHMENT_REQUEST) {
      if (length >= 3 + 4 + ZIGBEE_CBKE_SUITE2_CERT_SIZE) {
        for (i = 0; i < ZIGBEE_CBKE_SUITE2_CERT_SIZE; i++) {
          zke->partnerCertificate[i] = p[7 + i];
        }
        zke->state = ZIGBEE_SEND_INITIATE_KEY_ESTABLISHMENT_RESPONSE;
        zke->seqnum = seqnum;
      }
    }
  } else if (commandId == 1) {  /* Ephemeral Data Request */
    if (zke->state == ZIGBEE_WAIT_EPHEMERAL_DATA_REQUEST) {
      if (length >= 3 + ZIGBEE_CBKE_SUITE2_QE_SIZE) {
        for (i = 0; i < ZIGBEE_CBKE_SUITE2_QE_SIZE; i++) {
          zke->partnerEphemeralPublicKey[i] = p[3 + i];
        }
        zke->state = ZIGBEE_GENERATE_EPHEMERAL_DATA;
        zke->seqnum = seqnum;
      }
    }
  } else if (commandId == 2) {  /* Confirm Key Data Request */
    if (zke->state == ZIGBEE_WAIT_CONFIRM_KEY_DATA_REQUEST) {
      if (length >= 3 + ZIGBEE_CBKE_SUITE2_MAC_SIZE) {
        for (i = 0; i < ZIGBEE_CBKE_SUITE2_MAC_SIZE; i++) {
          zke->partnerMac[i] = p[3 + i];
        }
        zke->state = ZIGBEE_CALCULATE_SMAC;
        zke->seqnum = seqnum;
      }
    }
  } else {  /* (commandId == 3)  Terminate Key Establishment */
    zke->state = ZIGBEE_WAIT_INITIATE_KEY_ESTABLISHMENT_REQUEST;
  }
}

int ZigbeeBuildKeyEstablishmentServerResponse(ZigbeeKeyEstablishment *zke, void *packet) {
  int i;
  int n = 0;
  unsigned char *p = packet;
  switch (zke->state) {
  case ZIGBEE_SEND_INITIATE_KEY_ESTABLISHMENT_RESPONSE:
    p[n++] = 0x09;  /* frame control */
    p[n++] = zke->seqnum;
    p[n++] = 0;  /* command id (Initiate Key Establishment Response) */
    /* Requested Key Establishment Suite (Crypto Suite 2) */
    p[n++] = 0x02;
    p[n++] = 0x00;
    p[n++] = 10;  /* Ephemeral Data Generate Time */
    p[n++] = 10;  /* Confirm Key Generate Time */
    for (i = 0; i < ZIGBEE_CBKE_SUITE2_CERT_SIZE; i++) {
      p[n++] = zke->myCertificate[i];
    }
    zke->state = ZIGBEE_WAIT_EPHEMERAL_DATA_REQUEST;
    break;
  case ZIGBEE_SEND_EPHEMERAL_DATA_RESPONSE:
    p[n++] = 0x09;  /* frame control */
    p[n++] = zke->seqnum;
    p[n++] = 1;  /* command id (Ephemeral Data Response) */
    for (i = 0; i < ZIGBEE_CBKE_SUITE2_QE_SIZE; i++) {
      p[n++] = zke->myEphemeralPublicKey[i];  /* Ephemeral Data QEV */
    }
    zke->state = ZIGBEE_WAIT_CONFIRM_KEY_DATA_REQUEST;
    break;
  case ZIGBEE_SEND_CONFIRM_KEY_DATA_RESPONSE:
    p[n++] = 0x09;  /* frame control */
    p[n++] = zke->seqnum;
    p[n++] = 2;  /* command id (Confirm Key Response) */
    for (i = 0; i < ZIGBEE_CBKE_SUITE2_MAC_SIZE; i++) {
      p[n++] = zke->responderMac[i];  /* MAC V */
    }
    zke->state = ZIGBEE_STORE_LINK_KEY;
    break;
  case ZIGBEE_SEND_TERMINATE_KEY_ESTABLISHMENT:
    p[n++] = 0x09;  /* frame control */
    p[n++] = zke->seqnum;
    p[n++] = 3;  /* command id (Terminate Key Establishment) */
    p[n++] = 4;  /* status (NO_RESOURCES) */
    p[n++] = 30;  /* wait time (seconds) */
    p[n++] = 2;  /* key establishment suite (lsb) */
    p[n++] = 0;  /* key establishment suite (msb) */
    zke->state = ZIGBEE_WAIT_INITIATE_KEY_ESTABLISHMENT_REQUEST;
  }
  return n;
}

/*
 * ZigBee Over-the-Air Upgrading Cluster
 *
 * References:
 * [OTA] ZigBee Over-the-Air Upgrading Cluster, Revision 23, Version 1.1, ZigBee Document 095264r23, March 12 2014.
 * [ZSE] D.8 Over-the-Air Bootload Cluster
 */

enum {
  ZIGBEE_OTA_IDLE,
  ZIGBEE_OTA_SEND_QUERY_NEXT_IMAGE_RESPONSE,
  ZIGBEE_OTA_SEND_IMAGE_BLOCK_RESPONSE,
  ZIGBEE_OTA_SEND_UPGRADE_END_RESPONSE,
};

/*
 * [OTA] 6.10.4 Query Next Image Request Command
 */
static void ZigbeeReceiveOtaQueryNextImageRequest(ZigbeeOtaServer *ota, const void *payload, int length) {
  /* TODO: validate the payload */
  ota->state = ZIGBEE_OTA_SEND_QUERY_NEXT_IMAGE_RESPONSE;
}

/*
 * [OTA] 6.10.5 Query Next Image Response Command
 */
static int ZigbeeBuildOtaQueryNextImageResponse(ZigbeeOtaServer *ota, void *payload) {
  unsigned char *p = payload;
  p[0] = 0x19;  /* frame control (disable default response, server to client, cluster specific) */
  p[1] = ota->seqnum;
  p[2] = 2;  /* command id (Query Next Image Response) */
  p[3] = ota->queryNextImageStatus;
  ota->state = ZIGBEE_OTA_IDLE;
  if (ota->queryNextImageStatus == ZIGBEE_SUCCESS) {
    p[4] = ota->manufacturerCode & 0xFF;
    p[5] = ota->manufacturerCode >> 8;
    p[6] = ota->imageType & 0xFF;
    p[7] = ota->imageType >> 8;
    p[8] = ota->fileVersion;
    p[9] = ota->fileVersion >> 8;
    p[10] = ota->fileVersion >> 16;
    p[11] = ota->fileVersion >> 24;
    p[12] = ota->imageSize;
    p[13] = ota->imageSize >> 8;
    p[14] = ota->imageSize >> 16;
    p[15] = ota->imageSize >> 24;
    return 16;
  }
  return 4;
}

/*
 * [OTA] 6.10.6 Image Block Request Command
 */
static void ZigbeeReceiveOtaImageBlockRequest(ZigbeeOtaServer *ota, const void *payload, int length) {
  /* TODO: validate the payload */
  if (length >= 3 + 14) {
    const unsigned char *p = payload;
    ota->fileOffset = p[12] | p[13] << 8 | p[14] << 16 | p[15] << 24;
    ota->maxDataSize = p[16];
    ota->state = ZIGBEE_OTA_SEND_IMAGE_BLOCK_RESPONSE;
  }
}

/*
 * [OTA] 6.10.8 Image Block Response Command
 */
static int ZigbeeBuildOtaImageBlockResponse(ZigbeeOtaServer *ota, void *payload, const void *imageData, unsigned char dataSize) {
  unsigned char i;
  unsigned char *p = payload;
  p[0] = 0x19;  /* frame control (disable default response, server to client, cluster specific) */
  p[1] = ota->seqnum;
  p[2] = 2;  /* command id (Query Next Image Response) */
  p[3] = ota->imageBlockStatus;
  ota->state = ZIGBEE_OTA_IDLE;
  if (ota->imageBlockStatus == ZIGBEE_SUCCESS) {
    p[4] = ota->manufacturerCode & 0xFF;
    p[5] = ota->manufacturerCode >> 8;
    p[6] = ota->imageType & 0xFF;
    p[7] = ota->imageType >> 8;
    p[8] = ota->fileVersion;
    p[9] = ota->fileVersion >> 8;
    p[10] = ota->fileVersion >> 16;
    p[11] = ota->fileVersion >> 24;
    p[12] = ota->fileOffset;
    p[13] = ota->fileOffset >> 8;
    p[14] = ota->fileOffset >> 16;
    p[15] = ota->fileOffset >> 24;
    p[16] = dataSize;
    for (i = 0; i < dataSize; i++) {
      p[17 + i] = ((unsigned char *)imageData)[i];
    }
    return 17 + dataSize;
  }
  return 4;
}

/*
 * [OTA] 6.10.9 Upgrade End Request Command
 */
static void ZigbeeReceiveOtaUpgradeEndRequest(ZigbeeOtaServer *ota, const void *payload, int length) {
  /* TODO: validate the payload */
  if (length >= 3 + 9) {
    const unsigned char *p = payload;
    unsigned char status = p[3];
    if (status == ZIGBEE_SUCCESS) {
      ota->queryNextImageStatus = ZIGBEE_NO_IMAGE_AVAILABLE;
      /* TODO: clear firwmware notification flag for GPF */
      /* TODO: update GUI */
    }
    ota->state = ZIGBEE_OTA_SEND_UPGRADE_END_RESPONSE;
  }
}

/*
 * [OTA] 6.10.10 Upgrade End Response Command
 */
static int ZigbeeBuildOtaUpgradeEndResponse(ZigbeeOtaServer *ota, void *payload) {
  unsigned char *p = payload;
  p[0] = 0x19;  /* frame control (disable default response, server to client, cluster specific) */
  p[1] = ota->seqnum;
  p[2] = 2;  /* command id (Query Next Image Response) */
  /* Manufacturer code (wildcard) */
  p[3] = 0xff;
  p[4] = 0xff;
  /* Image type (wildcard) */
  p[5] = 0xff;
  p[6] = 0xff;
  /* File version (wildcard) */
  p[7] = 0xff;
  p[8] = 0xff;
  p[9] = 0xff;
  p[10] = 0xff;
  /* Current time (wildcard) */
  p[11] = 0xff;
  p[12] = 0xff;
  p[13] = 0xff;
  p[14] = 0xff;
  /* Upgrade time (wildcard) - see GBCS 11.2.1 Transport of firmware images */
  p[15] = 0xff;
  p[16] = 0xff;
  p[17] = 0xff;
  p[18] = 0xff;
  return 19;
}

void ZigbeeReceiveOtaServerCommand(ZigbeeOtaServer *ota, unsigned char endpoint, const void *payload, int length) {
  const unsigned char *p = payload;
  if (length > 2) {
    unsigned char command = p[2];
    ota->endpoint = endpoint;
    ota->seqnum = p[1];
    if (command == 1) {
      ZigbeeReceiveOtaQueryNextImageRequest(ota, payload, length);
    } else if (command == 3) {
      ZigbeeReceiveOtaImageBlockRequest(ota, payload, length);
    } else if (command == 6) {
      ZigbeeReceiveOtaUpgradeEndRequest(ota, payload, length);
    }
  }
}

int ZigbeeBuildOtaServerResponse(ZigbeeOtaServer *ota, void *payload) {
  if (ota->state == ZIGBEE_OTA_SEND_QUERY_NEXT_IMAGE_RESPONSE) {
    return ZigbeeBuildOtaQueryNextImageResponse(ota, payload);
  } else if (ota->state == ZIGBEE_OTA_SEND_UPGRADE_END_RESPONSE) {
    return ZigbeeBuildOtaUpgradeEndResponse(ota, payload);
  }
  return 0;
}

/*
 * Calculates the CRC of an Installation Code.
 * installCode: pointer to the 16 bytes (128 bits) with the installation code.
 * Returns the 16-bit CRC.
 *
 * Notes about the CRC algorithm in ZSE 5.4.8.1.1.1 CRC Algorithm Information
 * which maybe could have been better explained.
 *   Length: 16 
 *   Polynomial: x16 + x12 + x5 + 1 (0x1021)
 *   Initialization method: Direct
 *   Initialization value: 0xFFFF
 *   Final XOR value: 0xFFFF
 *   Reflected In: True
 *   Reflected Out: True
 * These mean that the implementation should be something like this:
 *   int crc = 0xFFFF;
 *   for (int i = 0; i < 8; i++) {
 *     int b = crc ^ (byte >> i);
 *     crc = crc >> 1;
 *     if (b & 1) {
 *       crc = crc ^ 0x8408;
 *     }
 *   }
 *   crc = crc ^ 0xFFFF;
 * Unrolling the for(;;) loop, using the notation
 *   xi := bit i of the input byte,
 *   yi := bit i of the old 16-bit CRC value,
 *   zi := bit i of the new 16-bit CRC value,
 * we get:
 *   zf = x7^y7 ^ x3^y3
 *   ze = x6^y6 ^ x2^y2
 *   zd = x5^y5 ^ x1^y1
 *   zc = x4^y4 ^ x0^y0
 *   zb = x3^y3
 *   za = x2^y2 ^ x7^y7 ^ x3^y3
 *   z9 = x1^y1 ^ x6^y6 ^ x2^y2
 *   z8 = x0^y0 ^ x5^y5 ^ x1^y1
 *   z7 =         x4^y4 ^ x0^y0
 *   z6 =         x3^y3                 ^ yf
 *   z5 =         x2^y2                 ^ ye
 *   z4 =         x1^y1                 ^ yd
 *   z3 =         x0^y0 ^ x7^y7 ^ x3^y3 ^ yc
 *   z2 =               ^ x6^y6 ^ x2^y2 ^ yb
 *   z1 =               ^ x5^y5 ^ x1^y1 ^ ya
 *   z0 =               ^ x4^y4 ^ x0^y0 ^ y9
 * which is what is implemented in this function.
 *
 * References:
 * - ZSE 5.4.8.1.1.1 CRC Algorithm Information
 * - CRC https://www.itu.int/rec/T-REC-V.41/en
 */
static int ZigbeeCalculateInstallCodeCrc(const void *installCode) {
  int i;
  int crc = 0xFFFF;
  for (i = 0; i < 16; i++) {
    int x = ((unsigned char *)installCode)[i];
    int w = x ^ crc;
    w = (w ^ (w << 4)) & 0xFF;
    crc = (crc >> 8) ^ (w << 8) ^ (w << 3) ^ (w >> 4);
  }
  crc = crc ^ 0xFFFF;
  return crc;
}

/*
 * Derives the Pre-Configured Key of an Installation Code.
 * preconfiguredKey: pointer to 16 bytes (128 bits) to store the derived preconfigured key.
 * installCode: pointer to the 16 bytes (128 bits) with the installation code.
 *
 * References:
 * - ZSE 5.4.8.1.1 Installation Code Format
 * - ZSE 5.4.8.1.2 Hashing Function
 */
void ZigbeeDerivePreconfiguredKey(void *preconfiguredKey, const void *installCode) {
  int i;
  int crc;
  unsigned char installCodeCrc[16 + 2];

  for (i = 0; i < 16; i++) {
    installCodeCrc[i] = ((unsigned char *)installCode)[i];
  }
  crc = ZigbeeCalculateInstallCodeCrc(installCode);
  installCodeCrc[16] = crc;
  installCodeCrc[17] = crc >> 8;

  CryptoAesMmo(preconfiguredKey, installCodeCrc, sizeof(installCodeCrc));
}
