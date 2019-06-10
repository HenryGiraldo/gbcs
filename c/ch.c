/*
 * ch.c: Communications Hub
 *
 * This is free and unencumbered software released into the public domain.
 * See the UNLICENSE file or https://unlicense.org for more details.
 */

#include "ch.h"

#include "gbcs.h"

/* The number of the zigbee endpoint used by the CH.
 * We can choose any endpoint value from 0x01 to 0xFE.
 * The usual value is 1, and some GBCS devices wrongly assume that,
 * so we choose some other unusual value to check that the GBCS devices
 * use the correct endpoint value found by endpoint discovery.
 * [ZIGBEE] 2.2.5.1.2 Destination Endpoint Field.
 */
enum { CH_ZSE_ENDPOINT = 123 /* 0x7B */ };

ChDevice *ChAddDevice(CommsHub *ch, const void *address, const void *installCode) {
  int i, j;

  for (i = 0; i < sizeof(ch->devices) / sizeof(ch->devices[0]); i++) {
    ChDevice *device = &ch->devices[i];
    for (j = 0; j < 8; j++) {
      if (device->extendedAddress[j] != 0) {
        break;
      }
    }
    if (j == 8) {
      /* Initialise the ChDevice data structure. */
      for (j = 0; j < sizeof(device); j++) {
        ((char *)device)[j] = 0;
      }
      /* Set the values that would be sent by a CCS01 command. */
      for (j = 0; j < 8; j++) {
        device->extendedAddress[j] = ((char *)address)[j];
      }
      for (j = 0; j < 16; j++) {
        device->installCode[j] = ((char *)installCode)[j];
      }
      ZigbeeDerivePreconfiguredKey(device->preconfiguredKey, device->installCode);
      /* Set remaining fields that have non-zero default values. */
      device->ota.queryNextImageStatus = ZIGBEE_NOT_AUTHORIZED;
      return device;
    }
  }
  return (ChDevice *)0;
}

void ChRemoveDevice(CommsHub *ch, const void *address) {
  int i, j;

  for (i = 0; i < sizeof(ch->devices) / sizeof(ch->devices[0]); i++) {
    for (j = 0; j < 8; j++) {
      if (ch->devices[i].extendedAddress[j] != ((unsigned char *)address)[j]) {
        break;
      }
    }
    if (j == 8) {
      for (j = 0; j < 8; j++) {
        ch->devices[i].extendedAddress[j] = 0;
      }
    }
  }
}

ChDevice *ChGetDeviceByShortAddress(CommsHub *ch, int address) {
  int i;
  for (i = 0; i < sizeof(ch->devices) / sizeof(ch->devices[0]); i++) {
    if (ch->devices[i].shortAddress == address) {
      return &ch->devices[i];
    }
  }
  return (ChDevice *)0;
}

ChDevice *ChGetDeviceByGbcsEntityId(CommsHub *ch, const void *id) {
  int i, j;
  for (i = 0; i < sizeof(ch->devices) / sizeof(ch->devices[0]); i++) {
    for (j = 0; j < sizeof(ch->devices[i].extendedAddress); j++) {
      if (ch->devices[i].extendedAddress[j] != ((unsigned char *)id)[j]) {
        break;
      }
    }
    if (j == sizeof(ch->devices[i].extendedAddress)) {
      return &ch->devices[i];
    }
  }
  return (ChDevice *)0;
}

ChDevice *ChGetDeviceByZigbeeExtendedAddress(CommsHub *ch, const void *address) {
  char gbcsEntityId[8];
  for (int i = 0; i < 8; i++) {
    gbcsEntityId[i] = ((char *)address)[7 - i];
  }
  return ChGetDeviceByGbcsEntityId(ch, gbcsEntityId);
}

void ChReceiveGbcsMessage(CommsHub *ch, const void *gbcsMessage, int gbcsMessageLength) {
  int i;
  ChDevice *d = &ch->devices[0];  /* TODO */
  int head = d->gbcsMessageHead;
  int nextHead = (head + 1) & (CH_QUEUE_SIZE - 1);
  if (nextHead != d->gbcsMessageTail) {
    char *b = d->gbcsMessages[head];
    for (i = 0; i < gbcsMessageLength; i++) {
      b[i] = ((char *)gbcsMessage)[i];
    }
    d->gbcsMessageLengths[head] = gbcsMessageLength;
    d->gbcsMessageHead = nextHead;
  }
}

void ChHandleTunnelDataGet(CommsHub *ch, const void *packet, int length) {
#if 0
  ChDevice *gsme = &ch->devices[0];  /* TODO */
  if (gsme->flags & CH_GSME_TUNNEL_GET) {
    /* Already handling a TransferData GET command */
  } else {
    gsme->tunnelGetTransactionSequenceNumber = ((char *)packet)[1];
    gsme->tunnelEndpoint = 0; 
    gsme->flags |= CH_GSME_TUNNEL_GET;
  }
#endif
}

/*
 * ZSE Metering Cluster
 *
 * [ZSE] D.3 Metering Cluster
 */

enum {
  CH_MIRROR_IDLE,
  CH_MIRROR_SEND_REQUEST_MIRROR_RESPONSE,
  CH_MIRROR_SEND_CONFIGURE_MIRROR_DEFAULT_RESPONSE,
};

static void ChReceiveMeteringClientCommand(CommsHub *ch, ChDevice *device, int sourceEndpoint, const void *payload, int length) {
  const unsigned char *p = payload;
  int seqnum = p[1];
  int commandId = p[2];
  if (commandId == 1) {  /* Request Mirror */
    device->mirrorState = CH_MIRROR_SEND_REQUEST_MIRROR_RESPONSE;
    device->mirrorSeqNum = seqnum;
  } else if (commandId == 8) {  /* Configure Mirror */
    /* TODO: parse the command (see ZSE D.3.2.3.1.9 ConfigureMirror Command) */
    device->mirrorState = CH_MIRROR_SEND_CONFIGURE_MIRROR_DEFAULT_RESPONSE;
    device->mirrorSeqNum = seqnum;
  }
}

static int ChBuildMeteringClientResponse(ChDevice *device, void *packet) {
  int n = 0;
  unsigned char *p = packet;
  if (device->mirrorState == CH_MIRROR_SEND_REQUEST_MIRROR_RESPONSE) {
    device->mirrorState = CH_MIRROR_IDLE;
    p[0] = 0x11;  /* frame control (disable default response | client to server | cluster specific) */
    p[1] = device->mirrorSeqNum;
    p[2] = 1;  /* command id (request mirror response) */
    p[3] = CH_ZSE_ENDPOINT;  /* EndPoint ID (lsb) */
    p[4] = 0;  /* EndPoint ID (msb) */
    n = 5;
  } else if (device->mirrorState == CH_MIRROR_SEND_CONFIGURE_MIRROR_DEFAULT_RESPONSE) {
    device->mirrorState = CH_MIRROR_IDLE;
    p[0] = 0x10;  /* frame control (disable default response | client to server | profile wide) */
    p[1] = device->mirrorSeqNum;
    p[2] = 11;  /* command id (default response) */
    p[3] = 8;  /* response to Configure Mirror command */
    p[4] = 0;  /* status (success) */
    n = 5;
  }
  return n;
}

/*
 * ZSE Tunneling Cluster
 *
 * [ZSE] D.6 Tunneling Cluster
 */

enum {
  CH_TUNNEL_SEND_REQUEST_TUNNEL_RESPONSE = 1,
  CH_TUNNEL_SEND_DEFAULT_RESPONSE = 2,
  CH_TUNNEL_SEND_GET_RESPONSE = 4,
};

static int ChReceiveTunnelingServerCommand(ChDevice *device, int sourceEndpoint, const void *payload, int length, void *gbcsMsgBuf) {
  int retval = 0;
  const unsigned char *p = payload;
  //int frameControl = p[0];
  int seqnum = p[1];
  int commandId = p[2];
  if (commandId == 0) {  /* Request Tunnel */
    /* TODO: parse the command (see ZSE D.6.2.4.1 RequestTunnel Command) */
    device->tunnelSeqNumRx = seqnum;
    device->tunnelState = CH_TUNNEL_SEND_REQUEST_TUNNEL_RESPONSE;
  } else if (commandId == 2) {  /* Transfer Data */
    device->tunnelSeqNumRx = seqnum;
    device->tunnelState |= CH_TUNNEL_SEND_DEFAULT_RESPONSE;
    /* tunnelId = p[3] | p[4] << 8; */
    int gbcsCommand = p[5];
    if (gbcsCommand == 1) {  /* GET */
      device->tunnelState |= CH_TUNNEL_SEND_GET_RESPONSE;
    } else if (gbcsCommand == 3) {  /* PUT */
      retval = length - 6;
      for (int i = 0; i < retval; i++) {
        ((unsigned char *)gbcsMsgBuf)[i] = p[6 + i];
      }
    }
  }
  return retval;
}

static void ChReceiveTunnelingServerDefaultResponse(ChDevice *device, int seqnum, int command, int status) {
  if (command == 1) {  /* Transfer Data */
    /* TODO: check seqnum and status and remove the sent GBCS message from the queue */
    device->tunnelSeqNumTx++;
  }
}

static int ChBuildTunnelingServerResponse(ChDevice *device, void *packet) {
  int n = 0;
  unsigned char *p = packet;
  if (device->tunnelState & CH_TUNNEL_SEND_DEFAULT_RESPONSE) {
    device->tunnelState &= ~CH_TUNNEL_SEND_DEFAULT_RESPONSE;
    p[0] = 0x18;  /* frame control (disable default response | server to client | profile wide) */
    p[1] = device->tunnelSeqNumRx;
    p[2] = ZCL_DEFAULT_RESPONSE;  /* command id */
    p[3] = 2;  /* response to Transfer Data command */
    p[4] = ZIGBEE_SUCCESS;  /* status */
    n = 5;
  } else if (device->tunnelState & CH_TUNNEL_SEND_GET_RESPONSE) {
    device->tunnelState &= ~CH_TUNNEL_SEND_GET_RESPONSE;
    p[0] = 0x19;  /* frame control (disable default response | server to client | cluster specific) */
    p[1] = device->tunnelSeqNumTx;
    p[2] = 1;  /* command id (Transfer Data) */
    p[3] = 0;  /* tunnel id (lsb) */
    p[4] = 0;  /* tunnel id (msb) */
    p[5] = 2;  /* GET-RESPONSE */
    p[6] = 0;  /* Number of remaining messages */
    n = 7;
  } else if (device->tunnelState & CH_TUNNEL_SEND_REQUEST_TUNNEL_RESPONSE) {
    device->tunnelState &= ~CH_TUNNEL_SEND_REQUEST_TUNNEL_RESPONSE;
    p[0] = 0x19;  /* frame control (disable default response | server to client | cluster specific) */
    p[1] = device->tunnelSeqNumRx;
    p[2] = 0;  /* command id (Request Tunnel Response) */
    p[3] = 0;  /* tunnel id (lsb) */
    p[4] = 0;  /* tunnel id (msb) */
    p[5] = 0;  /* tunnel status (success) */
    p[6] = 1500 & 255;  /* maximum incoming transfer size (lsb) */
    p[7] = 1500 >> 8;  /* maximum incoming transfer size (msb) */
    n = 8;
  }
  return n;
}

/*
 * ZSE = Zigbee Smart Energy
 *
 * [ZCL] 2.3.1 General ZCL Frame Format
 */
static int ChReceiveZseFrame(CommsHub *ch, ChDevice *device, int encryption, int clusterId, int sourceEndpoint, const void *payload, int length, void *gbcsMsgBuf) {
  int retval = 0;
  const unsigned char *p = payload;

  /* ZCL header */
  int frameControl = p[0];
  if ((frameControl & 4) == 0) {  /* not manufacturer specific */
    int seqnum = p[1];
    int commandId = p[2];
    const void *zclPayload = p + 3;
    int zclPayloadLength = length - 3;

    int frameType = frameControl & 3;
    if (frameType == 1) {  /* cluster specific command */
      if (clusterId == ZIGBEE_METERING_CLUSTER_ID) {
        ChReceiveMeteringClientCommand(ch, device, sourceEndpoint, payload, length);
      } else if (clusterId == ZIGBEE_TUNNELING_CLUSTER_ID) {
        retval = ChReceiveTunnelingServerCommand(device, sourceEndpoint, payload, length, gbcsMsgBuf);
      } else if (clusterId == ZIGBEE_KEY_ESTABLISHMENT_CLUSTER_ID) {
        ZigbeeReceiveKeyEstablishmentServerCommand(&ch->zke, device->shortAddress, sourceEndpoint, payload, length);
      } else if (clusterId == ZIGBEE_OTA_CLUSTER_ID) {
        ZigbeeReceiveOtaServerCommand(&device->ota, sourceEndpoint, payload, length);
      }
    } else if (frameType == 0) {  /* profile wide command */
      if (commandId == ZCL_DEFAULT_RESPONSE) {
        int command = p[3];
        int status = p[4];
        if (clusterId == ZIGBEE_TUNNELING_CLUSTER_ID) {
          ChReceiveTunnelingServerDefaultResponse(device, seqnum, command, status);
        }
      } else if (commandId == ZCL_READ_ATTRIBUTES) {
        ZigbeeParseReadAttributes(&device->readAttributes, clusterId, zclPayload, zclPayloadLength);
        device->readAttributes.endpoint = sourceEndpoint;
        device->readAttributes.encryption = encryption;
        device->sequenceNumber = seqnum;
        device->flags |= CH_READ_ATTRIBUTES;
      } else if (commandId == ZCL_REPORT_ATTRIBUTES) {
        device->sequenceNumber = seqnum;
        device->flags |= CH_READ_ATTRIBUTES;
      }
    }
  }
  return retval;
}

/*
 * ZDO = Zigbee Device Object
 */
static void ChReceiveZdoFrame(CommsHub *ch, ChDevice *device, ZigbeeZdoClusterId clusterId, const void *payload, int length) {
  if (clusterId == ZIGBEE_MATCH_DESC_REQ) {
    ZigbeeMatchDescReq req;
    if (ZigbeeParseMatchDescReq(&req, payload, length)) {
      device->sequenceNumber = req.sequenceNumber;
      device->flags |= CH_MATCH_DESC;
    }
  }
}

int ChReceiveZigbeeApsFrame(CommsHub *ch, ChDevice *device, int encryption, int profileId, int clusterId, int sourceEndpoint, int destinationEndpoint, const void *payload, int length, void *gbcsMsgBuf) {
  int retval = 0;
  if (profileId == ZIGBEE_SMART_ENERGY_PROFILE_ID && destinationEndpoint == CH_ZSE_ENDPOINT) {
    retval = ChReceiveZseFrame(ch, device, encryption, clusterId, sourceEndpoint, payload, length, gbcsMsgBuf);
  } else if (profileId == ZIGBEE_DEVICE_PROFILE_ID && destinationEndpoint == ZIGBEE_ZDO_ENDPOINT && sourceEndpoint == ZIGBEE_ZDO_ENDPOINT) {
    ChReceiveZdoFrame(ch, device, clusterId, payload, length);
  }
  return retval;
}

/* Zigbee responses */

/*
 * Builds a Read Attributes Status Record for the Basic cluster.
 *
 * "The Basic Cluster Physical Environment attribute shall, contrary to ZSE,
 * be supported and shall have the value 0x01." Reference:
 * GBCS 10.2.2 Requirements for the Tunneling Cluster.
 */
static int ChBuildReadAttributesRecordBasic(void *record, int attributeId) {
  switch (attributeId) {
  case ZCL_PHYSICAL_ENVIRONMENT:
    return ZigbeeBuildAttributeRecordEnum8(record, attributeId, 0x01);
  default:
    return 0;
  }
}

/*
 * Builds a Read Attributes Status Record for the Time cluster.
 *
 * References:
 * - GBCS 9.1.3 Device Requirements relating to the ZCL Time Cluster and its usage.
 */
static int ChBuildReadAttributesRecordTime(void *record, int attributeId) {
  switch (attributeId) {
  case ZCL_TIME:
    return ZigbeeBuildAttributeRecordUtcTime(record, attributeId, ZigbeeGetCurrentUtcTime());
  case ZCL_TIME_STATUS:
    return ZigbeeBuildAttributeRecordBitmap8(record, attributeId, 9);  /* Superseeding | Master */
  default:
    return 0;
  }
}

/*
 * Builds a Read Attributes Status Record for the Metering cluster.
 * Reference: ZSE D.3.3.2 Attributes.
 */
static int ChBuildReadAttributesRecordMetering(ChDevice *device, void *record, int attributeId) {
  if (attributeId == ZSE_FUNCTIONAL_NOTIFICATION_FLAGS) {
    unsigned flags = 0;
    if (device->ota.queryNextImageStatus == ZIGBEE_SUCCESS) {
      flags |= 1;  /* New OTA Firmware */
    }
    return ZigbeeBuildAttributeRecordBitmap32(record, attributeId, flags);
  }
  return 0;
}

/*
 * Builds a Read Attributes Status Record for the Price cluster.
 */
static int ChBuildReadAttributesRecordPrice(void *record, int attributeId) {
  switch (attributeId) {
  case ZSE_COMMODITY_TYPE:
    return ZigbeeBuildAttributeRecordEnum8(record, attributeId, 1);  /* gas metering */
  default:
    return 0;
  }
}

/*
 * Builds a Read Attributes Status Record for the Key Establishment cluster.
 */
static int ChBuildReadAttributesRecordKeyEstablishment(void *record, int attributeId) {
  switch (attributeId) {
  case ZSE_KEY_ESTABLISHMENT_SUITE:
    return ZigbeeBuildAttributeRecordEnum16(record, attributeId, 2);
  default:
    return 0;
  }
}

static int ChBuildReadAttributesResponse(ChDevice *device, void *payload, ZigbeePacketInfo *info) {
  unsigned char *p = payload;

  info->destinationNode = device->shortAddress;
  info->profileId = ZIGBEE_SMART_ENERGY_PROFILE_ID;
  info->clusterId = device->readAttributes.clusterId;
  info->sourceEndpoint = CH_ZSE_ENDPOINT;
  info->destinationEndpoint = device->readAttributes.endpoint;
  info->encryption = device->readAttributes.encryption;
  info->fragmentation = 0;

  p[0] = 0x18;  /* frame control (disable default response | server to client) */
  p[1] = device->sequenceNumber;
  p[2] = ZCL_READ_ATTRIBUTES_RESPONSE;  /* command id */
  int n = 3;
  int clusterId = device->readAttributes.clusterId;
  for (int i = 0; i < sizeof(device->readAttributes.attributeIds) / sizeof(device->readAttributes.attributeIds[0]); i++) {
    int attributeId = device->readAttributes.attributeIds[i];
    if (attributeId == 0xFFFF) {
      break;
    }
    int m = 0;
    if (clusterId == ZIGBEE_BASIC_CLUSTER_ID) {
      m = ChBuildReadAttributesRecordBasic(p + n, attributeId);
    } else if (clusterId == ZIGBEE_TIME_CLUSTER_ID) {
      m = ChBuildReadAttributesRecordTime(p + n, attributeId);
    } else if (clusterId == ZIGBEE_METERING_CLUSTER_ID) {
      m = ChBuildReadAttributesRecordMetering(device, p + n, attributeId);
    } else if (clusterId == ZIGBEE_PRICE_CLUSTER_ID) {
      m = ChBuildReadAttributesRecordPrice(p + n, attributeId);
    } else if (clusterId == ZIGBEE_KEY_ESTABLISHMENT_CLUSTER_ID) {
      m = ChBuildReadAttributesRecordKeyEstablishment(p + n, attributeId);
    }
    if (m == 0) {
      m = ZigbeeBuildAttributeRecordStatus(p + n, attributeId, ZIGBEE_UNSUPPORTED_ATTRIBUTE);
    }
    n += m;
  }

  return n;
}

int ChGetZigbeePacketToSend(CommsHub *ch, void *packet, ZigbeePacketInfo *info) {
  int bytes = 0;
  ChDevice *gsme = &ch->devices[0];  /* TODO */
  if (gsme->flags & CH_ZIGBEE_SENDING) {

  } else if (gsme->flags & CH_GSME_TUNNEL_SENDING) {
    /* Currently sending tunnel data */
  } else if (gsme->flags & CH_GSME_TUNNEL_GET) {
    gsme->flags |= CH_GSME_TUNNEL_SENDING;
    if (gsme->tunnelFragmentNext == 0) {
      info->destinationNode = gsme->shortAddress;
      info->profileId = ZIGBEE_SMART_ENERGY_PROFILE_ID;
      info->clusterId = ZIGBEE_TUNNELING_CLUSTER_ID;
      info->sourceEndpoint = CH_ZSE_ENDPOINT;
      info->destinationEndpoint = gsme->tunnelEndpoint;
      info->encryption = 1;
      info->fragmentation = 1;
      info->fragmentNumber = 0;
      info->fragmentCount = 2;
      unsigned char *p = (unsigned char *)packet;
      p[0] = 0x91;
      p[1] = gsme->tunnelGetTransactionSequenceNumber;
      p[2] = 1;  /* command id (transfer data) */
      p[3] = 0;  /* tunnel id (lsb) */
      p[4] = 0;  /* tunnel id (msb) */
      p[5] = 2;  /* transfer data command (GET-RESPONSE) */
      if (gsme->gbcsMessageHead != gsme->gbcsMessageTail) {
        int tail = gsme->gbcsMessageTail;
        int length = gsme->gbcsMessageLengths[tail];
        p[6] = (gsme->gbcsMessageHead - tail + 1) & (CH_QUEUE_SIZE - 1);  /* remaining messages */
        int totalLength = 7 + length;
        int transferDataLength = totalLength;
        if (transferDataLength > GBCS_ZIGBEE_FRAGMENT_DATA_MAX_SIZE) {
          transferDataLength = GBCS_ZIGBEE_FRAGMENT_DATA_MAX_SIZE;
        }
        for (int i = 0; i < transferDataLength - 7; i++) {
          p[7 + i] = gsme->gbcsMessages[tail][i];
        }
        bytes = transferDataLength;
      } else {
        p[6] = 0;  /* remaining messages */
        bytes = 7;
      }
    }
  } else if (gsme->flags & CH_READ_ATTRIBUTES) {
    gsme->flags &= ~CH_READ_ATTRIBUTES;
    bytes = ChBuildReadAttributesResponse(gsme, packet, info);
  } else if (gsme->flags & CH_MATCH_DESC) {
    char *p = packet;
    p[0] = gsme->sequenceNumber;
    p[1] = 0;  /* status (success) */
    p[2] = 0;  /* nwkAddress (lsb) */
    p[3] = 0;  /* nwkAddress (msb) */
    p[4] = 1;  /* match length */
    p[5] = CH_ZSE_ENDPOINT;  /* match list */
    bytes = 6;
    info->destinationNode = gsme->shortAddress;
    info->profileId = ZIGBEE_DEVICE_PROFILE_ID;
    info->clusterId = ZIGBEE_MATCH_DESC_RSP;
    info->sourceEndpoint = ZIGBEE_ZDO_ENDPOINT;
    info->destinationEndpoint = ZIGBEE_ZDO_ENDPOINT;
    info->encryption = 0;
    info->fragmentation = 0;
    gsme->flags &= ~CH_MATCH_DESC;
  } else {
    info->destinationNode = gsme->shortAddress;
    info->profileId = ZIGBEE_SMART_ENERGY_PROFILE_ID;
    info->clusterId = ZIGBEE_METERING_CLUSTER_ID;
    info->sourceEndpoint = CH_ZSE_ENDPOINT;
    info->destinationEndpoint = 1;  /* FIXME: hardcoded */
    info->encryption = 1;
    info->fragmentation = 0;
    bytes = ChBuildMeteringClientResponse(gsme, packet);
    if (!bytes) {
      info->destinationNode = gsme->shortAddress;
      info->profileId = ZIGBEE_SMART_ENERGY_PROFILE_ID;
      info->clusterId = ZIGBEE_TUNNELING_CLUSTER_ID;
      info->sourceEndpoint = CH_ZSE_ENDPOINT;
      info->destinationEndpoint = 1;  /* FIXME: hardcoded */
      info->encryption = 1;
      info->fragmentation = 0;
      bytes = ChBuildTunnelingServerResponse(gsme, packet);
      if (!bytes) {
        info->destinationNode = gsme->shortAddress;
        info->profileId = ZIGBEE_SMART_ENERGY_PROFILE_ID;
        info->clusterId = ZIGBEE_KEY_ESTABLISHMENT_CLUSTER_ID;
        info->sourceEndpoint = CH_ZSE_ENDPOINT;
        info->destinationEndpoint = 1;  /* FIXME: hardcoded */
        info->encryption = 0;
        info->fragmentation = 0;
        bytes = ZigbeeBuildKeyEstablishmentServerResponse(&ch->zke, packet);
        if (!bytes) {
          info->destinationNode = gsme->shortAddress;
          info->profileId = ZIGBEE_SMART_ENERGY_PROFILE_ID;
          info->clusterId = ZIGBEE_OTA_CLUSTER_ID;
          info->sourceEndpoint = CH_ZSE_ENDPOINT;
          info->destinationEndpoint = gsme->ota.endpoint;
          info->encryption = 1;
          info->fragmentation = 0;
          bytes = ZigbeeBuildOtaServerResponse(&gsme->ota, packet);
        }
      }
    }
  }
  if (bytes) {
    gsme->flags |= CH_ZIGBEE_SENDING;
  }
  return bytes;
}

void ChZigbeeFrameSent(CommsHub *ch, int destination, int counter, int error) {
  ChDevice *device = ChGetDeviceByShortAddress(ch, destination);
  if (device) {
    device->apsCounter = counter;
    device->flags &= ~CH_ZIGBEE_SENDING;
  }
}
