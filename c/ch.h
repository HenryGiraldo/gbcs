/*
 * ch.h: Communications Hub
 *
 * This is free and unencumbered software released into the public domain.
 * See the UNLICENSE file or https://unlicense.org for more details.
 */

#include "zigbee.h"

/* Maximum number of devices allowed to join this CH. */
enum { CH_MAX_DEVICES = 16 };

/* The maximum number of GBCS messages that can in queue for a GSME. */
enum { CH_QUEUE_SIZE = 32 };  /* must be a power of two */

typedef struct {
  unsigned char x[8];
} GbcsEntityId;

typedef struct {
  unsigned short shortAddress;
  unsigned char extendedAddress[8];
  unsigned char installCode[16];
  unsigned char preconfiguredKey[16];
  unsigned char cbkeKey[16];

  /* Zigbee packet fragmentation (transmission) */
  unsigned char apsCounter;
  char fragTxIndex;
  char fragTxCount;

  /* Zigbee packet fragmentation (reception) */
  char fragBuffer[1201];
  short fragLength;
  char fragIndex;  /* index of the next fragment to receive */
  char fragCount;  /* total number of fragments */

  /* GSME */
  enum {
    CH_FRAGMENT_ACK = 1,
    CH_READ_ATTRIBUTES = 2,
    CH_MATCH_DESC = 4,
    CH_GSME_TUNNEL_GET = 8,  /* received a GET tunnel data command */
    CH_GSME_TUNNEL_SENDING = 16,  /* currently sending data */
    CH_ZIGBEE_SENDING = 32,
    CH_SEND_MIRROR_REPORT_ATTRIBUTE_RESPONSE = 64,
  } flags;
  unsigned char tunnelGetTransactionSequenceNumber;
  unsigned char tunnelFragmentNext;
  unsigned char tunnelEndpoint;

  unsigned char sequenceNumber;
  unsigned char destinationEndpoint;

  ZclReadAttributes readAttributes;

  char gbcsMessages[CH_QUEUE_SIZE][1200];
  short gbcsMessageLengths[CH_QUEUE_SIZE];
  char gbcsMessageHead;
  char gbcsMessageTail;

  char fragmentationData[16];  /* EzspApsFrame */

  /* Metering Client */
  unsigned char mirrorState;
  unsigned char mirrorSeqNum;
  unsigned char mirrorEndpoint;

  /* Zigbee Smart Energy Tunneling Cluster (Server) */
  unsigned char tunnelState;
  unsigned char tunnelSeqNumRx;
  unsigned char tunnelSeqNumTx;

  /* ZigBee Over-the-Air Upgrading Cluster */
  ZigbeeOtaServer ota;
  char imageFile[128];

} ChDevice;

typedef struct {
  ChDevice devices[CH_MAX_DEVICES];
  ZigbeeKeyEstablishment zke;
  char status;  /* 0 = down, 1 = up */
  char channel;  /* 11 to 26 */
  char panId[2];
  /* char extendedPanId[8]; */  /* same as gpfId */
  char gpfId[8];
  char networkKey[16];
} CommsHub;

ChDevice *ChAddDevice(CommsHub *ch, const void *address, const void *installCode);
void ChRemoveDevice(CommsHub *ch, const void *address);

ChDevice *ChGetDeviceByShortAddress(CommsHub *ch, int address);

ChDevice *ChGetDeviceByZigbeeExtendedAddress(CommsHub *ch, const void *address);
ChDevice *ChGetDeviceByGbcsEntityId(CommsHub *ch, const void *id);

void ChReceiveGbcsMessage(CommsHub *ch, const void *gbcsMessage, int gbcsMessageLength);

void ChHandleTunnelDataGet(CommsHub *ch, const void *packet, int length);

int ChReceiveZigbeeApsFrame(CommsHub *ch, ChDevice *device, int encryption, int profileId, int clusterId, int sourceEndpoint, int destinationEndpoint, const void *payload, int length, void *gbcsMsgBuf);

int ChGetZigbeePacketToSend(CommsHub *ch, void *packet, ZigbeePacketInfo *info);

void ChZigbeeFrameSent(CommsHub *ch, int destination, int counter, int error);
