/*
 * ezsp.c
 *
 * Implementation of the Ember ZNet Serial Protocol (EZSP)
 * used to communicate with Silicon Labs EM35xx ZigBee modules.
 *
 * This is free and unencumbered software released into the public domain.
 * See the UNLICENSE file or https://unlicense.org for more details.
 *
 * References:
 *
 * [UG100] UG100: EZSP reference guide, rev. 3.4
 *         https://www.silabs.com/documents/public/user-guides/ug100-ezsp-reference-guide.pdf
 *
 * [UG101] UG101: UART gateway protocol reference, rev. 0.9
 *         https://www.silabs.com/documents/public/user-guides/ug101-uart-gateway-protocol-reference.pdf
 */

#include "ezsp.h"

/*
 * Initial value of the pseudo-random sequence of the data randomization.
 * Reference: [UG101] 4.3 Data randomization.
 */
enum { EZSP_RAND = 0x42 };

/*
 * Initial value of the CRC computation.
 * Reference: [UG101] 2.3 CRC.
 */
enum { EZSP_CRC = 0xFFFF };

/*
 * Perform one step of the CRC computation for an input byte.
 * Standard CRC-CCITT: g(x) = x^16 + x^12 + x^5 + 1
 * Reference: [UG101] 2.3. CRC.
 *
 * Usage:
 * unsigned short crc = EZSP_CRC;
 * for (i = ...)
 *   EzspCrc(&crc, input[i]);
 */
static void EzspCrc(unsigned short *crc, unsigned char input) {
  unsigned i, x;
  x = *crc ^ (input << 8);
  for (i = 0; i < 8; i++) {
    x = x << 1;
    if (x & 0x10000) {
      x = x ^ 0x1021;
    }
  }
  *crc = x & 0xffff;
}

/*
 * Put a byte in the output buffer, with byte stuffing in case of reserved byte.
 * [UG101] 4.2 Reserved bytes and byte stuffing.
 */
static void EzspByteStuff(Ezsp *ezsp, unsigned char byte) {
  switch (byte) {
  case 0x11: case 0x13: case 0x18: case 0x1A: case 0x7E: case 0x7D:
    ezsp->output[ezsp->output_head++] = 0x7D;
    byte ^= 0x20;
    break;
  }
  ezsp->output[ezsp->output_head++] = byte;
}

/*
 * Apply randomization, update the CRC, add the byte stuffing, and put it in the output buffer.
 * Reference: [UG101] 4.3 Data randomization.
 */
static void EzspRandCrcStuff(Ezsp *ezsp, unsigned char *rand, unsigned short *crc, unsigned char byte) {
  unsigned char r = *rand;
  byte ^= r;
  *rand = (r >> 1) ^ ((r & 1) * 0xB8);
  EzspCrc(crc, byte);
  EzspByteStuff(ezsp, byte);
}

/*
 * Put an ACK frame in the output buffer.
 * Reference: [UG101] 3.5 ACK frame format.
 */
static void EzspAck(Ezsp *ezsp) {
  unsigned char acknum, control;
  unsigned short crc;

  /* Control byte */
  acknum = (ezsp->acknum + 1) & 7;
  ezsp->acknum = acknum;
  control = 0x80 | acknum;
  ezsp->output[ezsp->output_head++] = control;

  /* CRC bytes */
  crc = EZSP_CRC;
  EzspCrc(&crc, control);
  EzspByteStuff(ezsp, (crc >> 8) & 0xff);
  EzspByteStuff(ezsp, crc & 0xff);

  /* Flag byte */
  ezsp->output[ezsp->output_head++] = 0x7e;

  ezsp->busy = 0;
}

/*
 * Put a command DATA frame in the output buffer.
 * References:
 * [UG100] 3 Protocol format.
 * [UG101] 2 Frames.
 * [UG101] 3.4 DATA frame format.
 */
static void EzspCommand(Ezsp *ezsp, const void *command, int length) {
  unsigned short crc = EZSP_CRC;
  unsigned char rand = EZSP_RAND;
  int frmnum, control, i;

#if 0
  printf("EZSP command: %02X", frame_id);
  for (int i = 0; i < (int)parameters_length; i++) {
    printf(" %02X", ((unsigned char *)parameters)[i]);
  }
  printf("\n");
#endif

  /* Control byte */
  frmnum = ezsp->sequence & 7;
  control = frmnum << 4 | ezsp->acknum;
  EzspCrc(&crc, control);
  EzspByteStuff(ezsp, control);

  /* Sequence byte */
  EzspRandCrcStuff(ezsp, &rand, &crc, ezsp->sequence++);

  /* Frame control byte */
  EzspRandCrcStuff(ezsp, &rand, &crc, 0);

  if (ezsp->version > 4) {
    /* Legacy frame id byte */
    EzspRandCrcStuff(ezsp, &rand, &crc, 0xFF);
    /* Extended frame control byte */
    EzspRandCrcStuff(ezsp, &rand, &crc, 0);
  }

  /* Frame id byte and parameter bytes */
  for (i = 0; i < length; i++) {
    EzspRandCrcStuff(ezsp, &rand, &crc, ((unsigned char *)command)[i]);
  }

  /* CRC bytes */
  EzspByteStuff(ezsp, (crc >> 8) & 0xFF);
  EzspByteStuff(ezsp, crc & 0xff);

  /* Flag byte */
  ezsp->output[ezsp->output_head++] = 0x7E;

  ezsp->busy = 1;
}

/*
 * Put a version command in the output buffer.
 * Reference: [UG100] 4 Configuration frames.
 */
static void EzspVersion(Ezsp *ezsp) {
  char x[] = { EZSP_VERSION, ezsp->version };
  EzspCommand(ezsp, x, sizeof(x));
}

/*
 * Put a RST (reset) frame in the output buffer and initialize the ezsp structure.
 * Reference: [UG101] 3.1 RST frame format.
 */
void EzspReset(Ezsp *ezsp) {
  ezsp->output[0] = 0x1A;   /* cancel byte */
  ezsp->output[1] = 0xC0;   /* control byte */
  ezsp->output[2] = 0x38;   /* CRC high byte */
  ezsp->output[3] = 0xBC;   /* CRC low byte */
  ezsp->output[4] = 0x7E;   /* flag byte */
  ezsp->output_head = 5;
  ezsp->input_head = 0;
  ezsp->input_tail = 0;
  ezsp->acknum = 0;
  ezsp->sequence = 0;
  ezsp->busy = 0;
  /*
   * Assume initialy the legacy EZSP version 4 and correct it later
   * based on the response of the device to the version command.
   */
  ezsp->version = 4;
}

/*
 * Get the next response DATA frame in the input buffer.
 * Returns 0 if there is no complete response in the input buffer
 * otherwise copies the response to the begining of the input buffer,
 * starting at the frame id byte, and returns the number of bytes
 * of the response (frame id byte + response parameter bytes).
 * References:
 * [UG100] 3 Protocol Format.
 * [UG101] 4.4 Receiving frames.
 */
int EzspGetResponse(Ezsp *ezsp)
{
  int i, j, length;
  unsigned char byte, rand, frmnum, version;
  unsigned short crc;

  for (i = ezsp->input_tail; i < ezsp->input_head; i++) {
    byte = ezsp->input[i];
    if (byte == 0x1a) { /* cancel byte (ignore previous data) */
      ezsp->input_tail = i + 1;
    } else if (byte != 0x7e) { /* flag byte (end of a frame) */
      continue;
    }
    /* Reverse the bit stuffing and calculate the CRC. */
    length = 0;
    crc = EZSP_CRC;
    for (j = ezsp->input_tail; j < i; j++) {
      byte = ezsp->input[j];
      if (byte != 0x11) { /* xon byte (ignore) */
        if (byte == 0x7d) { /* escape byte */
          byte = ezsp->input[++j] ^ 0x20;
        }
        ezsp->input[length++] = byte;
        EzspCrc(&crc, byte);
      }
    }
    ezsp->input_tail = i + 1;
    if (length < 4 || crc != 0) { /* invalid frame or wrong CRC */
      continue;
    }
    length = length - 2; /* exclude the CRC bytes */
    byte = ezsp->input[0]; /* control byte */
    if ((byte & 0x80) == 0) { /* DATA frame */
      frmnum = (byte >> 4) & 7;
      if (frmnum != ezsp->acknum) { /* wrong acknowledge number */
        continue;
      }
      EzspAck(ezsp);
      /* Reverse the data randomization */
      rand = EZSP_RAND;
      for (j = 1; j < length; j++) {
        ezsp->input[j] ^= rand;
        rand = (rand >> 1) ^ ((rand & 1) * 0xb8);
      }
      /* Copy the response to the begining of the input buffer */
      if (ezsp->input[3] == 0xff) { /* EZSP version > 4 */
        length = length - 5;
        for (j = 0; j < length; j++) {
          ezsp->input[j] = ezsp->input[j + 5];
        }
      } else { /* EZSP version == 4 */
        length = length - 3;
        for (j = 0; j < length; j++) {
          ezsp->input[j] = ezsp->input[j + 3];
        }
      }
      /* Resend the version command if the EZSP versions don't match */
      if (ezsp->input[0] == EZSP_VERSION) { /* frame id */
        version = ezsp->input[1];
        if (version != ezsp->version) {
          ezsp->version = version;
          EzspVersion(ezsp);
          break;
        }
      }
      return length;
    } else if (byte == 0xc1) { /* RSTACK (reset acknowledge) */
      /* The version command must be the first one sent after reset */
      EzspVersion(ezsp);
    }
  }

  /* Copy any remaining input bytes to the begining of the input buffer */
  for (j = 0, i = ezsp->input_tail; i < ezsp->input_head; i++) {
    byte = ezsp->input[i];
    if (byte != 0x11) { /* xon byte (ignore) */
      ezsp->input[j++] = byte;
    }
  }
  ezsp->input_head = j;
  ezsp->input_tail = 0;

  /* There is no complete response in the input buffer */
  return 0;
}

/* Configuration Frames */

void EzspGetConfigurationValue(Ezsp *ezsp, EzspConfigId id) {
  char x[] = { EZSP_GET_CONFIGURATION_VALUE, id };
  EzspCommand(ezsp, x, sizeof(x));
}

void EzspSetConfigurationValue(Ezsp *ezsp, EzspConfigId id, int value) {
  char x[] = { EZSP_SET_CONFIGURATION_VALUE, id, value, value >> 8 };
  EzspCommand(ezsp, x, sizeof(x));
}

void EzspSetPolicy(Ezsp *ezsp, EzspPolicyId policy, EzspDecisionId decision) {
  char x[] = { EZSP_SET_POLICY, policy, decision };
  EzspCommand(ezsp, x, sizeof(x));
}

void EzspGetPolicy(Ezsp *ezsp, EzspPolicyId policy) {
  char x[] = { EZSP_GET_POLICY, policy };
  EzspCommand(ezsp, x, sizeof(x));
}

void EzspGetValue(Ezsp *ezsp, EzspValueId id) {
  char x[] = { EZSP_GET_VALUE, id };
  EzspCommand(ezsp, x, sizeof(x));
}

/* Utilities Frames */

void EzspGetMfgToken(Ezsp *ezsp, EzspMfgTokenId id) {
  char x[] = { EZSP_GET_MFG_TOKEN, id };
  EzspCommand(ezsp, x, sizeof(x));
}

void EzspGetEui64(Ezsp *ezsp) {
  char x[] = { EZSP_GET_EUI64 };
  EzspCommand(ezsp, x, sizeof(x));
}

/* Networking Frames */

/*
 * duration: 0 to 14
 */
void EzspScan(Ezsp *ezsp, EzspNetworkScanType type, int channels, int duration) {
  char x[] = {
    EZSP_START_SCAN,
    type,
    channels,
    channels >> 8,
    channels >> 16,
    channels >> 24,
    duration
  };
  EzspCommand(ezsp, x, sizeof(x));
}

void EzspFormNetwork(Ezsp *ezsp, const void *extendedPanId, const void *panId, int channel) {
  char x[] = {
    EZSP_FORM_NETWORK,
    /* EmberNetworkParameters */
    ((char *)extendedPanId)[0],
    ((char *)extendedPanId)[1],
    ((char *)extendedPanId)[2],
    ((char *)extendedPanId)[3],
    ((char *)extendedPanId)[4],
    ((char *)extendedPanId)[5],
    ((char *)extendedPanId)[6],
    ((char *)extendedPanId)[7],
    ((char *)panId)[0],
    ((char *)panId)[1],
    0,  /* radioTxPower (dBm) */
    channel,
    0,  /* joinMethod (EMBER_USE_MAC_ASSOCIATION) */
    0, 0,  /* EmberNodeId nwkManagerId */
    0,  /* nwkUpdateId */
    0, 0, 0, 0,  /* channels */
  };
  EzspCommand(ezsp, x, sizeof(x));
}

void EzspLeaveNetwork(Ezsp *ezsp) {
  char x[] = { EZSP_LEAVE_NETWORK };
  EzspCommand(ezsp, x, sizeof(x));
}

/*
 * duration: 0 to 0xFE number of seconds, or 0xFF to permit forever
 */
void EzspPermitJoining(Ezsp *ezsp, int duration) {
  char x[] = { EZSP_PERMIT_JOINING, duration };
  EzspCommand(ezsp, x, sizeof(x));
}

/* Messaging Frames */

void EzspSendUnicast(Ezsp *ezsp, int destination, int profileId, int clusterId, int sourceEndpoint, int destinationEndpoint, EzspApsOption options, int messageLength, const void *messageContents) {
  char x[256] = {
    EZSP_SEND_UNICAST,
    0,  /* type (EMBER_OUTGOING_DIRECT) */
    destination, destination >> 8,
    /* apsFrame */
    profileId, profileId >> 8,
    clusterId, clusterId >> 8,
    sourceEndpoint,
    destinationEndpoint,
    options, options >> 8,
    0, 0,  /* groupId (not used in unicast) */
    0,  /* sequence (the EZSP device will overwrite this value) */
    /* messageTag */
    0,
    messageLength,
  };
  int i;
  for (i = 0; i < messageLength; i++) {
    x[17 + i] = ((char *)messageContents)[i];
  }
  EzspCommand(ezsp, x, 17 + messageLength);
}

void EzspSendReply(Ezsp *ezsp, const void *sender, const void *apsFrame, int messageLength, const void *messageContents) {
  char x[256] = {
    EZSP_SEND_REPLY,
    ((char *)sender)[0],
    ((char *)sender)[1],
    ((char *)apsFrame)[0],
    ((char *)apsFrame)[1],
    ((char *)apsFrame)[2],
    ((char *)apsFrame)[3],
    ((char *)apsFrame)[4],
    ((char *)apsFrame)[5],
    ((char *)apsFrame)[6],
    ((char *)apsFrame)[7],
    ((char *)apsFrame)[8],
    ((char *)apsFrame)[9],
    ((char *)apsFrame)[10],
    messageLength,
  };
  int i;
  for (i = 0; i < messageLength; i++) {
    x[15 + i] = ((char *)messageContents)[i];
  }
  EzspCommand(ezsp, x, 15 + messageLength);
}

void EzspSendRawMessage(Ezsp *ezsp, int messageLength, const void *messageContents) {
  char x[257];
  x[0] = EZSP_SEND_RAW_MESSAGE;
  x[1] = messageLength;
  for (int i = 0; i < messageLength; i++) {
    x[2 + i] = ((char *)messageContents)[i];
  }
  EzspCommand(ezsp, x, 2 + messageLength);
}

/* Security Frames */

void EzspSetInitialSecurityState(Ezsp *ezsp, const void *networkKey) {
  char x[] = {
    EZSP_SET_INITIAL_SECURITY_STATE,
    /* EmberInitialSecurityState */
    //0x08, 0x0A,  /* EmberInitialSecurityMask (EMBER_PRECONFIGURED_NETWORK_KEY_MODE | EMBER_HAVE_NETWORK_KEY | EMBER_REQUIRE_ENCRYPTED_KEY) */
    //0x08, 0x02,  /* EmberInitialSecurityMask (EMBER_PRECONFIGURED_NETWORK_KEY_MODE | EMBER_HAVE_NETWORK_KEY) */
    0x00, 0x02,  /* EmberInitialSecurityMask (EMBER_HAVE_NETWORK_KEY) */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* preconfiguredKey */
    ((char *)networkKey)[0],
    ((char *)networkKey)[1],
    ((char *)networkKey)[2],
    ((char *)networkKey)[3],
    ((char *)networkKey)[4],
    ((char *)networkKey)[5],
    ((char *)networkKey)[6],
    ((char *)networkKey)[7],
    ((char *)networkKey)[8],
    ((char *)networkKey)[9],
    ((char *)networkKey)[10],
    ((char *)networkKey)[11],
    ((char *)networkKey)[12],
    ((char *)networkKey)[13],
    ((char *)networkKey)[14],
    ((char *)networkKey)[15],
    0,  /* networkKeySequenceNumber */
    0, 0, 0, 0, 0, 0, 0, 0,  /* preconfiguredTrustCenterEui64 */
  };
  EzspCommand(ezsp, x, sizeof(x));
}

void EzspGetKeyTableEntry(Ezsp *ezsp, int index) {
  char x[] = { EZSP_GET_KEY_TABLE_ENTRY, index };
  EzspCommand(ezsp, x, sizeof(x));
}

void EzspSetKeyTableEntry(Ezsp *ezsp, int index, const void *address, int isLinkKey, const void *key) {
  char x[] = {
    EZSP_SET_KEY_TABLE_ENTRY,
    index,
    ((char *)address)[0],
    ((char *)address)[1],
    ((char *)address)[2],
    ((char *)address)[3],
    ((char *)address)[4],
    ((char *)address)[5],
    ((char *)address)[6],
    ((char *)address)[7],
    isLinkKey,
    ((char *)key)[0],
    ((char *)key)[1],
    ((char *)key)[2],
    ((char *)key)[3],
    ((char *)key)[4],
    ((char *)key)[5],
    ((char *)key)[6],
    ((char *)key)[7],
    ((char *)key)[8],
    ((char *)key)[9],
    ((char *)key)[10],
    ((char *)key)[11],
    ((char *)key)[12],
    ((char *)key)[13],
    ((char *)key)[14],
    ((char *)key)[15],
  };
  EzspCommand(ezsp, x, sizeof(x));
}

void EzspFindKeyTableEntry(Ezsp *ezsp, const void *address, int isLinkKey) {
  char x[] = {
    EZSP_FIND_KEY_TABLE_ENTRY,
    ((char *)address)[0],
    ((char *)address)[1],
    ((char *)address)[2],
    ((char *)address)[3],
    ((char *)address)[4],
    ((char *)address)[5],
    ((char *)address)[6],
    ((char *)address)[7],
    isLinkKey
  };
  EzspCommand(ezsp, x, sizeof(x));
}

void EzspClearKeyTable(Ezsp *ezsp) {
  char x[] = { EZSP_CLEAR_KEY_TABLE };
  EzspCommand(ezsp, x, sizeof(x));
}

/* Certificate Based Key Exchange (CBKE) Frames */

void EzspGenerateCbkeKeys283k1(Ezsp *ezsp) {
  char x[] = { EZSP_GENERATE_CBKE_KEYS_283K1 };
  EzspCommand(ezsp, x, sizeof(x));
}

void EzspCalculateSmacs283k1(Ezsp *ezsp, int initiator, const void *certificate, const void *key) {
  char x[1 + 1 + 74 + 37];
  int i;
  x[0] = EZSP_CALCULATE_SMACS_283K1;
  x[1] = initiator;
  for (i = 0; i < 74; i++) {
    x[2 + i] = ((char *)certificate)[i];
  }
  for (i = 0; i < 37; i++) {
    x[76 + i] = ((char *)key)[i];
  }
  EzspCommand(ezsp, x, sizeof(x));
}

void EzspClearTemporaryDataMaybeStoreLinkKey283k1(Ezsp *ezsp, int store) {
  char x[] = { EZSP_CLEAR_TEMPORARY_DATA_MAYBE_STORE_LINK_KEY_283K1, store };
  EzspCommand(ezsp, x, sizeof(x));
}

void EzspGetCertificate283k1(Ezsp *ezsp) {
  char x[] = { EZSP_GET_CERTIFICATE283K1 };
  EzspCommand(ezsp, x, sizeof(x));
}
