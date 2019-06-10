/*
 * ezsp.h
 *
 * Implementation of the Ember ZNet Serial Protocol (EZSP)
 * used to communicate with Silicon Labs EM35xx zigbee modules.
 *
 * This is free and unencumbered software released into the public domain.
 * See the UNLICENSE file or https://unlicense.org for more details.
 */

/* Frame ID values */
enum {
  /* Configuration Frames */
  EZSP_VERSION = 0x00,
  EZSP_GET_CONFIGURATION_VALUE = 0x52,
  EZSP_SET_CONFIGURATION_VALUE = 0x53,
  EZSP_ADD_ENDPOINT = 0x02,
  EZSP_SET_POLICY = 0x55,
  EZSP_GET_POLICY = 0x56,
  EZSP_GET_VALUE = 0xAA,

  /* Utilities Frames */
  EZSP_GET_MFG_TOKEN = 0x0B,
  EZSP_GET_EUI64 = 0x26,

  /* Networking Frames */
  EZSP_STACK_STATUS_HANDLER = 0x19,
  EZSP_START_SCAN = 0x1A,
  EZSP_ENERGY_SCAN_RESULT_HANDLER = 0x48,
  EZSP_NETWORK_FOUND_HANDLER = 0x1B,
  EZSP_SCAN_COMPLETE_HANDLER = 0x1C,
  EZSP_FORM_NETWORK = 0x1E,
  EZSP_LEAVE_NETWORK = 0x20,
  EZSP_PERMIT_JOINING = 0x22,
  EZSP_CHILD_JOIN_HANDLER = 0x23,

  /* Messaging Frames */
  EZSP_SEND_UNICAST = 0x34,
  EZSP_SEND_REPLY = 0x39,
  EZSP_MESSAGE_SENT_HANDLER = 0x3F,
  EZSP_INCOMING_MESSAGE_HANDLER = 0x45,
  EZSP_SEND_RAW_MESSAGE = 0x96,

  /* Security Frames */
  EZSP_SET_INITIAL_SECURITY_STATE = 0x68,
  EZSP_GET_KEY_TABLE_ENTRY = 0x71,
  EZSP_SET_KEY_TABLE_ENTRY = 0x72,
  EZSP_FIND_KEY_TABLE_ENTRY = 0x75,
  EZSP_ADD_OR_UPDATE_KEY_TABLE_ENTRY = 0x66,
  EZSP_CLEAR_KEY_TABLE = 0xB1,

  /* Trust Center Frames */
  EZSP_TRUST_CENTER_JOIN_HANDLER = 0x24,

  /* Certificate Based Key Exchange (CBKE) Frames */
  EZSP_GENERATE_CBKE_KEYS_283K1 = 0xE8,
  EZSP_GENERATE_CBKE_KEYS_HANDLER_283K1 = 0xE9,
  EZSP_CALCULATE_SMACS_283K1 = 0xEA,
  EZSP_CALCULATE_SMACS_HANDLER_283K1 = 0xEB,
  EZSP_CLEAR_TEMPORARY_DATA_MAYBE_STORE_LINK_KEY_283K1 = 0xEE,
  EZSP_GET_CERTIFICATE283K1 = 0xEC,
};

/* EmberStatus */
typedef enum {
  EZSP_SUCCESS = 0,
  EZSP_NETWORK_UP = 0x90,
  EZSP_NETWORK_DOWN = 0x91,
  EZSP_OPERATION_IN_PROGRESS = 0xBA,
} EzspStatus;

typedef enum {
  EZSP_CONFIG_STACK_PROFILE = 0x0C,
  EZSP_CONFIG_SECURITY_LEVEL = 0x0D,
  EZSP_CONFIG_KEY_TABLE_SIZE = 0x1E,
  EZSP_CONFIG_APPLICATION_ZDO_FLAGS = 0x2A,
  EZSP_CONFIG_SUPPORTED_NETWORKS = 0x2D,
} EzspConfigId;

typedef enum {
  EZSP_VALUE_CERTIFICATE_283K1 = 0x1A,
} EzspValueId;

typedef enum {
  EZSP_APP_RECEIVES_SUPPORTED_ZDO_REQUESTS = 0x01,
  EZSP_APP_HANDLES_UNSUPPORTED_ZDO_REQUESTS = 0x02,
  EZSP_APP_HANDLES_ZDO_ENDPOINT_REQUESTS = 0x04,
  EZSP_APP_HANDLES_ZDO_BINDING_REQUESTS = 0x08,
} EzspZdoConfigurationFlags;

typedef enum {
  EZSP_TRUST_CENTER_POLICY = 0x00,
  EZSP_UNICAST_REPLIES_POLICY = 0x02,
} EzspPolicyId;

typedef enum {
  EZSP_HOST_WILL_NOT_SUPPLY_REPLY = 0x20,
  EZSP_HOST_WILL_SUPPLY_REPLY = 0x21,
} EzspDecisionId;

typedef enum {
  EZSP_MFG_CBKE_DATA = 0x09,  /* 92 bytes */
  EZSP_MFG_INSTALLATION_CODE = 0x0A,
} EzspMfgTokenId;

typedef enum {
  EZSP_APS_OPTION_NONE = 0x0000,
  EZSP_APS_OPTION_ENCRYPTION = 0x0020,
  EZSP_APS_OPTION_FRAGMENT = 0x8000,
} EzspApsOption;

typedef enum {
  EZSP_SECURED_REJOIN = 0,
  EZSP_UNSECURED_JOIN = 1,
  EZSP_DEVICE_LEFT = 2,
  EZSP_UNSECURED_REJOIN = 3,
} EzspDeviceUpdate;

typedef enum {
  EZSP_ENERGY_SCAN = 0,  /* scan each channel for its RSSI value */
  EZSP_ACTIVE_SCAN = 1,  /* scan each channel for available networks */
} EzspNetworkScanType;

enum { EZSP_ALL_CHANNELS = 0x7FFF800 };

/*
 * 3.2 Structure Definitions
 */
typedef struct {
  unsigned char profileId[2];
  unsigned char clusterId[2];
  unsigned char sourceEndpoint;
  unsigned char destinationEndpoint;
  unsigned char options[2];  /* EzspApsOptions */
  unsigned char groupId[2];
  unsigned char sequence;
} EzspApsFrame;

/* Response packets */

typedef struct {
  unsigned char frameId;  /* EZSP_INCOMING_MESSAGE_HANDLER */
  unsigned char type;  /* EzspIncomingMessageType */
  unsigned char apsFrame[sizeof(EzspApsFrame)];
  unsigned char lastHopLqi;
    signed char lastHopRssi;
  unsigned char sender[2];
  unsigned char bindingIndex;
  unsigned char addressIndes;
  unsigned char messageLength;
  unsigned char messageContents[1];
} EzspIncomingMessageHandlerResponse;

typedef struct {
  unsigned char frameId;  /* EZSP_SEND_UNICAST */
  unsigned char status;
  unsigned char sequence;
} EzspSendUnicastResponse;

typedef struct {
  unsigned char frameId;  /* EZSP_MESSAGE_SENT_HANDLER */
  unsigned char type;  /* EzspOutgoingMessageType */
  unsigned char destination[2];
  unsigned char apsFrame[sizeof(EzspApsFrame)];
  unsigned char messageTag;
  unsigned char status;  /* EzspStatus */
  unsigned char messageLength;
} EzspMessageSentHandlerResponse;

/* EZSP input/output buffers and state of the communications */
typedef struct {
  unsigned char input[254];
  unsigned char output[255];
  unsigned char input_head;
  unsigned char input_tail;
  unsigned char output_head;

  /* Acknowledge number of the last DATA or ACK frame sent */
  unsigned char acknum;

  /* Sequence number of the next command DATA frame to be sent */
  unsigned char sequence;

  /* EZSP version */
  unsigned char version;

  char busy;
} Ezsp;

void EzspReset(Ezsp *ezsp);
int EzspGetResponse(Ezsp *ezsp);

/* Configuration Frames */
void EzspGetConfigurationValue(Ezsp *ezsp, EzspConfigId id);
void EzspSetConfigurationValue(Ezsp *ezsp, EzspConfigId id, int value);
void EzspSetPolicy(Ezsp *ezsp, EzspPolicyId policy, EzspDecisionId decision);
void EzspGetPolicy(Ezsp *ezsp, EzspPolicyId policy);
void EzspGetValue(Ezsp *ezsp, EzspValueId id);

/* Utilities Frames */
void EzspGetMfgToken(Ezsp *ezsp, EzspMfgTokenId id);
void EzspGetEui64(Ezsp *ezsp);

/* Networking Frames */
void EzspScan(Ezsp *ezsp, EzspNetworkScanType type, int channels, int duration);
void EzspFormNetwork(Ezsp *ezsp, const void *extendedPanId, const void *panId, int channel);
void EzspLeaveNetwork(Ezsp *ezsp);
void EzspPermitJoining(Ezsp *ezsp, int duration);

/* Messaging Frames */
void EzspSendUnicast(Ezsp *ezsp, int destination, int profileId, int clusterId, int sourceEndpoint, int destinationEndpoint, EzspApsOption options, int messageLength, const void *messageContents);
void EzspSendReply(Ezsp *ezsp, const void *sender, const void *apsFrame, int messageLength, const void *messageContents);
void EzspSendRawMessage(Ezsp *ezsp, int messageLength, const void *messageContents);

/* Security Frames */
void EzspSetInitialSecurityState(Ezsp *ezsp, const void *networkKey);
void EzspGetKeyTableEntry(Ezsp *ezsp, int index);
void EzspSetKeyTableEntry(Ezsp *ezsp, int index, const void *address, int isLinkKey, const void *key);
void EzspFindKeyTableEntry(Ezsp *ezsp, const void *address, int isLinkKey);
void EzspClearKeyTable(Ezsp *ezsp);

/* Certificate Based Key Exchange (CBKE) Frames */
void EzspGenerateCbkeKeys283k1(Ezsp *ezsp);
void EzspCalculateSmacs283k1(Ezsp *ezsp, int initiator, const void *certificate, const void *key);
void EzspClearTemporaryDataMaybeStoreLinkKey283k1(Ezsp *ezsp, int store);
void EzspGetCertificate283k1(Ezsp *ezsp);
