/*
 * main.c: GBCS programmer's devices
 *
 * This is free and unencumbered software released into the public domain.
 * See the UNLICENSE file or https://unlicense.org for more details.
 */

#include "ch.h"
#include "crypto.h"
#include "ezsp.h"
#include "gfi.h"
#include "zigbee.h"

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <setupapi.h>
#include <ntddser.h>  /* GUID_DEVINTERFACE_COMPORT */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

enum {
  MAX_HTTP_CLIENTS = 10,
  MAX_SERIAL_PORTS = 3,
};

/* Websocket command identifier byte */
enum {
  WS_GET_SETTINGS,
  WS_START,
  WS_STOP,
  WS_ENERGY_SCAN,  // TOREMOVE
  WS_ACTIVE_SCAN,
  WS_SCAN_COMPLETE,  // TOREMOVE
  WS_FIRMWARE_UPGRADE,  // TOREMOVE
  WS_GET_DEVICES,
  WS_ADD_CH_DEVICE = 10,
  WS_REMOVE_CH_DEVICE,
  WS_CH_DEVICE,
  WS_SAVE_CH_DEVICE,
  WS_GET_SERIAL_DEVICES = 20,
  WS_ZIGBEE_RX = 128,
  WS_ZIGBEE_TX,
  WS_GBCS_MESSAGE,
  WS_SEND_MAC_FRAME,
  WS_SEND_APS_FRAME,
  WS_LOG_MESSAGE = 255,
};

enum {
  SOCKET_DISCONNECTED,
  SOCKET_CONNECTED,
  SOCKET_HTTP,
  SOCKET_WEBSOCKET,
  SOCKET_GFI,
};

typedef struct {
  unsigned short head;
  unsigned short tail;
  unsigned char state;  /* SOCKET_DISCONNECTED, etc... */
  unsigned char buffer[30 + 1200 * 2];
} HttpBuffer;

// poll() vs WaitForMultipleObjects()

#ifdef _WIN32
static HANDLE handles[1 /* HTTP server socket */ + MAX_HTTP_CLIENTS + MAX_SERIAL_PORTS];
static int handleCount;
#endif

typedef enum {
  IDLE = 0,
  START = 1,
} MainState;

typedef struct {
#ifdef _WIN32
  HANDLE handle;
  OVERLAPPED overlapped;
#endif
  char name[8];
} SerialPort;

typedef struct {
  const char *configfile;

  SerialPort serialPort;

  Ezsp ezsp;
  unsigned short ezspLastSendUnicastNodeId;
  unsigned char ezspLastSequence;

  CommsHub ch;

  MainState state;

  char scan;

#ifdef _WIN32
  int serialPortCount;
#endif

} MainData;

static MainData mainData;

static void SendToAllWebsockets(const void *message, int length);

static void SendLogMessage(const char *format, ...) {
  char s[512];
  va_list args;
  int n;

  s[0] = (char)WS_LOG_MESSAGE;

  va_start(args, format);
  n = vsprintf(&s[1], format, args);
  va_end(args);

  SendToAllWebsockets(s, 1 + n);
}

static void ParseHexString(void *bytes, int size, const char *hexstring) {
  int i;
  char h[3];

  for (i = 0; i < size; i++) {
    h[0] = hexstring[i * 2];
    h[1] = hexstring[i * 2 + 1];
    h[2] = '\0';
    ((char *)bytes)[i] = (char)strtol(h, NULL, 16);
  }
}

static void PrintHexString(FILE *f, const char *name, const void *bytes, int size) {
  int i;

  fprintf(f, "%s ", name);
  for (i = 0; i < size; i++) {
    fprintf(f, "%02X", ((unsigned char *)bytes)[i]);
  }
  fprintf(f, "\n");
}

static int getHex(char c) {
  int n = 0;
  if (c >= '0' && c <= '9') {
    n = c - '0';
  } else if (c >= 'A' && c <= 'F') {
    n = c - 'A' + 10;
  }
  return n;
}

/*
 * MMMM-TTTT-VVVVVVVV-III.zigbee
 */
static void UpdateImageFile(ChDevice *device, const char *name, int namelength) {
  int i, n = namelength;
  if (n < 18 || n >= sizeof(device->imageFile)) {
    return;
  }
  char buf[sizeof(device->imageFile)];
  for (i = 0; i < n; i++) {
    buf[i] = name[i];
  }
  buf[n] = 0;
  unsigned size = 0;
  FILE *f = fopen(buf, "r");
  if (f) {
    if (fseek(f, 0, SEEK_END) == 0) {
      long p = ftell(f);
      if (p >= 0) {
        size = p;
      }
    }
    fclose(f);
  }
  if (size == 0) {
    return;
  }
  device->ota.manufacturerCode = getHex(name[0]) << 12 | getHex(name[1]) << 8 | getHex(name[2]) << 4 | getHex(name[3]);
  device->ota.imageType = getHex(name[5]) << 12 | getHex(name[6]) << 8 | getHex(name[7]) << 4 | getHex(name[8]);
  device->ota.fileVersion = getHex(name[10]) << 28 | getHex(name[11]) << 24 | getHex(name[12]) << 20 | getHex(name[13]) << 16
                          | getHex(name[14]) << 12 | getHex(name[15]) << 8 | getHex(name[16]) << 4 | getHex(name[17]);
  device->ota.imageSize = size;
  for (i = 0; i < n; i++) {
    device->imageFile[i] = name[i];
  }
  device->imageFile[n] = '\0';
}

static void LoadConfig(MainData *data, const char *filename) {
  int i;

  /* Initialise with default values in case there is no config file */
  memset(data, 0, sizeof(*data));
  data->configfile = filename;
  data->ch.channel = 11;
  for (i = 0; i < sizeof(data->ch.networkKey); i++) {
    data->ch.networkKey[i] = i * 0x11;  /* 0x00112233...DDEEFF */
  }
  int deviceCount = 0;

  char s[128];
  char id[8];
  ChDevice *device = NULL;
  FILE *f = fopen(filename, "rb");
  if (f) {
    while (fgets(s, sizeof(s), f)) {
      char *x = strtok(s, " ");
      char *y = strtok(NULL, "\r\n");
      if (!strcmp(x, "SerialPort")) {
        if (strlen(y) < sizeof(data->serialPort.name)) {
          strcpy(data->serialPort.name, y);
        }
      } else if (!strcmp(x, "Channel")) {
        data->ch.channel = atoi(y);
      } else if (!strcmp(x, "NetworkKey")) {
        ParseHexString(data->ch.networkKey, sizeof(data->ch.networkKey), y);
      } else if (!strcmp(x, "Device")) {
        ParseHexString(id, sizeof(id), y);
      } else if (!strcmp(x, "InstallCode")) {
        char installCode[16];
        ParseHexString(installCode, sizeof(installCode), y);
        device = ChAddDevice(&data->ch, id, installCode);
      } else if (!strcmp(x, "ImageFile")) {
        UpdateImageFile(device, y, (int)strlen(y));
      }
    }
    fclose(f);
  }
}

static char *HexString(const void *bytes, int count, char *buffer) {
  int i;
  for (i = 0; i < count; i++) {
    sprintf(buffer + i * 2, "%02X", ((unsigned char *)bytes)[i]);
  }
  return buffer;
}

static void SaveConfig(MainData *data) {
  char tmpFileName[128];
  strcpy(tmpFileName, data->configfile);
  strcat(tmpFileName, "~");
  FILE *f = fopen(tmpFileName, "wb");
  if (f) {
    fprintf(f, "SerialPort %s\n", data->serialPort.name);
    fprintf(f, "Channel %d\n", data->ch.channel);
    PrintHexString(f, "NetworkKey", data->ch.networkKey, sizeof(data->ch.networkKey));
    for (int i = 0; i < sizeof(data->ch.devices) / sizeof(data->ch.devices[0]); i++) {
      ChDevice *d = &data->ch.devices[i];
      for (int j = 0; j < sizeof(d->extendedAddress); j++) {
        if (d->extendedAddress[j] != 0) {
          PrintHexString(f, "Device", d->extendedAddress, sizeof(d->extendedAddress));
          PrintHexString(f, "InstallCode", d->installCode, sizeof(d->installCode));
          if (d->imageFile[0]) {
            fprintf(f, "ImageFile %s\n", d->imageFile);
          }
          break;
        }
      }
    }
    fclose(f);
#ifdef _WIN32
    MoveFileExA(tmpFileName, data->configfile, MOVEFILE_REPLACE_EXISTING);
#else
    rename(tmpFileName, data->configfile);
#endif
  }
}

/* TODO: Linux */
static int OpenSerialPort(SerialPort *s) {
  char path[4 + sizeof(s->name)];
  DCB dcb;
  COMMTIMEOUTS timeouts;

  strcpy(path, "\\\\.\\");
  strcat(path, s->name);

  s->handle = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, 0);
  if (s->handle == INVALID_HANDLE_VALUE) {
    return 0;
  }
  if (!GetCommState(s->handle, &dcb)) {
    //fprintf(stderr, "error: GetCommState\n", argv[0]);
  }
  dcb.BaudRate = CBR_57600;
  dcb.ByteSize = 8;
  dcb.Parity = NOPARITY;
  dcb.StopBits = ONESTOPBIT;
  dcb.fRtsControl = RTS_CONTROL_ENABLE;
  if (!SetCommState(s->handle, &dcb) || !SetCommMask(s->handle, EV_RXCHAR)) {
    //fprintf(stderr, "%s: error: SetCommState || SetCommMask\n", argv[0]);
  }
  timeouts.ReadIntervalTimeout = 1;
  timeouts.ReadTotalTimeoutMultiplier = 0;
  timeouts.ReadTotalTimeoutConstant = 0;
  timeouts.WriteTotalTimeoutMultiplier = 0;
  timeouts.WriteTotalTimeoutConstant = 0;
  if (!SetCommTimeouts(s->handle, &timeouts)) {
    //fprintf(stderr, "%s: error: SetCommTimeouts\n", argv[0]);
  }

  s->overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (!ReadFile(s->handle, mainData.ezsp.input, sizeof(mainData.ezsp.input), NULL, &s->overlapped)) {
    //printf("ReadFile GetLastError=%d\n", GetLastError());
  }

  if (s->handle != INVALID_HANDLE_VALUE) {
    handles[handleCount++] = s->overlapped.hEvent;
    mainData.serialPortCount++;
  }

  return 1;
}

static void CloseSerialPort(SerialPort *s) {
  CloseHandle(s->overlapped.hEvent);
  CloseHandle(s->handle);

  for (int i = 0; i < handleCount; i++) {
    if (handles[i] == s->overlapped.hEvent) {
      handles[i] = handles[handleCount - 1];
      break;
    }
  }
  handleCount--;
  mainData.serialPortCount--;
}

static void SendChSettings(CommsHub *ch) {
  char x[29 + sizeof(mainData.serialPort.name)];
  int n;

  x[0] = WS_GET_SETTINGS;
  x[1] = ch->status;
  x[2] = ch->channel;
  memcpy(&x[3], ch->panId, 2);
  memcpy(&x[5], ch->gpfId, 8);
  memcpy(&x[13], ch->networkKey, 16);
  n = 29;
  strcpy(&x[n], mainData.serialPort.name);
  n += (int)strlen(mainData.serialPort.name);
  SendToAllWebsockets(x, n);
}

static void SetStatus(char status) {
  mainData.ch.status = status;
  SendChSettings(&mainData.ch);
}

/*
 * References:
 * - https://docs.microsoft.com/en-us/windows-hardware/drivers/install/enumerating-installed-device-interface-classes
 * - https://docs.microsoft.com/en-us/windows-hardware/drivers/install/registry-trees-and-keys
 */
static void GetSerialDevices(void) {
  char buf[512];
  int buflen;
  HDEVINFO hdi;
  SP_DEVINFO_DATA data;
  DWORD i;
  char name[64];
  
  buf[0] = WS_GET_SERIAL_DEVICES;
  buflen = 1;

  hdi = SetupDiGetClassDevsA(&GUID_DEVINTERFACE_COMPORT, NULL, NULL, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
  data.cbSize = sizeof(data);
  for (i = 0; SetupDiEnumDeviceInfo(hdi, i, &data); i++) {
    if (SetupDiGetDeviceRegistryPropertyA(hdi, &data, SPDRP_FRIENDLYNAME, NULL, name, sizeof(name), NULL)) {
      char *port = strstr(name, " (");
      if (port) {
        port[0] = '\0';
        port += 2;
        port[strlen(port) - 1] = '\0';
        if (buflen + strlen(port) + 1 + strlen(name) + 1 <= sizeof(buf)) {
          strcpy(buf + buflen, port);
          buflen += (int)strlen(port) + 1;
          strcpy(buf + buflen, name);
          buflen += (int)strlen(name) + 1;
        }
      }
    }
  }
  SetupDiDestroyDeviceInfoList(hdi);

  SendToAllWebsockets(buf, buflen);
}

// HTTP

static void HttpInit(HttpBuffer *h) {
  h->head = 0;
  h->tail = 0;
  h->state = SOCKET_CONNECTED;
}

static int ParseHttpRequest(HttpBuffer *h) {
  int startOfLine = h->tail;
  for (int i = startOfLine; i < h->head; i++) {
    if (h->buffer[i] == '\n') {
      int headerLen = i + 1 - startOfLine;
      startOfLine = i + 1;
      if (headerLen == 1 || (headerLen == 2 && h->buffer[i - 1] == '\r')) {
        h->tail = i + 1;
        return 1;
      }
    }
  }
  h->head -= h->tail;
  memmove(h->buffer, &h->buffer[h->tail], h->head);
  h->tail = 0;
  return 0;
}

static void ParseHttpHeaders(HttpBuffer *h, char **secWebSocketKey) {
  *secWebSocketKey = 0;
  int startOfLine = 0;
  for (int i = 0; i < h->tail; i++) {
    if (h->buffer[i] == '\n') {
      const char match[] = "Sec-WebSocket-Key:";
      char *header = &h->buffer[startOfLine];
      int headerLen = i - startOfLine;
      for (int j = 0; j < headerLen; j++) {
        if (match[j] == 0) {
          while (header[j] == ' ') {
            j++;
          }
          *secWebSocketKey = &header[j];
          break;
        }
        if (header[j] != match[j]) {
          break;
        }
      }
      startOfLine = i + 1;
    }
  }
}

static int setSecWebSocketAccept(char *buffer, const char *secWebSocketKey) {
  char concatenation[24 + 36];
  memcpy(concatenation, secWebSocketKey, 24);
  memcpy(concatenation + 24, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);

  char hash[20];
  CryptoSha1(hash, concatenation, sizeof(concatenation));

  return CryptoBase64(buffer, hash, sizeof(hash));
}

static int setHttpResponse(char *buffer, const char *secWebSocketKey) {
  const char prefilledResponse[] =
    "HTTP/1.1 101\n" /* Switching Protocols */
    "Upgrade:websocket\n"
    "Connection:Upgrade\n"
    "Sec-WebSocket-Accept:";
  int length = sizeof(prefilledResponse) - 1;
  memcpy(buffer, prefilledResponse, length);
  length += setSecWebSocketAccept(buffer + length, secWebSocketKey);
  buffer[length++] = '\n';
  buffer[length++] = '\n';
  return length;
}

static void SendWebsocketChDevice(const ChDevice *device) {
  char x[1 + sizeof(device->extendedAddress) + sizeof(device->installCode) + sizeof(device->preconfiguredKey) + sizeof(device->cbkeKey) + 2 + 1 + 1 + sizeof(device->imageFile)];
  int i, n = 0;
  x[n++] = WS_CH_DEVICE;
  memcpy(&x[n], device->extendedAddress, sizeof(device->extendedAddress));
  n += sizeof(device->extendedAddress);
  memcpy(&x[n], device->installCode, sizeof(device->installCode));
  n += sizeof(device->installCode);
  memcpy(&x[n], device->preconfiguredKey, sizeof(device->preconfiguredKey));
  n += sizeof(device->preconfiguredKey);
  memcpy(&x[n], device->cbkeKey, sizeof(device->cbkeKey));
  n += sizeof(device->cbkeKey);
  x[n++] = device->shortAddress >> 8;
  x[n++] = device->shortAddress & 255;
  x[n++] = device->ota.queryNextImageStatus;
  x[n++] = device->ota.imageBlockStatus;
  for (i = 0; device->imageFile[i]; i++) {
    x[n++] = device->imageFile[i];
  }
  SendToAllWebsockets(x, n);
}

static void SendWebsocketChDevices(const CommsHub *ch) {
  int i, j;
  for (i = 0; i < sizeof(ch->devices) / sizeof(ch->devices[0]); i++) {
    const ChDevice *device = &ch->devices[i];
    for (j = 0; j < sizeof(device->extendedAddress); j++) {
      if (device->extendedAddress[j] != 0) {
        SendWebsocketChDevice(device);
        break;
      }
    }
  }
}

static void ReceiveWebsocketAddChDevice(const void *payload, int length) {
  if (length == 1 + 8 + 16) {
    const unsigned char *address = &((const unsigned char *)payload)[1];  /* 8 bytes */
    const unsigned char *installCode = &((const unsigned char *)payload)[9];  /* 16 bytes */
    CommsHub *ch = &mainData.ch;
    ChDevice *device = ChAddDevice(ch, address, installCode);
    if (device) {
      SendWebsocketChDevice(device);
      SaveConfig(&mainData);
    }
  }
}

/* Handle the websocket packet that removes a device from the comms hub. */
static void RemoveChDevice(const void *payload, int length) {
  if (length >= 9) {
    const unsigned char *address = &((const unsigned char *)payload)[1];
    CommsHub *ch = &mainData.ch;
    char x[] = {
      WS_REMOVE_CH_DEVICE,
      address[0],
      address[1],
      address[2],
      address[3],
      address[4],
      address[5],
      address[6],
      address[7],
    };
    SendToAllWebsockets(x, sizeof(x));
    ChRemoveDevice(ch, address);
    SaveConfig(&mainData);
  }
}

static void ReceiveWebsocketSaveChDevice(const void *payload, int length) {
  if (length > 1 + 8 + 1 + 1) {
    const unsigned char *p = payload;
    ChDevice *device = ChGetDeviceByGbcsEntityId(&mainData.ch, &p[1]);
    if (device) {
      device->ota.queryNextImageStatus = p[9];
      device->ota.imageBlockStatus = p[10];
      UpdateImageFile(device, &p[11], length - 11);
      SendWebsocketChDevice(device);
      SaveConfig(&mainData);
    }
  }
}

static void HandleWebsocketStart(const void *payload, int length) {
  const struct {
    char websocketCommandId;
    char channel;
    char networkKey[16];
    char serialPort[1];
  } *params = payload;

  int modified = 0;
  if (length >= sizeof(*params)) {
    if (mainData.ch.channel != params->channel) {
      mainData.ch.channel = params->channel;
      modified = 1;
    }
    if (memcmp(mainData.ch.networkKey, params->networkKey, sizeof(mainData.ch.networkKey))) {
      memcpy(mainData.ch.networkKey, params->networkKey, sizeof(mainData.ch.networkKey));
      modified = 1;
    }
    if (strcmp(mainData.serialPort.name, params->serialPort)) {
      strcpy(mainData.serialPort.name, params->serialPort);
      modified = 1;
    }
  }
  if (modified) {
    SaveConfig(&mainData);
  }

  mainData.state |= START;
}

static void ZigbeeSend(ZigbeePacketInfo *info, int messageLength, const void *messageContents);

static void ReceiveWebsocketSendApsFrame(const unsigned char *payload, int length) {
  ZigbeePacketInfo zpi;
  zpi.destinationNode = payload[1] << 8 | payload[2];
  zpi.profileId = payload[3] << 8 | payload[4];
  zpi.clusterId = payload[5] << 8 | payload[6];
  zpi.sourceEndpoint = payload[7];
  zpi.destinationEndpoint = payload[8];
  zpi.encryption = payload[9];
  zpi.fragmentation = 0;
  zpi.fragmentNumber = 0;
  zpi.fragmentCount = 0;
  ZigbeeSend(&zpi, length - 10, payload + 10);
}

static void HandleWebsocketPayload(const unsigned char *payload, int length) {
  if (length > 0) {
    switch (payload[0]) {
    case WS_GET_SETTINGS:
      SendChSettings(&mainData.ch);
      break;
   case WS_GET_DEVICES:
      SendWebsocketChDevices(&mainData.ch);
      break; 
//   case WS_FIRMWARE_UPGRADE:
//      UpdateFirmwareUpgradeInfo(payload, length);
//      break;
    case WS_START:
      HandleWebsocketStart(payload, length);
      break;
    case WS_STOP:
      EzspLeaveNetwork(&mainData.ezsp);
      break;
    case WS_ACTIVE_SCAN:
      mainData.scan = 1;
      break;
    case WS_SAVE_CH_DEVICE:
      ReceiveWebsocketSaveChDevice(payload, length);
      break;
    case WS_ADD_CH_DEVICE:
      ReceiveWebsocketAddChDevice(payload, length);
      break;
    case WS_REMOVE_CH_DEVICE:
      RemoveChDevice(payload, length);
      break;
    case WS_GET_SERIAL_DEVICES:
      GetSerialDevices();
      break;
    case WS_SEND_MAC_FRAME:
      EzspSendRawMessage(&mainData.ezsp, length - 1, payload + 1);
      break;
    case WS_SEND_APS_FRAME:
      ReceiveWebsocketSendApsFrame(payload, length);
      break;
    }
  }
}

static int ReadWebsocketData(HttpBuffer *h) {
  int i = h->tail;
  int n = h->head;
  int length = 0x7fff;
  int masked = 0;
  unsigned char mask[4] = { 0 };
  if (i + 2 <= n) {
    int opcode = h->buffer[i] & 15;
    if (opcode != 2) {  /* opcode != binary frame */
      //printf("opcode=%d\n", opcode);
      return -1;
    }
    length = h->buffer[i + 1] & 127;
    masked = h->buffer[i + 1] & 128;
  }
  i += 2;
  if (length == 126) {
    if (i + 2 <= n) {
      length = h->buffer[i] << 8 | h->buffer[i + 1];
    }
    i += 2;
  }
  if (masked) {
    if (i + 4 <= n) {
      for (int j = 0; j < 4; j++) {
        mask[j] = h->buffer[i + j];
      }
    }
    i += 4;
  }
  if (i + length <= n) {
    for (int j = 0; j < length; j++) {
      h->buffer[i + j] ^= mask[j & 3];
    }
    h->tail = i + length;
    HandleWebsocketPayload(h->buffer + i, length);
    return 1;
  }
  return 0;
}

static void SendToWebsocket(SOCKET s, const void *payload, int length) {
  char header[4];
  int headerLen = 0;
  header[headerLen++] = 0x82;  /* FIN(0x80) | opcode(0x02 (binary frame)) */
  if (length < 126) {
    header[headerLen++] = length;
  } else {
    header[headerLen++] = 126;
    header[headerLen++] = length >> 8;
    header[headerLen++] = length;
  }
  send(s, header, headerLen, 0);
  send(s, payload, length, 0);
}

static HttpBuffer httpClientBuffers[MAX_HTTP_CLIENTS];

static HttpBuffer httpBuffers[MAX_HTTP_CLIENTS];
static int httpClientCount;
static SOCKET httpSockets[MAX_HTTP_CLIENTS];

// HTTP Clients

static void SendToAllWebsockets(const void *message, int length) {
  for (int i = 0; i < httpClientCount; i++) {
    if (httpClientBuffers[i].state == SOCKET_WEBSOCKET) {
      SendToWebsocket(httpSockets[i], message, length);
    }
  }
}

static void SendGbcsMessageToGfi(const void *message, int length) {
  char buf[GFI_MESSAGE_MAX_SIZE];
  int n = GfiFromGbcs(buf, sizeof(buf), message, length);
  for (int i = 0; i < httpClientCount; i++) {
    if (httpClientBuffers[i].state == SOCKET_GFI) {
      send(httpSockets[i], buf, n, 0);
    }
  }
}

static void ZigbeeFrameReceived(int profileId, int clusterId, int sourceEndpoint, int destinationEndpoint, const void *payload, int length) {
  int i;
  char a[256];

  a[0] = WS_ZIGBEE_RX;
  a[1] = profileId;
  a[2] = profileId >> 8;
  a[3] = clusterId;
  a[4] = clusterId >> 8;
  a[5] = sourceEndpoint;
  a[6] = destinationEndpoint;
  for (i = 0; i < length; i++) {
    a[7 + i] = ((char *)payload)[i];
  }
  SendToAllWebsockets(a, 7 + length);
}

static void ZigbeeFrameSent(int profileId, int clusterId, int sourceEndpoint, int destinationEndpoint, const void *payload, int length) {
  int i;
  char a[256];

  a[0] = WS_ZIGBEE_TX;
  a[1] = profileId;
  a[2] = profileId >> 8;
  a[3] = clusterId;
  a[4] = clusterId >> 8;
  a[5] = sourceEndpoint;
  a[6] = destinationEndpoint;
  for (i = 0; i < length; i++) {
    a[7 + i] = ((char *)payload)[i];
  }
  SendToAllWebsockets(a, 7 + length);
}

static void SendGbcsMessageLog(const void *message, int length) {
  int i;
  char a[1 + 1200];

  a[0] = WS_GBCS_MESSAGE;
  for (i = 0; i < length; i++) {
    a[1 + i] = ((char *)message)[i];
  }
  SendToAllWebsockets(a, 1 + length);
}

/* GFI */

static int ReceiveGfiData(HttpBuffer *h) {
  char *gfiMessage = &h->buffer[h->tail];
  int gfiMessageLength = h->head - h->tail;
  char *gbcsMessage = h->buffer;
  int gbcsMessageLength;
  h->tail += GfiToGbcs(gfiMessage, gfiMessageLength, gbcsMessage, &gbcsMessageLength);
  if (gbcsMessageLength) {
    SendGbcsMessageLog(gbcsMessage, gbcsMessageLength);
    ChReceiveGbcsMessage(&mainData.ch, gbcsMessage, gbcsMessageLength);
    return 1;
  }
  return 0;
}

static void SendActiveScanResult(int channel, int panId, const char *extendedPanId, int allowJoin, int stackProfile, int rssi) {
  if (stackProfile == 2) {
    char x[] = {
      WS_ACTIVE_SCAN,
      channel,
      panId >> 8,
      panId,
      extendedPanId[7],
      extendedPanId[6],
      extendedPanId[5],
      extendedPanId[4],
      extendedPanId[3],
      extendedPanId[2],
      extendedPanId[1],
      extendedPanId[0],
      allowJoin,
      rssi,
    };
    SendToAllWebsockets(x, sizeof(x));
  }
}

static const unsigned char ezspConfigValues[] = {
  EZSP_CONFIG_STACK_PROFILE, 2,  /* Zigbee stack profile 2 (Zigbee Pro) */
  EZSP_CONFIG_SECURITY_LEVEL, 5,  /* security level 5 (encryption and 32-bit MIC authentication) */
  EZSP_CONFIG_KEY_TABLE_SIZE, 16,
  EZSP_CONFIG_APPLICATION_ZDO_FLAGS, EZSP_APP_HANDLES_UNSUPPORTED_ZDO_REQUESTS | EZSP_APP_HANDLES_ZDO_ENDPOINT_REQUESTS | EZSP_APP_HANDLES_ZDO_BINDING_REQUESTS,
  EZSP_CONFIG_SUPPORTED_NETWORKS, 1,
};
static unsigned ezspConfigValueIndex;

/*
static const unsigned char ezspPolicyValues[] = {
  EZSP_UNICAST_REPLIES_POLICY, EZSP_HOST_WILL_SUPPLY_REPLY,
};
static unsigned ezspPolicyValueIndex;
*/

static void ZigbeeSend(ZigbeePacketInfo *info, int messageLength, const void *messageContents) {
  EzspApsOption options = EZSP_APS_OPTION_NONE;
  if (info->encryption) {
    options |= EZSP_APS_OPTION_ENCRYPTION;
  }
  if (info->fragmentation) {
    options |= EZSP_APS_OPTION_FRAGMENT;
  }
  EzspSendUnicast(&mainData.ezsp, info->destinationNode, info->profileId, info->clusterId, info->sourceEndpoint, info->destinationEndpoint, options, messageLength, messageContents);
  ZigbeeFrameSent(info->profileId, info->clusterId, info->sourceEndpoint, info->destinationEndpoint, messageContents, messageLength);
  mainData.ezspLastSendUnicastNodeId = info->destinationNode;
}

static void ReadEzspIncomingMessageHandler(MainData *data, Ezsp *ezsp, int length) {
  EzspIncomingMessageHandlerResponse *response = (EzspIncomingMessageHandlerResponse *)ezsp->input;
  int sourceShortAddress = response->sender[0] | response->sender[1] << 8;
  CommsHub *ch = &data->ch;
  ChDevice *device = ChGetDeviceByShortAddress(ch, sourceShortAddress);
  if (device) {
    EzspApsFrame *apsFrame = (EzspApsFrame *)response->apsFrame;
    EzspApsOption options = apsFrame->options[0] | apsFrame->options[1] << 8;
    int messageLength = response->messageLength;
    void *messageContents = response->messageContents;
    if (options & EZSP_APS_OPTION_FRAGMENT) {
      int fragIndex = apsFrame->groupId[0];
      int fragCount = apsFrame->groupId[1];
      SendLogMessage("Receive APS fragment index=%d count=%d", fragIndex, fragCount);
      if (fragIndex == 0) {
        device->fragIndex = 0;
        device->fragCount = fragCount;
        device->fragLength = 0;
      }
      if (fragIndex == device->fragIndex) {
        if (device->fragLength + messageLength <= sizeof(device->fragBuffer)) {
          memcpy(device->fragBuffer + device->fragLength, messageContents, messageLength);
          device->fragLength += messageLength;
          device->fragIndex++;
          if (device->fragIndex == device->fragCount) {
            messageContents = device->fragBuffer;
            messageLength = device->fragLength;
          } else {
            messageContents = NULL;
          }
          device->flags |= CH_FRAGMENT_ACK;
          EzspApsFrame *apsFrameAck = (EzspApsFrame *)device->fragmentationData;
          *apsFrameAck = *apsFrame;
          apsFrameAck->groupId[1] = 1;  /* extended header ack bitfield */
        }
      }
    }
    if (messageContents) {
      int profileId = apsFrame->profileId[0] | apsFrame->profileId[1] << 8;
      int clusterId = apsFrame->clusterId[0] | apsFrame->clusterId[1] << 8;
      ZigbeeFrameReceived(profileId, clusterId, apsFrame->sourceEndpoint, apsFrame->destinationEndpoint, messageContents, messageLength);
      int encryption = apsFrame->options[0] & EZSP_APS_OPTION_ENCRYPTION;
      unsigned char gbcsMsg[1200];
      int gbcsMsgLen = ChReceiveZigbeeApsFrame(ch, device, encryption, profileId, clusterId, apsFrame->sourceEndpoint, apsFrame->destinationEndpoint, messageContents, messageLength, gbcsMsg);
      if (gbcsMsgLen) {
        SendGbcsMessageLog(gbcsMsg, gbcsMsgLen);
        SendGbcsMessageToGfi(gbcsMsg, gbcsMsgLen);
      }
    }
  }
}

static void ReadEzspSendUnicast(MainData *data, const void *frame, int length) {
  const EzspSendUnicastResponse *x = (const EzspSendUnicastResponse *)frame;
  if (length >= sizeof(*x)) {
    if (x->status == EZSP_SUCCESS) {
      data->ezspLastSequence = x->sequence;
    } else {
      SendLogMessage("EzspSendUnicast status=%u", x->status);
    }
  }
}

static void ReadEzspGenerateCbkeKeys283k1(Ezsp *ezsp, int length) {
  if (length > 1) {
    EzspStatus status = ezsp->input[1];
    if (status != EZSP_OPERATION_IN_PROGRESS) {
      mainData.ch.zke.state = ZIGBEE_SEND_TERMINATE_KEY_ESTABLISHMENT;
      SendLogMessage("EzspGenerateCbkeKeys283k1: status=%d", status);  /* TOREMOVE */
    }
  }
}

static void ReadEzspCalculateSmacs283k1(Ezsp *ezsp, int length) {
  if (length > 1) {
    EzspStatus status = ezsp->input[1];
    if (status != EZSP_OPERATION_IN_PROGRESS) {
      mainData.ch.zke.state = ZIGBEE_SEND_TERMINATE_KEY_ESTABLISHMENT;
      SendLogMessage("EzspCalculateSmacs283k1: status=%d", status);  /* TOREMOVE */
    }
  }
}

static void ReadEzspGenerateCbkeKeysHandler283k1(Ezsp *ezsp, const void *frame, int length) {
  if (length >= 1 + 1 + ZIGBEE_CBKE_SUITE2_QE_SIZE) {
    for (int i = 0; i < ZIGBEE_CBKE_SUITE2_QE_SIZE; i++) {
      mainData.ch.zke.myEphemeralPublicKey[i] = ((char *)frame)[2 + i];
    }
    mainData.ch.zke.state = ZIGBEE_SEND_EPHEMERAL_DATA_RESPONSE;
  }
}

static void ReadEzspCalculateSmacsHandler283k1(Ezsp *ezsp, const void *frame, int length) {
  if (length >= 1 + 1 + ZIGBEE_CBKE_SUITE2_MAC_SIZE + ZIGBEE_CBKE_SUITE2_MAC_SIZE && ((char *)frame)[1] == 0) {
    for (int i = 0; i < ZIGBEE_CBKE_SUITE2_MAC_SIZE; i++) {
      mainData.ch.zke.initiatorMac[i] = ((char *)frame)[2 + i];
    }
    for (int i = 0; i < ZIGBEE_CBKE_SUITE2_MAC_SIZE; i++) {
      mainData.ch.zke.responderMac[i] = ((char *)frame)[2 + ZIGBEE_CBKE_SUITE2_MAC_SIZE + i];
    }
    mainData.ch.zke.state = ZIGBEE_SEND_CONFIRM_KEY_DATA_RESPONSE;
  }
}

typedef struct {
  char bytes[8];
} Id64;

static Id64 SwapId64(const void *x) {
  Id64 y = {
    ((char *)x)[7],
    ((char *)x)[6],
    ((char *)x)[5],
    ((char *)x)[4],
    ((char *)x)[3],
    ((char *)x)[2],
    ((char *)x)[1],
    ((char *)x)[0],
  };
  return y;
}

static void ReadEzspClearTemporaryDataMaybeStoreLinkKey283k1(Ezsp *ezsp, const void *frame, int length) {
  if (length == 2) {
    Id64 address = SwapId64(mainData.ch.devices[0].extendedAddress);
    EzspFindKeyTableEntry(ezsp, &address, 1);
  }
}

static void ReadEzspFindKeyTableEntry(Ezsp *ezsp, const void *frame, int length) {
  if (length == 2) {
    int index = ((unsigned char *)frame)[1];
    if (index != 0xFF) {
      EzspGetKeyTableEntry(ezsp, index);
    }
  }
}

static void ReadEzspGetKeyTableEntry(Ezsp *ezsp, const void *frame, int length) {
  if (1) {
    int status = ((unsigned char *)frame)[1];
    int bitmask = ((unsigned char *)frame)[2] | ((unsigned char *)frame)[3] << 8;
    int type = ((unsigned char *)frame)[4];
    char *key = (char *)frame + 5;
    char *outgoingFrameCounter = (char *)frame + 21;
    char *incomingFrameCounter = (char *)frame + 25;
    int sequenceNumber = ((unsigned char *)frame)[29];
    unsigned char *partnerEui64 = (unsigned char *)frame + 30;
    Id64 id = SwapId64(partnerEui64);
    if (status == 0 && memcmp(&id, mainData.ch.devices[0].extendedAddress, sizeof(id)) == 0) {
      memcpy(mainData.ch.devices[0].cbkeKey, key, sizeof(mainData.ch.devices[0].cbkeKey));
      SendWebsocketChDevice(&mainData.ch.devices[0]);
      SendLogMessage("CBKE Key %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                     mainData.ch.devices[0].cbkeKey[0],
                     mainData.ch.devices[0].cbkeKey[1],
                     mainData.ch.devices[0].cbkeKey[2],
                     mainData.ch.devices[0].cbkeKey[3],
                     mainData.ch.devices[0].cbkeKey[4],
                     mainData.ch.devices[0].cbkeKey[5],
                     mainData.ch.devices[0].cbkeKey[6],
                     mainData.ch.devices[0].cbkeKey[7],
                     mainData.ch.devices[0].cbkeKey[8],
                     mainData.ch.devices[0].cbkeKey[9],
                     mainData.ch.devices[0].cbkeKey[10],
                     mainData.ch.devices[0].cbkeKey[11],
                     mainData.ch.devices[0].cbkeKey[12],
                     mainData.ch.devices[0].cbkeKey[13],
                     mainData.ch.devices[0].cbkeKey[14],
                     mainData.ch.devices[0].cbkeKey[15]);
    }
  }
  mainData.ch.zke.state = ZIGBEE_WAIT_INITIATE_KEY_ESTABLISHMENT_REQUEST;
}

static void ReadEzspMessageSentHandler(Ezsp *ezsp, const void *frame, int length) {
  const EzspMessageSentHandlerResponse *x = (const EzspMessageSentHandlerResponse *)frame;
  if (length >= sizeof(*x)) {
    int destination = x->destination[0] | x->destination[1] << 8;
    int sequenceNumber = mainData.ezspLastSequence;  /* APS counter */
    int error = x->status;
    //SendLogMessage("EzspMessageSentHandler status=%u destination=%Xh counter=%u", x->status, destination, sequenceNumber);
    ChZigbeeFrameSent(&mainData.ch, destination, sequenceNumber, error);
  }
}

static void ReadEzspChildJoinHandler(Ezsp *ezsp, const void *frame, int length) {
#if 0
  if (length == 14) {
    //int index = ((unsigned char *)frame)[1];
    int joining = ((unsigned char *)frame)[2];
    int childId = ((unsigned char *)frame)[3] | ((unsigned char *)frame)[4] << 8;
    unsigned char *childEui64 = (unsigned char *)frame + 5;
    //int type = ((unsigned char *)frame)[13];

    ChDevice *device = ChGetDeviceByZigbeeExtendedAddress(&mainData.ch, childEui64);
    if (device) {
      if (joining) {
        device->shortAddress = childId;
      } else {
        device->shortAddress = 0;
        SendLogMessage("Leave (%02X%02X%02X%02X%02X%02X%02X%02X)",
                       childEui64[7], childEui64[6], childEui64[5], childEui64[4],
                       childEui64[3], childEui64[2], childEui64[1], childEui64[0]);
      }
      //SendInfo();
    }
  }
#endif
}

static void ReadEzspTrustCenterJoinHandler(Ezsp *ezsp, const void *frame, int length) {
  if (length == 15) {
    int newNodeId = ((unsigned char *)frame)[1] | ((unsigned char *)frame)[2] << 8;
    unsigned char *newNodeEui64 = (unsigned char *)frame + 3;
    EzspDeviceUpdate status = ((unsigned char *)frame)[11];
    //int policyDecision = ((unsigned char *)frame)[12];
    //int parentOfNewNodeId = ((unsigned char *)frame)[13] | ((unsigned char *)frame)[14] << 8;

    ChDevice *device = ChGetDeviceByZigbeeExtendedAddress(&mainData.ch, newNodeEui64);

    const char *command = "Trust Center Join Handler";
    if (status == EZSP_SECURED_REJOIN) {
      command = "Rejoin Request";
      if (device) {
        device->shortAddress = newNodeId;
        SendWebsocketChDevice(device);
      }
    } else if (status == EZSP_UNSECURED_JOIN) {
      command = "Association Request";
      if (device) {
        device->shortAddress = newNodeId;
        SendWebsocketChDevice(device);
      }
    } else if (status == EZSP_DEVICE_LEFT) {
      command = "Leave";
      if (device) {
        device->shortAddress = 0;
        SendWebsocketChDevice(device);
      }
    }
    SendLogMessage("%s %02X%02X%02X%02X%02X%02X%02X%02X %02X%02X",
                   command,
                   newNodeEui64[7], newNodeEui64[6], newNodeEui64[5], newNodeEui64[4],
                   newNodeEui64[3], newNodeEui64[2], newNodeEui64[1], newNodeEui64[0],
                   newNodeId >> 8, newNodeId & 0xFF);
  }
}

static void ReceiveEzspGetCertificate283k1(Ezsp *ezsp, const unsigned char *frame, int length, CommsHub *ch) {
  if (length == 76 && frame[1] == 0) {  /* status == success */
    for (int i = 0; i < ZIGBEE_CBKE_SUITE2_CERT_SIZE; i++) {
      ch->zke.myCertificate[i] = frame[2 + i];
    }
  } else {
    SendLogMessage("ReceiveEzspGetCertificate283k1: length=%d status=%d", length, frame[1]);
  }
}

static int ReadEzsp(MainData *d, SerialPort *s, Ezsp *ezsp) {
  DWORD bytesRead;
  if (!GetOverlappedResult(s->handle, &s->overlapped, &bytesRead, FALSE)) {
    SendLogMessage("Error: ReadEzsp GetOverlappedResult");
    return 0;
  }
  ezsp->input_head += (unsigned char)bytesRead;
  int length;
  while ((length = EzspGetResponse(ezsp)) > 0) {
    switch (ezsp->input[0]) {  /* frame id */

    /* TODO: 08:00:52.882 EZSP response: 80 42 8E A8 */

    case EZSP_INCOMING_MESSAGE_HANDLER:
      ReadEzspIncomingMessageHandler(d, ezsp, length);
      break;
    case EZSP_SEND_UNICAST:
      ReadEzspSendUnicast(d, ezsp->input, length);
      /* TODO */
      break;
    case EZSP_MESSAGE_SENT_HANDLER:
      ReadEzspMessageSentHandler(ezsp, ezsp->input, length);
      break;

    /* Certificate Based Key Establishment (CBKE) */
    case EZSP_GENERATE_CBKE_KEYS_283K1:
      ReadEzspGenerateCbkeKeys283k1(ezsp, length);
      break;
    case EZSP_GENERATE_CBKE_KEYS_HANDLER_283K1:
      ReadEzspGenerateCbkeKeysHandler283k1(ezsp, ezsp->input, length);
      break;
    case EZSP_CALCULATE_SMACS_283K1:
      ReadEzspCalculateSmacs283k1(ezsp, length);
      break;
    case EZSP_CALCULATE_SMACS_HANDLER_283K1:
      ReadEzspCalculateSmacsHandler283k1(ezsp, ezsp->input, length);
      break;
    case EZSP_CLEAR_TEMPORARY_DATA_MAYBE_STORE_LINK_KEY_283K1:
      ReadEzspClearTemporaryDataMaybeStoreLinkKey283k1(ezsp, ezsp->input, length);
      break;
    case EZSP_FIND_KEY_TABLE_ENTRY:
      ReadEzspFindKeyTableEntry(ezsp, ezsp->input, length);
    case EZSP_GET_KEY_TABLE_ENTRY:
      ReadEzspGetKeyTableEntry(ezsp, ezsp->input, length);
      break;

    case EZSP_CHILD_JOIN_HANDLER:
      ReadEzspChildJoinHandler(ezsp, ezsp->input, length);
      break;
    case EZSP_TRUST_CENTER_JOIN_HANDLER:
      ReadEzspTrustCenterJoinHandler(ezsp, ezsp->input, length);

    case EZSP_STACK_STATUS_HANDLER:
      if (length == 2) {
        int status = ezsp->input[1];
        SetStatus(status == EZSP_NETWORK_UP);
        if (status != EZSP_NETWORK_UP) {
          CloseSerialPort(&mainData.serialPort);
          ezsp->output_head = 0;
        }
      }
      break;

    /* Network scans */
    case EZSP_NETWORK_FOUND_HANDLER:
      if (length == 17) {
        int channel = ezsp->input[1];
        int panId = ezsp->input[2] | ezsp->input[3] << 8;
        char *extendedPanId = &ezsp->input[4];
        int allowJoin = ezsp->input[12];
        int stackProfile = ezsp->input[13];
        //int nwkUpdateId = ezsp->input[14];
        //int lqi = ezsp->input[15];
        int rssi = (signed char)ezsp->input[16];
        SendActiveScanResult(channel, panId, extendedPanId, allowJoin, stackProfile, rssi);
      }
      break;
    //case EZSP_SCAN_COMPLETE_HANDLER:
      //SendScanComplete();
      //break;

    /* Initialisation sequence */
    case EZSP_VERSION:
      if (1) {
        ezspConfigValueIndex = 0;
        int id = ezspConfigValues[ezspConfigValueIndex];
        int value = ezspConfigValues[ezspConfigValueIndex + 1];
        EzspSetConfigurationValue(ezsp, id, value);
      }
      break;
    case EZSP_SET_CONFIGURATION_VALUE:
      ezspConfigValueIndex += 2;
      if (ezspConfigValueIndex < sizeof(ezspConfigValues)) {
        int id = ezspConfigValues[ezspConfigValueIndex];
        int value = ezspConfigValues[ezspConfigValueIndex + 1];
        EzspSetConfigurationValue(ezsp, id, value);
      } else {
        EzspGetEui64(ezsp);
      }
      break;
    case EZSP_GET_EUI64:
      for (int i = 0; i < 8; i++) {
        mainData.ch.gpfId[i] = ezsp->input[8 - i];
      }
      SendChSettings(&mainData.ch);
      EzspGetCertificate283k1(ezsp);
      break;
    case EZSP_GET_CERTIFICATE283K1:
      ReceiveEzspGetCertificate283k1(ezsp, ezsp->input, length, &mainData.ch);
      EzspClearKeyTable(ezsp);
      break;
    case EZSP_CLEAR_KEY_TABLE:
      if (1) {
        int index = 2;
        int isLinkKey = 1;
        char address[8];
        for (int i = 0; i < 8; i++) {
          address[i] = mainData.ch.devices[0].extendedAddress[7 - i];
        }
        EzspSetKeyTableEntry(ezsp, index, address, isLinkKey, mainData.ch.devices[0].preconfiguredKey);
      }
      break;
    case EZSP_SET_KEY_TABLE_ENTRY:
      EzspSetInitialSecurityState(ezsp, mainData.ch.networkKey);
      break;
    case EZSP_SET_INITIAL_SECURITY_STATE:
      EzspPermitJoining(ezsp, 0xFF);
      break;
    case EZSP_PERMIT_JOINING: {
      mainData.ch.panId[0] = 0xA1;  /* TODO: random PAN ID */
      mainData.ch.panId[1] = 0xB2;
      char panId[2] = { mainData.ch.panId[1], mainData.ch.panId[0] };
      char extendedPanId[8] = {
        mainData.ch.gpfId[7], mainData.ch.gpfId[6], mainData.ch.gpfId[5],
        mainData.ch.gpfId[4], mainData.ch.gpfId[3], mainData.ch.gpfId[2],
        mainData.ch.gpfId[1], mainData.ch.gpfId[0],
      };
      EzspFormNetwork(ezsp, extendedPanId, panId, mainData.ch.channel);
    } break;
    case EZSP_FORM_NETWORK:
      //EzspClearTemporaryDataMaybeStoreLinkKey283k1(ezsp, 0);
      break;

      default: {
        char buf[512];
        int n = sprintf(buf, "EZSP response:");
        for (int i = 0; i < length; i++) {
          n += sprintf(buf + n, " %02X", ezsp->input[i]);
        }
        SendLogMessage(buf);
      } break;
    }
  }

  if (!ReadFile(s->handle, ezsp->input + ezsp->input_head, sizeof(ezsp->input) - ezsp->input_head, NULL, &s->overlapped)) {
    //printf("ReadFile\n");
    //return 0;
  }

  return 1;
}

static void WriteEzsp(MainData *data, Ezsp *ezsp) {
  if (data->state & START) {
    data->state &= ~START;
    if (OpenSerialPort(&data->serialPort)) {
      EzspReset(ezsp);
    } else {
      SendLogMessage("Error opening serial port %s", data->serialPort.name);
    }
  } else if (!ezsp->busy) {
    CommsHub *ch = &data->ch;
    ChDevice *device = &ch->devices[0];
    if (device->flags & CH_FRAGMENT_ACK) {
      char sender[2] = { (char)device->shortAddress, (char)(device->shortAddress >> 8) };
      EzspApsFrame *apsFrame = (EzspApsFrame *)device->fragmentationData;
      EzspSendReply(ezsp, sender, apsFrame, 0, NULL);
      device->flags &= ~CH_FRAGMENT_ACK;
    } else {
      ZigbeePacketInfo info;
      char packet[256];  // TODO: [GBCS_ZIGBEE_FRAGMENT_DATA_MAX_SIZE];
      int length = ChGetZigbeePacketToSend(&data->ch, packet, &info);
      if (length) {
        ZigbeeSend(&info, length, packet);
      } else if (data->scan) {
        int duration = 5;  /* takes about 8 seconds to scan all channels */
        EzspScan(&mainData.ezsp, EZSP_ACTIVE_SCAN, EZSP_ALL_CHANNELS, duration);
        data->scan = 0;
      } else {
        ZigbeeKeyEstablishment *zke = &mainData.ch.zke;
        switch (zke->state) {
        case ZIGBEE_GENERATE_EPHEMERAL_DATA:
          EzspGenerateCbkeKeys283k1(ezsp);
          zke->state = ZIGBEE_GENERATING_EPHEMERAL_DATA;
          break;
        case ZIGBEE_CALCULATE_SMAC:
          EzspCalculateSmacs283k1(ezsp, 0, zke->partnerCertificate, zke->partnerEphemeralPublicKey);
          zke->state = ZIGBEE_CALCULATING_SMAC;
          break;
        case ZIGBEE_STORE_LINK_KEY:
          EzspClearTemporaryDataMaybeStoreLinkKey283k1(ezsp, 1);
          zke->state = ZIGBEE_STORING_LINK_KEY;
          break;
        }
      }
    }
  }

  if (ezsp->output_head > 0) {
#ifdef _WIN32
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    DWORD bytesWritten;
    for (unsigned n = 0; n < ezsp->output_head; n += bytesWritten) {
      if (!WriteFile(mainData.serialPort.handle, ezsp->output + n, ezsp->output_head - n, &bytesWritten, &overlapped)) {
        if (!GetOverlappedResult(mainData.serialPort.handle, &overlapped, &bytesWritten, TRUE)) {
          SendLogMessage("Error: WriteFile GetOverlappedResult");
          CloseSerialPort(&mainData.serialPort);
          break;
        }
      }
    }
    CloseHandle(overlapped.hEvent);
#endif
    ezsp->output_head = 0;
  }
}

int main(int argc, char **argv) {
  char *configfile = "config.txt";
  if (argc == 2) {
    configfile = argv[1];
  }
  LoadConfig(&mainData, configfile);

#ifdef _WIN32
  {
    WSADATA wsaData;
    WSAStartup(0x0202, &wsaData);
  }
#endif

#ifdef _WIN32
  SOCKET httpServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (httpServerSocket == INVALID_SOCKET) {
    fprintf(stderr, "%s: error: socket\n", argv[0]);
    return 1;
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(23456);
  if (bind(httpServerSocket, (struct sockaddr *)&addr, sizeof(addr))) {
    closesocket(httpServerSocket);
    return 1;
  }

  if (listen(httpServerSocket, 10)) {
    closesocket(httpServerSocket);
    return 1;
  }

  WSAEVENT event = WSACreateEvent();
  WSAEventSelect(httpServerSocket, event, FD_ACCEPT | FD_CLOSE);
  handles[handleCount++] = event;
#endif

  for (;;) {
    WriteEzsp(&mainData, &mainData.ezsp);

#ifdef _WIN32
    DWORD n = WaitForMultipleObjects(handleCount, handles, FALSE, 10000);  // INFINITE);
    if (n >= WAIT_OBJECT_0 && n < WAIT_OBJECT_0 + handleCount) {
      int i = n - WAIT_OBJECT_0;
      if (i > 0 && i < 1 + httpClientCount) {  /* HTTP client socket */
        WSAResetEvent(handles[i]);
        int j = i - 1;
        SOCKET s = httpSockets[j];
        HttpBuffer *h = &httpClientBuffers[j];
        if (h->tail > 0) {
          h->head -= h->tail;
          memmove(h->buffer, h->buffer + h->tail, h->head);
          h->tail = 0;
        }
        int n = recv(s, h->buffer + h->head, sizeof(h->buffer) - h->head, 0);
        if (n > 0) {
          h->head += n;
          if (h->state == SOCKET_CONNECTED && h->head > 1) {
            if (h->buffer[1] == 'E') {  /* "GET..." */
              h->state = SOCKET_HTTP;
            } else if (h->buffer[1] == 'B') { /* "GBCS..." */
              h->state = SOCKET_GFI;
            } else {
              n = -1;
            }
          }

          if (h->state == SOCKET_HTTP) {
            while (ParseHttpRequest(h)) {
              char *secWebSocketKey;
              ParseHttpHeaders(h, &secWebSocketKey);
              if (secWebSocketKey) {
                char httpResponse[128];
                int x = setHttpResponse(httpResponse, secWebSocketKey);
                int y = send(s, httpResponse, x, 0);
                h->state = SOCKET_WEBSOCKET;
                break;
              }
            }
          }
          if (h->state == SOCKET_WEBSOCKET) {
            do {
              n = ReadWebsocketData(h);
            } while (n > 0);
            if (n == 0) {
              n = 1;
            }
          } else if (h->state == SOCKET_GFI) {
            do {
              n = ReceiveGfiData(h);
            } while (n > 0);
            if (n == 0) {
              n = 1;
            }
          }
        }
        if (n <= 0) {
          closesocket(s);
          WSACloseEvent(handles[i]);
          handles[i] = handles[1 + httpClientCount - 1];
          handles[1 + httpClientCount - 1] = handles[1 + httpClientCount + mainData.serialPortCount - 1];
          httpClientBuffers[j] = httpClientBuffers[httpClientCount - 1];
          httpClientCount--;
          /* TODO: update serialPorts */
          handleCount--;
        }
      } else if (i == 0) {  /* HTTP server socket */
        WSAResetEvent(handles[i]);
        SOCKET s = accept(httpServerSocket, NULL, NULL);
        if (httpClientCount < MAX_HTTP_CLIENTS) {
          WSAEVENT e = WSACreateEvent();
          WSAEventSelect(s, e, FD_READ | FD_CLOSE);
          handles[1 + httpClientCount + mainData.serialPortCount] = handles[1 + httpClientCount];
          handles[1 + httpClientCount] = e;
          httpSockets[httpClientCount] = s;
          HttpInit(&httpClientBuffers[httpClientCount]);
          httpClientCount++;
          handleCount++;
        } else {
          SendLogMessage("Error: too many HTTP clients");
          closesocket(s);
        }
      } else {  /* serial port */
        ReadEzsp(&mainData, &mainData.serialPort, &mainData.ezsp);
      }
    }
#endif  /* _WIN32 */
  }

  return 0;
}

/* Zigbee */

int ZigbeeGetCurrentUtcTime(void) {
  return (int)time(0) - 946684800;  /* seconds since 2000-01-01 00:00:00 UTC */
}
