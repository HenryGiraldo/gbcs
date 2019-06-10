/*
 * gfi.c
 *
 * Conversion of GBCS messages from/to the GFI text format described in
 * https://www.smartdcc.co.uk/media/3089/gfi-segmented-processing.pdf
 *
 * This is free and unencumbered software released into the public domain.
 * See the UNLICENSE file or https://unlicense.org for more details.
 *
 * Example of the GFI text format of a GBCS message:
 * GBCS:DATA#0:72:DD000000000000401100000000DF090200000000000003EB0800DB1234567890A00890B3D51F30010000000200210CDA200003EB0000010001020000F4E3A029790221B3B6549478\r\n
 */

#include "gfi.h"

/* TOREMOVE */
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>

int GfiToGbcs(const void *gfi, int gfiLen, void *gbcs, int *gbcsLen) {
  int gfiBytesConsumed = 0;
  const char *in = (char *)gfi;
  unsigned char *out = (unsigned char *)gbcs;
  *gbcsLen = 0;
  if (gfiLen > 15) {
    int length = 0, offset = 0;
    sscanf(in, "GBCS:DATA#%*d:%d:%n", &length, &offset);
    if (offset + length * 2 + 2 <= gfiLen) {
      for (int i = 0; i < length; i++) {
        char s[3] = { in[offset + i * 2], in[offset + i * 2 + 1], '\0' };
        out[i] = (unsigned char)strtoul(s, NULL, 16);
      }
      *gbcsLen = length;
      gfiBytesConsumed = offset + length * 2 + 2;
    }
  }
  return gfiBytesConsumed;
}

int GfiFromGbcs(void *gfi, int gfiMaxLen, const void *gbcs, int gbcsLen) {
  char *p = gfi;
  int n = 0;
  p[n++] = 'G';
  p[n++] = 'B';
  p[n++] = 'C';
  p[n++] = 'S';
  p[n++] = ':';
  p[n++] = 'D';
  p[n++] = 'A';
  p[n++] = 'T';
  p[n++] = 'A';
  p[n++] = '#';
  p[n++] = '0';
  p[n++] = ':';
  if (gbcsLen > 9) {
    if (gbcsLen > 99) {
      if (gbcsLen > 999) {
        p[n++] = '0' + gbcsLen / 1000 % 10;
      }
      p[n++] = '0' + gbcsLen / 100 % 10;
    }
    p[n++] = '0' + gbcsLen / 10 % 10;
  }
  p[n++] = '0' + gbcsLen % 10;
  p[n++] = ':';
  for (int i = 0; i < gbcsLen; i++) {
    const char h[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    unsigned char x = ((unsigned char *)gbcs)[i];
    p[n++] = h[x >> 4];
    p[n++] = h[x & 15];
  }
  p[n++] = '\r';
  p[n++] = '\n';

  return n;
}
