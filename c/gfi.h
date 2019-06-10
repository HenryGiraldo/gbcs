/*
 * gfi.h
 *
 * Conversion of GBCS messages from/to the GFI text format described in
 * https://www.smartdcc.co.uk/media/3089/gfi-segmented-processing.pdf
 *
 * This is free and unencumbered software released into the public domain.
 * See the UNLICENSE file or https://unlicense.org for more details.
 *
 * Example of the format of the GFI messages:
 * GBCS:DATA#0:72:DD000000000000401100000000DF090200000000000003EB0800DB1234567890A00890B3D51F30010000000200210CDA200003EB0000010001020000F4E3A029790221B3B6549478\r\n
 */

enum { GFI_MESSAGE_MAX_SIZE = 30 + 2 * 1200 };

int GfiToGbcs(const void *gfi, int gfiLen, void *gbcs, int *gbcsLen);
int GfiFromGbcs(void *gfi, int gfiMaxLen, const void *gbcs, int gbcsLen);
