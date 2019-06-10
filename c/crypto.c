/*
 * crypto.c: cryptographic algorithms
 *
 * This is free and unencumbered software released into the public domain.
 * See the UNLICENSE file or https://unlicense.org for more details.
 */

#include "crypto.h"

/*
 * aes.h: Advanced Encryption Standard (AES) algorithm
 *
 * https://github.com/andrebdo/c-crumbs/blob/master/aes.h
 *
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to UNLICENSE or http://unlicense.org
 */

/*
 * Implements the AES encryption algorithm for 128-bit keys (AES-128).
 *
 * References:
 * [AES] Advanced Encryption Standard (AES), FIPS 197, Nov 26 2001.
 *       http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */

/*
 * Multiply the binary polynomial b with the polynomial x.
 * [AES] 4.2.1 Multiplication by x.
 */
static unsigned char aes_xtime(unsigned char b) {
  unsigned char bx = b << 1;
  if (b & 0x80) {
    bx ^= 0x1b;
  }
  return bx;
}

/*
 * Performs the AES cipher transform (encryption) for Nk=4 (AES-128).
 * output: pointer to 64 bytes (128 bits) of memory to store the ciphertext
 * intput: pointer to 64 bytes (128 bits) of memory with the plaintext
 * key: pointer to 64 bytes (128 bits) of memory with the cipher key
 */
static void aes_encrypt(void *output, const void *input, const void *key) {
  /* [AES] 5.1.1 SubBytes() transformation */
  const unsigned char sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
  };
  unsigned char *state;
  unsigned char key_schedule[16];
  unsigned char a, b, c, d;
  unsigned char a1, a2, a3, b1, b2, b3, c1, c2, c3, d1, d2, d3;
  unsigned char rcon;
  int i, round;

  /* [AES] 5.1.4 AddRoundKey() transformation (initial round key addition) */
  state = (unsigned char *)output;
  for (i = 0; i < 16; i++) {
    key_schedule[i] = ((unsigned char *)key)[i];
    state[i] = ((unsigned char *)input)[i] ^ key_schedule[i];
  }

  rcon = 1;
  for (round = 1; round <= 10; round++) {
    /* [AES] 5.1.1 SubBytes() transformation */
    for (i = 0; i < 16; i++) {
      state[i] = sbox[state[i]];
    }

    /* [AES] 5.1.2 ShiftRows() transformation */
    a = state[1]; b = state[5]; c = state[9]; d = state[13];
    state[1] = b; state[5] = c; state[9] = d; state[13] = a;
    a = state[2]; b = state[6]; c = state[10]; d = state[14];
    state[2] = c; state[6] = d; state[10] = a; state[14] = b;
    a = state[3]; b = state[7]; c = state[11]; d = state[15];
    state[3] = d; state[7] = a; state[11] = b; state[15] = c;

    /* [AES] 5.1.3 MixColumns() transformation */
    if (round < 10) {
      for (i = 0; i < 16; i += 4) {
        a1 = state[i + 0]; a2 = aes_xtime(a1); a3 = a1 ^ a2;
        b1 = state[i + 1]; b2 = aes_xtime(b1); b3 = b1 ^ b2;
        c1 = state[i + 2]; c2 = aes_xtime(c1); c3 = c1 ^ c2;
        d1 = state[i + 3]; d2 = aes_xtime(d1); d3 = d1 ^ d2;
        state[i + 0] = a2 ^ b3 ^ c1 ^ d1;
        state[i + 1] = a1 ^ b2 ^ c3 ^ d1;
        state[i + 2] = a1 ^ b1 ^ c2 ^ d3;
        state[i + 3] = a3 ^ b1 ^ c1 ^ d2;
      }
    }

    /* [AES] 5.2 Key expansion */
    key_schedule[0] ^= rcon;
    rcon = aes_xtime(rcon);
    key_schedule[0] ^= sbox[key_schedule[13]];
    key_schedule[1] ^= sbox[key_schedule[14]];
    key_schedule[2] ^= sbox[key_schedule[15]];
    key_schedule[3] ^= sbox[key_schedule[12]];
    for (i = 4; i < 16; i++) {
      key_schedule[i] ^= key_schedule[i - 4];
    }

    /* [AES] 5.1.4 AddRoundKey() transformation */
    for (i = 0; i < 16; i++) {
      state[i] ^= key_schedule[i];
    }
  }
}

/*
 * aes-mmo.h: AES Matyas-Meyer-Oseas (AES-MMO) hash function
 *
 * https://github.com/andrebdo/c-crumbs/blob/master/aes-mmo.h
 *
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to UNLICENSE or http://unlicense.org
 */

/*
 * Computes the Matyas-Meyer-Oseas hash function based on the AES-128 block cipher.
 *
 * Uses the aes_encrypt function in aes.h, so you need to include that too:
 * #include "aes.h"
 * #include "aes-mmo.h"
 *
 * digest: pointer to 16 bytes (128 bits) of memory to store the message digest output
 * message: input message
 * length: number of bytes of the input message
 *
 * Reference:
 * ZigBee specification, document 05-3474-21, Aug 2015,
 * section B.6 Block-Cipher-Based Cryptographic Hash Function.
 */
static void aes_mmo(void *digest, const void *message, int length) {
  int i, r;
  unsigned char p[16];

  /* Hash0 = 0^(8n)  n-octet all-zero bit string */
  for (i = 0; i < 16; i++) {
    ((char *)digest)[i] = 0;
  }

  /* Hashj = E(Hashj-1,Mj) xor Mj */
  for (r = 0; r <= length - 16; r += 16) {
    aes_encrypt(digest, (char *)message + r, digest);
    for (i = 0; i < 16; i++) {
      ((char *)digest)[i] ^= ((char *)message)[r + i];
    }
  }

  /* Build and process the final padded block(s) */
  r = length & 15;
  for (i = 0; i < r; i++) {
    p[i] = ((char *)message)[(length & ~15) + i];
  }
  p[r++] = 0x80;
  if ((length < 8192 && r > 14) || (length >= 8192 && r > 10)) {
    /* The first of 2 padded blocks */
    for (i = r; i < 16; i++) {
      p[i] = 0;
    }
    aes_encrypt(digest, p, digest);
    for (i = 0; i < 16; i++) {
      ((char *)digest)[i] ^= p[i];
    }
    r = 0;
  }
  /* The final padded block with the length in bits */
  if (length < 8192) {
    for (i = r; i < 14; i++) {
      p[i] = 0;
    }
    p[14] = length >> 5;
    p[15] = length << 3;
  } else {
    for (i = r; i < 10; i++) {
      p[i] = 0;
    }
    p[10] = length >> 21;
    p[11] = length >> 13;
    p[12] = length >> 5;
    p[13] = length << 3;
    p[14] = 0;
    p[15] = 0;
  }
  aes_encrypt(digest, p, digest);
  for (i = 0; i < 16; i++) {
    ((char *)digest)[i] ^= p[i];
  }
}

/*
 * base64.h: base 64 data encoding
 *
 * https://github.com/andrebdo/c-crumbs/blob/master/base64.h
 *
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to UNLICENSE or http://unlicense.org
 */

/*
 * Encodes a sequence of bytes into base 64 format.
 * output: pointer to (length+2)/3*4 bytes of memory to store the base 64 encoded data
 * input: pointer to the input data
 * length: number of bytes of the input data
 * Returns the number of bytes stored in output, always (length+2)/3*4.
 *
 * References:
 * [RFC4648] The Base16, Base32, and Base64 Data Encodings.
 */
static int base64_encode(void *output, const void *input, int length) {
  const char alphabet[64] = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M',
    'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','l','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z',
    '0','1','2','3','4','5','6','7','8','9','+','/',
  };
  unsigned char a, b, c;
  int i, n;

  n = 0;
  for (i = 0; i <= length - 3; i += 3) {
    a = ((unsigned char *)input)[i];
    b = ((unsigned char *)input)[i + 1];
    c = ((unsigned char *)input)[i + 2];
    ((unsigned char *)output)[n++] = alphabet[(a >> 2) & 63];
    ((unsigned char *)output)[n++] = alphabet[(a << 4 | b >> 4) & 63];
    ((unsigned char *)output)[n++] = alphabet[(b << 2 | c >> 6) & 63];
    ((unsigned char *)output)[n++] = alphabet[c & 63];
  }
  if (i + 2 == length) {
    a = ((unsigned char *)input)[i];
    b = ((unsigned char *)input)[i + 1];
    ((unsigned char *)output)[n++] = alphabet[(a >> 2) & 63];
    ((unsigned char *)output)[n++] = alphabet[(a << 4 | b >> 4) & 63];
    ((unsigned char *)output)[n++] = alphabet[(b << 2) & 63];
    ((unsigned char *)output)[n++] = '=';
  } else if (i + 1 == length) {
    a = ((unsigned char *)input)[i];
    ((unsigned char *)output)[n++] = alphabet[(a >> 2) & 63];
    ((unsigned char *)output)[n++] = alphabet[(a << 4) & 63];
    ((unsigned char *)output)[n++] = '=';
    ((unsigned char *)output)[n++] = '=';
  }

  return n;
}

/*
 * sha1.h: Secure Hash Algorithm 1 (SHA-1)
 *
 * https://github.com/andrebdo/c-crumbs/blob/master/sha1.h
 *
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to UNLICENSE or http://unlicense.org
 */

/*
 * Computes the SHA-1 message digest of a message.
 * digest: pointer to 20 bytes (160 bits) to store the SHA-1 message digest
 * message: pointer to the input message
 * length: number of bytes of the input message
 *
 * References:
 * [SHS] Secure Hash Standard (FIPS PUB 180-4), Aug 2015
 *       http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 */
static void sha1(void *digest, const void *message, int length) {
  unsigned char pad[64];  /* padded block */
  unsigned w[16];  /* message schedule (ring buffer for a total of 80 elements) */
  unsigned h[5];  /* hash value words */
  unsigned a, b, c, d, e;  /* working variables */
  unsigned tmp, ft, kt, wt, wtr;
  unsigned char *m;
  int i, j, t;

  /* [SHS] 5.3 Setting the Initial Hash Value H(0), 5.3.1 SHA-1 */
  h[0] = 0x67452301;
  h[1] = 0xefcdab89;
  h[2] = 0x98badcfe;
  h[3] = 0x10325476;
  h[4] = 0xc3d2e1f0;

  /* [SHS] 6.1.2 SHA-1 Hash Computation */
  for (i = 0; i - 9 < length; i += 64) {  /* min pad = 9 bytes (0x80 + 64-bit length) */
    m = (unsigned char *)message + i;
    if (i > length - 64) {
      /* [SHS] 5.1 Padding the Message, 5.1.1 SHA-1, SHA-224 and SHA-256 */
      for (j = 0; j < length - i; j++) {
        pad[j] = m[j];
      }
      if (i + j == length) {
        pad[j++] = 0x80;
      }
      if (j > 56) {  /* penultimate block */
        while (j < 64) {
          pad[j++] = 0;
        }
      } else {  /* last block */
        while (j < 56) {
          pad[j++] = 0;
        }
        pad[56] = 0;  /* length >> 53; */
        pad[57] = 0;  /* length >> 45; */
        pad[58] = 0;  /* length >> 37; */
        pad[59] = length >> 29;
        pad[60] = length >> 21;
        pad[61] = length >> 13;
        pad[62] = length >> 5;
        pad[63] = length << 3;
      }
      m = pad;
    }

    /*
     * 1. Prepare the message schedule W (part 1):
     * For t = 0 to 15
     *    Wt = M(i)t
     */
    for (t = 0; t < 16; t++) {
      w[t] = m[t*4] << 24 | m[t*4+1] << 16 | m[t*4+2] << 8 | m[t*4+3];
    }

    /* 2. Initialize the five working variables */
    a = h[0];
    b = h[1];
    c = h[2];
    d = h[3];
    e = h[4];

    /* 3. (transform the working variables) */
    for (t = 0; t < 80; t++) {
      /*
       * 1. Prepare the message schedule W (part 2):
       * For t = 16 to 79
       *    Wt = ROTL1(W(t-3) ^ W(t-8) ^ W(t-14) ^ W(t-16)
       */
      wt = w[t & 15];
      wtr = w[(t-3) & 15] ^ w[(t-8) & 15] ^ w[(t-14) & 15] ^ wt;
      w[t & 15] = wtr << 1 | wtr >> 31;

      /*
       * T = ROTL5(a) + ft(b,c,d) + e + Kt + Wt
       * [SHS] 4.1.1 SHA-1 Functions, [SHS] 4.2.1 SHA-1 Constants
       */
      if (t < 20) {
        ft = (b & c) ^ (~b & d);
        kt = 0x5a827999;
      } else if (t < 40) {
        ft = b ^ c ^ d;
        kt = 0x6ed9eba1;
      } else if (t < 60) {
        ft = (b & c) ^ (b & d) ^ (c & d);
        kt = 0x8f1bbcdc;
      } else { /* if (t < 80) */
        ft = b ^ c ^ d;
        kt = 0xca62c1d6;
      }
      tmp = (a << 5 | a >> 27) + ft + e + kt + wt;

      e = d;
      d = c;
      c = b << 30 | b >> 2;
      b = a;
      a = tmp;
    }

    /* 4. Compute the ith intermediate hash value H(i) */
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
  }

  /* Store the resulting 160-bit message digest */
  for (i = 0; i < 5; i++) {
    ((unsigned char *)digest)[i * 4 + 0] = h[i] >> 24;
    ((unsigned char *)digest)[i * 4 + 1] = h[i] >> 16;
    ((unsigned char *)digest)[i * 4 + 2] = h[i] >> 8;
    ((unsigned char *)digest)[i * 4 + 3] = h[i];
  }
}

/*
 * Public functions.
 */

void CryptoAesMmo(void *digest, const void *message, int length) {
  aes_mmo(digest, message, length);
}

int CryptoBase64(void *output, const void *input, int length) {
  return base64_encode(output, input, length);
}

void CryptoSha1(void *digest, const void *message, int length) {
  sha1(digest, message, length);
}
