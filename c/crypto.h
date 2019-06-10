/*
 * crypto.h: cryptographic algorithms
 *
 * This is free and unencumbered software released into the public domain.
 * See the UNLICENSE file or https://unlicense.org for more details.
 */

/*
 * Computes the Matyas-Meyer-Oseas hash function based on the AES-128 block cipher.
 * digest: pointer to 16 bytes (128 bits) of memory to store the message digest output.
 * message: input message.
 * length: number of bytes of the input message.
 */
void CryptoAesMmo(void *digest, const void *message, int length);

/*
 * Encodes a sequence of bytes into base 64 format.
 * output: pointer to (length+2)/3*4 bytes of memory to store the base 64 encoded data
 * input: pointer to the input data
 * length: number of bytes of the input data
 * Returns the number of bytes stored in output, always (length+2)/3*4.
 */
int CryptoBase64(void *output, const void *input, int length);

/*
 * Computes the SHA-1 message digest of a message.
 * digest: pointer to 20 bytes (160 bits) to store the SHA-1 message digest.
 * message: pointer to the input message.
 * length: number of bytes of the input message.
 */
void CryptoSha1(void *digest, const void *message, int length);
