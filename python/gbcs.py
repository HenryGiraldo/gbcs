"""
gbcs.py: Great Britain Companion Specification (GBCS).

Functions to generate and verify GBCS messages.

This is free and unencumbered software released into the public domain.
See the UNLICENSE file or https://unlicense.org for more details.

To use the functions that implement the GBCS criptographic primitives,
you will need libcrypto from OpenSSL.  You can download a precompiled
libcrypto.dll for Windows for example from here:
https://curl.haxx.se/windows/dl-7.65.1/openssl-1.1.1c-win64-mingw.zip
Note that the OpenSSL 1.x license is the following:
https://www.openssl.org/source/license-openssl-ssleay.txt
"""

import ctypes
import hashlib

"""
Values of the CRA Flag of a GBCS message.
Reference: GBCS 7.2.7 Message construction - Grouping Header.
"""
COMMAND = 1
RESPONSE = 2
ALERT = 3


class Entity:
    pass


# CS06 Activate Firmware.
# Reference: GBCS 11.5 CS06 Activate Firmware

def build_cs06_command(originator, recipient, acb, hash, counter):
    """
    Builds a GBCS CS06 command message.
    originator: object with counter, id and dsprvkey attributes of the originator.
    recipient: object with id and kapubkey attributes of the recipient.
    acb: object with kaprvkey attribute of the ACB.
    hash: manufacturerImageHash (32 bytes)
    counter: originatorCounter (int)
    TODO: executionDateTime
    Returns the generated GBCS CS06 command message.
    """
    CS06 = 0x0012  # message code
    payload = asn1_encode(0x30, asn1_encode(4, hash) + build_der_integer(counter));
    message = build_grouping_header(COMMAND, originator.counter, originator.id, recipient.id, CS06, len(payload))
    message += payload
    signature = calculate_signature(message, originator.dsprvkey)
    message += encode_length(len(signature)) + signature
    message += calculate_mac(message, acb.kaprvkey, recipient.kapubkey, 12)
    message = build_mac_header(len(message)) + message
    return message


# Common functions.

def build_mac_header(messagelen):
    """
    Builds the MAC header for a GBCS message with the specified content length.
    messagelen: len(grouping_header) + len(payload) + len(signature) + len(mac).
    Returns the bytes with the generated MAC header.
    Reference: GBCS 7.2.5 Message construction - MAC Header.
    """
    return bytes([0xDD,0,0,0,0,0,0]) + encode_length(messagelen+5) + bytes([0x11,0,0,0,0])


def build_grouping_header(cra_flag, originator_counter, originator_id, recipient_id, message_code, payloadlen):
    """
    Builds the grouping header for a GBCS message.
    cra_flag: value of the CRA Flag (COMMAND, RESPONSE, ALERT).
    originator_counter: 8 bytes with the originator counter.
    originator_id: 8 bytes with the originator identifier.
    recipient_id: 8 bytes with the recipient identifier.
    message_code: value the message code of the GBCS message.
    payloadlen: number of bytes of the payload of the GBCS message.
    Returns the generated grouping header.
    Reference: GBCS 7.2.7 Message construction - Grouping Header.
    """
    b = bytes([0xDF])
    b += bytes([9, cra_flag]) + originator_counter  # transaction-id
    b += bytes([8]) + originator_id  # originator-system-title
    b += bytes([8]) + recipient_id  # recipient-system-title
    b += bytes([0])  # date-time (TODO)
    b += bytes([2, message_code >> 8, message_code & 255])  # other-information (TODO)
    b += encode_length(payloadlen)  # content-length
    return b


def parse(b):
    """
    Parses a GBCS message.
    b: bytes with the GBCS message.
    Returns an object with attributes set to the parsed fields of the GBCS message.
    """
    class Message:
        pass
    m = Message()
    i = 0
    # MAC header.
    if b[i] == 0xDD:
        start = i
        i += 7
        contentlen = b[i]
        i += 1
        if contentlen == 0x82:
            contentlen = b[i] << 8 | b[i+1]
            i += 2
        elif contentlen == 0x81:
            contentlen = b[i]
            i += 1
        m.mac = b[i+contentlen-12:i+contentlen]
        i += 5  # security header
        m.mac_header = b[start:i]
    # Grouping header.
    if b[i] == 0xDF:
        start = i
        m.transaction_id = b[i+1:i+1+10]
        m.cra_flag = b[i+2]
        m.originator_counter = b[i+3:i+3+8]
        m.originator_id = b[i+12:i+12+8]
        m.recipient_id = b[i+21:i+21+8]
        i += 29
        datetimelen = b[i]
        i += 1
        if datetimelen > 0:
            m.datetime = b[i:i+datetimelen]
            i += datetimelen
        otherinfolen = b[i]  # TODO: if otherinfolen > 127
        i += 1
        m.message_code = b[i:i+2]
        i += otherinfolen
        payloadlen = b[i]
        i += 1
        if payloadlen == 0x82:
            payloadlen = b[i] << 8 | payloadlen[i+1]
            i += 2
        elif payloadlen == 0x81:
            payloadlen = b[i]
            i += 1
        m.grouping_header = b[start:i]
        m.payload = b[i:i+payloadlen]
        i += payloadlen
        if i < len(b):
            signaturelen = b[i]
            i += 1
            if signaturelen > 0:
                m.signature = b[i:i+signaturelen]
    return m


def encode_length(value):
    if value < 128:
        return bytes([value])
    elif value < 256:
        return bytes([0x81, value])
    else:
        return bytes([0x82, value >> 8, value & 255])


# ASN.1 DER encoding/decoding.
# References:
# X.680 Abstract Syntax Notation One (ASN.1): Specification of basic notation.
# X.690 ASN.1 encoding rules: BER, CER and DER.

def asn1_encode(tag, contents):
    return bytes([tag]) + encode_length(len(contents)) + contents

def build_der_integer(value):
    b = bytes()
    while value > 255:
        b = bytes([value & 255]) + b
        value = value >> 8
    b = bytes([value]) + b
    if value > 127:
        b = bytes([0]) + b
    return asn1_encode(2, b);


def calculate_mac(message, privatekey, publickey, maclen):
    """
    Calculates the MAC of a GBCS message.
    message: bytes with the GBCS message.
    privatekey: 32-byte key agreement private key of the local peer.
    publickey: 64-byte key agreement public key of the other peer.
    maclen: number of bytes of the MAC to return (12 or 16 in GBCS).
    Returns maclen bytes of the calculated MAC.
    References:
    GBCS 4.3.3.3 Calculating unique Shared Secret Keys for a Remote Party Message Instance.
    GBCS 4.3.3.4 Calculating the Initialization Vector for GCM and GMAC.
    GBCS 6.2.3 Command Cryptographic Protection II.
    """
    m = parse(message)
    # Build the initialization vector (IV).
    iv = m.originator_id + bytes([0,0,0,0])
    # Build the additional authenticated data (AAD).
    aad = bytes([0x11,0,0,0,0,0]) + m.grouping_header + m.payload
    if hasattr(m, 'signature'):
        aad += bytes([len(m.signature)]) + m.signature
    else:
        aad += bytes([0])
    # Derive the shared key.
    z = ecdh(privatekey, publickey)
    algorithm_id = bytes([0x60, 0x85, 0x74, 0x06, 0x08, 0x03, 0x00])
    otherinfo = algorithm_id + m.originator_id + m.transaction_id + m.recipient_id
    key = kdf(z, otherinfo)
    # Calculate the 128-bit (16-byte) MAC.
    mac = gmac(iv, aad, key)
    # Return the requested bytes of the MAC.
    return mac[0:maclen]


def calculate_signature(message, key):
    """
    Calculates the signature of a GBCS message.
    message: bytes with the GBCS message to sign.
    key: 32-byte digital signing private key of the originator.
    Returns the 64-byte signature.
    """
    m = parse(message)
    data = m.grouping_header[1:] + m.payload
    return ecdsa_sign(data, key)


def verify_signature(message, key):
    """
    Verifies the signature of a GBCS message.
    message: bytes with the signed GBCS message to verify.
    key: 64-byte digital signing public key of the originator.
    """
    m = parse(message)
    data = m.grouping_header[1:] + m.payload
    return ecdsa_verify(data, m.signature, key)


def create_ota_upgrade_image(manufacturer_image_file, manufacturer_code, image_type, file_version, min_hw_version, max_hw_version, key):
    """
    Creates an OTA Upgrade Image file as described in [GBCS] 11.2.3 Construction of OTA Upgrade Image.
    manufacturer_image_file: path to the file that contains the Manufacturer Image.
    manufacturer_code: 16-bit integer with the identifier assigned by the Zigbee Alliance to the manufacturer.
    image_type: 16-bit integer with a manufacturer-specific image type value.
    file_version: 32-bit integer with the version of the image file.
    min_hw_version: 16-bit integer with the minimum hardware version the image should be used on.
    max_hw_version: 16-bit integer with the maximum hardware version the image should be used on.
    key: 32-byte digital signing private key of the authorising remote party (supplier).
    The name of the generated file has the format recommended in [OTA] 6.3.8 OTA File Naming:
    MMMM-TTTT-VVVVVVVV-HHH...HHH.zigbee
    MMMM is the 16-bit Manufacturer Code in hexadecimal,
    TTTT is the 16-bit Image Type in hexadecimal,
    VVVVVVVV is the 32-bit File Version in hexadecimal,
    HHH...HHH is the 32-byte SHA256 Hash of the Manufacturer Image in hexadecimal (not mentioned in Zigbee OTA, but useful for the CS06 GBCS use case).
    References:
    GBCS section 11.2.2 Construction of Upgrade Image.
    GBCS section 11.2.3 Construction of OTA Upgrade Image.
    GBCS section 11.2.4 Construction of Manufacturer Image Hash.
    Zigbee OTA upgrade cluster section 6.3.2 OTA Header Format.
    Zigbee OTA upgrade cluster section 6.3.8 OTA File Naming.
    """
    file = open(manufacturer_image_file, 'rb')
    manufacturer_image = file.read()
    file.close()
    authorising_remote_party_signature = ecdsa_sign(manufacturer_image, key)
    force_replace = 0  # Only used by the CH, not by the meter.
    upgrade_image = manufacturer_image + bytes([force_replace, 0x40]) + authorising_remote_party_signature
    ota_header_length = 60
    total_image_size = ota_header_length + len(upgrade_image)
    ota_header = bytes([
        0x1E, 0xF1, 0xEE, 0x0B,  # OTA upgrade file identifier.
        0x00, 0x01,  # OTA header version.
        ota_header_length & 255, ota_header_length >> 8,
        0x04, 0x00,  # OTA header field control (hardware versions present).
        manufacturer_code & 0xFF, manufacturer_code >> 8,
        image_type & 255, image_type >> 8,
        file_version & 255, file_version >> 8 & 255, file_version >> 16 & 255, file_version >> 24,
        0x02, 0x00,  # Zigbee stack version.
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  # OTA header string (32 bytes).
        total_image_size & 255, total_image_size >> 8 & 255, total_image_size >> 16 & 255, total_image_size >> 24,
        min_hw_version & 255, min_hw_version >> 8,  # minimum hardware version
        max_hw_version & 255, max_hw_version >> 8,  # maximum_hardware_version
    ])
    ota_upgrade_image = ota_header + upgrade_image
    manufacturer_image_hash = hashlib.sha256(manufacturer_image).digest()
    ota_upgrade_image_file = '{:04X}-{:04X}-{:08X}-{:s}.zigbee'.format(manufacturer_code, image_type, file_version, manufacturer_image_hash.hex().upper())
    file = open(ota_upgrade_image_file, 'wb')
    file.write(ota_upgrade_image)
    file.close()


# Criptographic primitives.
# Reference: GBCS Section 4.3.3 Cryptographic primitives and their usage.

def ecdh(prvkey, pubkey):
    """
    Executes the Elliptic Curve Diffie Hellman (ECDH) algorithm to calculate a shared secret.
    prvkey: 32 bytes with the key agreement private key of the local peer.
    pubkey: 64 bytes with the key agreement public key of the other peer.
    Returns the calculated shared secret (32 bytes).
    References: GBCS 4.3.3.3 Calculating unique Shared Secret Keys for a Remote Party Message Instance.
    """
    eckey = libcrypto.EC_KEY_new_by_curve_name(libcrypto.NID_X9_62_prime256v1)
    bignum = libcrypto.BN_bin2bn(prvkey, len(prvkey), None)
    libcrypto.EC_KEY_set_private_key(eckey, bignum)
    libcrypto.BN_free(bignum)
    ecgroup = libcrypto.EC_KEY_get0_group(eckey)
    ecpoint = libcrypto.EC_POINT_new(ecgroup)
    upubkey = bytes([4]) + pubkey  # add the uncompressed form prefix byte
    libcrypto.EC_POINT_oct2point(ecgroup, ecpoint, upubkey, len(upubkey), None)
    secret = ctypes.create_string_buffer(32)
    result = libcrypto.ECDH_compute_key(secret, len(secret), ecpoint, eckey, None)
    libcrypto.EC_POINT_free(ecpoint)
    libcrypto.EC_KEY_free(eckey)
    return secret.raw


def ecdsa_sign(message, key):
    """
    Executes the Elliptic Curve Digital Signature Algorithm (ECDSA) to sign a message.
    message: bytes with the message to sign.
    key: 32 bytes with the digital signing private key to use to sign.
    Returns 64 bytes with the signature.
    """
    eckey = libcrypto.EC_KEY_new_by_curve_name(libcrypto.NID_X9_62_prime256v1)
    bignum = libcrypto.BN_bin2bn(key, len(key), 0)
    libcrypto.EC_KEY_set_private_key(eckey, bignum)
    libcrypto.BN_free(bignum)
    digest = hashlib.sha256(message).digest()
    sig = ctypes.create_string_buffer(72)  # ECDSA_size(eckey) maximum DER signature size
    siglen = ctypes.c_uint()
    libcrypto.ECDSA_sign(0, digest, len(digest), sig, ctypes.byref(siglen), eckey)
    libcrypto.EC_KEY_free(eckey)
    # Decode the 64-byte plain signature from the DER format
    signature = bytes()
    i = 3
    while i < siglen.value:
        intlen = sig.raw[i]
        i += 1
        if intlen == 33:
            i += 1
        signature += sig.raw[i:i+32]
        i += 32 + 1
    return signature


def ecdsa_verify(message, signature, key):
    """
    Executes the Elliptic Curve Digital Signature Algorithm (ECDSA) to verify the signature of a message.
    message: bytes with the signed message.
    signature: 64 bytes with the signature to verify.
    key: 64 bytes with the digital signing public key of the entity that signed the message.
    Returns True if the signature verifies successfully or False otherwise.
    """
    sig = bytes()  # convert the 64-byte plain signature to DER format
    for i in [0, 32]:
        if signature[i] < 0x80:
            sig += bytes([2, 32])  # integer tag, length
        else:
            sig += bytes([2, 33, 0])  # integer tag, length, padding 0 byte
        sig += signature[i:i+32]  # value
    sig = bytes([0x30, len(sig)]) + sig  # sequence tag, length, contents
    eckey = libcrypto.EC_KEY_new_by_curve_name(libcrypto.NID_X9_62_prime256v1)
    group = libcrypto.EC_KEY_get0_group(eckey)
    point = libcrypto.EC_POINT_new(group)
    ukey = bytes([4]) + key  # add the uncompressed form prefix byte
    libcrypto.EC_POINT_oct2point(group, point, ukey, len(ukey), None)
    libcrypto.EC_KEY_set_public_key(eckey, point)
    libcrypto.EC_POINT_free(point)
    digest = hashlib.sha256(message).digest()
    result = libcrypto.ECDSA_verify(0, digest, len(digest), sig, len(sig), eckey)
    libcrypto.EC_KEY_free(eckey)
    return result == 1


def gcm_decrypt(iv, aad, ciphertext, tag, key):
    """
    Executes the Galois Counter Mode (GCM) algorithm to decrypt data.
    iv: 12 bytes with the initalization vector.
    aad: bytes with the additional authenticated data.
    ciphertext: bytes with the ciphertext to decrypt.
    tag: bytes with the authentication tag to verify the decryption.
    key: 16 bytes with the AES 128-bit encryption key.
    Returns the decrypted plaintext or None if the tag verification fails.
    References:
    Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC,
    NIST Special Publication 800-38D, November 2007.
    https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
    """
    ctx = libcrypto.EVP_CIPHER_CTX_new()
    libcrypto.EVP_DecryptInit(ctx, libcrypto.EVP_aes_128_gcm(), key, iv)
    outlen = ctypes.c_int()
    libcrypto.EVP_DecryptUpdate(ctx, None, ctypes.byref(outlen), aad, len(aad))
    plaintext = ctypes.create_string_buffer(len(ciphertext))
    libcrypto.EVP_DecryptUpdate(ctx, plaintext, ctypes.byref(outlen), ciphertext, len(ciphertext))
    libcrypto.EVP_CIPHER_CTX_ctrl(ctx, libcrypto.EVP_CTRL_AEAD_SET_TAG, len(tag), tag)
    result = libcrypto.EVP_DecryptFinal(ctx, None, ctypes.byref(outlen))
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    if result > 0:
        return plaintext.raw
    else:
        return None  # tag verification failed


def gcm_encrypt(iv, aad, plaintext, taglen, key):
    """
    Executes the Galois Counter Mode (GCM) algorithm to encrypt data.
    iv: 12 bytes with the initalization vector.
    aad: bytes with the additional authenticated data.
    plaintext: bytes with the plaintext to encrypt.
    taglen: number of bytes of the 16-byte tag to return.
    key: 16 bytes with the AES 128-bit encryption key.
    Returns the encrypted ciphertext and taglen bytes of the authentication tag.
    References:
    Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC,
    NIST Special Publication 800-38D, November 2007.
    https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
    """
    ctx = libcrypto.EVP_CIPHER_CTX_new()
    libcrypto.EVP_EncryptInit(ctx, libcrypto.EVP_aes_128_gcm(), key, iv)
    outlen = ctypes.c_int()
    libcrypto.EVP_EncryptUpdate(ctx, None, ctypes.byref(outlen), aad, len(aad))
    ciphertext = ctypes.create_string_buffer(len(plaintext))
    libcrypto.EVP_EncryptUpdate(ctx, ciphertext, ctypes.byref(outlen), plaintext, len(plaintext))
    libcrypto.EVP_EncryptFinal(ctx, None, ctypes.byref(outlen))
    tag = ctypes.create_string_buffer(16)
    libcrypto.EVP_CIPHER_CTX_ctrl(ctx, libcrypto.EVP_CTRL_AEAD_GET_TAG, len(tag), tag)
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    return ciphertext.raw, tag.raw[0:taglen]


def gmac(iv, aad, key):
    """
    Executes the GMAC algorithm to calculate an authentication tag.
    iv: 12 bytes with the initalization vector.
    aad: bytes with the additional authenticated data.
    key: 16 bytes with the AES 128-bit encryption key.
    Returns 16 bytes with the calculated authentication tag.
    References:
    Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC,
    NIST Special Publication 800-38D, November 2007.
    https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
    """
    ctx = libcrypto.EVP_CIPHER_CTX_new()
    libcrypto.EVP_EncryptInit(ctx, libcrypto.EVP_aes_128_gcm(), key, iv)
    outlen = ctypes.c_int()
    libcrypto.EVP_EncryptUpdate(ctx, None, ctypes.byref(outlen), aad, len(aad))
    libcrypto.EVP_EncryptFinal(ctx, None, ctypes.byref(outlen))
    tag = ctypes.create_string_buffer(16)
    libcrypto.EVP_CIPHER_CTX_ctrl(ctx, libcrypto.EVP_CTRL_AEAD_GET_TAG, len(tag), tag)
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    return tag.raw


def kdf(z, otherinfo):
    """
    Executes a Key Derivation Function (KDF) to calculate a shared key from a shared secret.
    z: bytes with the shared secret.
    otherinfo: bytes with the OtherInfo data.
    Returns 16 bytes with the calculated shared key.
    References:
    Recommendation for Pair-Wise Key Establishment Schemes Using Discrete Logarithm Cryptography,
    NIST Special Publication 800-56A Revision 2, Section 5.8.1.1 The Single-Step KDF Specification.
    """
    counter = bytes([0, 0, 0, 1])
    x = counter + z + otherinfo
    k = hashlib.sha256(x).digest()
    return k[0:16]


# OpenSSL

libcrypto = ctypes.cdll.LoadLibrary('libcrypto.dll')  # libcrypto-1_1-x64.dll

# <openssl/bn.h>
# BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
libcrypto.BN_bin2bn.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
libcrypto.BN_bin2bn.restype = ctypes.c_void_p
# void BN_free(BIGNUM *a);
libcrypto.BN_free.argtypes = [ctypes.c_void_p]

# <openssl/ec.h>
# const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key);
libcrypto.EC_KEY_get0_group.argtypes = [ctypes.c_void_p]
libcrypto.EC_KEY_get0_group.restype = ctypes.c_void_p
# void EC_KEY_free(EC_KEY *key);
libcrypto.EC_KEY_free.argtypes = [ctypes.c_void_p]
# EC_KEY *EC_KEY_new_by_curve_name(int nid);
libcrypto.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
# int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *prv);
libcrypto.EC_KEY_set_private_key.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
# int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);
libcrypto.EC_KEY_set_public_key.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
# void EC_POINT_free(EC_POINT *point);
libcrypto.EC_POINT_free.argtypes = [ctypes.c_void_p]
# int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);
#libcrypto.EC_POINT_mul.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
# EC_POINT *EC_POINT_new(const EC_GROUP *group);
libcrypto.EC_POINT_new.argtypes = [ctypes.c_void_p]
libcrypto.EC_POINT_new.restype = ctypes.c_void_p
# int EC_POINT_oct2point(const EC_GROUP *group, EC_POINT *p, const unsigned char *buf, size_t len, BN_CTX *ctx);
libcrypto.EC_POINT_oct2point.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
# int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key, const EC_KEY *ecdh, void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
libcrypto.ECDH_compute_key.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

# <openssl/ecdsa.h>
# int ECDSA_sign(int type, const unsigned char *dgst, int dgstlen, unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);
libcrypto.ECDSA_sign.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
# int ECDSA_verify(int type, const unsigned char *dgst, int dgstlen, const unsigned char *sig, int siglen, EC_KEY *eckey);
libcrypto.ECDSA_verify.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]

# <openssl/evp.h>
# #define EVP_CTRL_AEAD_GET_TAG 0x10
libcrypto.EVP_CTRL_AEAD_GET_TAG = 0x10
# #define EVP_CTRL_AEAD_SET_TAG 0x11
libcrypto.EVP_CTRL_AEAD_SET_TAG = 0x11
# int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
libcrypto.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
# void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
libcrypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
# EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
libcrypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
# int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
libcrypto.EVP_DecryptFinal.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
# int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, const unsigned char *key, const unsigned char *iv);
libcrypto.EVP_DecryptInit.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
# int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
libcrypto.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
# int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
libcrypto.EVP_EncryptFinal.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
# int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv);
libcrypto.EVP_EncryptInit.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
# int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
libcrypto.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
# const EVP_CIPHER *EVP_aes_128_gcm(void);
libcrypto.EVP_aes_128_gcm.restype = ctypes.c_void_p

# <openssl/obj_mac.h>
# #define NID_X9_62_prime256v1 415
libcrypto.NID_X9_62_prime256v1 = 415
