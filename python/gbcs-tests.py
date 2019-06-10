"""
gbcs-tests.py: tests for the implementation of the functions in gbcs.py

This is free and unencumbered software released into the public domain.
See the UNLICENSE file or https://unlicense.org for more details.
"""

import gbcs

# The sample values in GBCS section 18.4 Cryptographic Test Vectors.

class SupplierA:
    id = bytes.fromhex('123456789ABCDEF0')
    counter = bytes.fromhex('0000000000000001')
    dsprvkey = bytes.fromhex('3A6B2EAA0D9F25A9E455983FEB5BB947528121911BF3B76BE5661C89DBF24B26')
    dspubkey = bytes.fromhex('76628E1C84EF7935548AE5D62C7BB3AD28964CF794F0387A697EEC19CDD98F460A4D5E19087EF7216ED89C29831A6EE838C8DE88EF34F11D3F41F36D80B2A5D5')

class ACB:
    kaprvkey = bytes.fromhex('E4A6CFB431471CFCAE491FD566D19C87082CF9FA7722D7FA24B2B3F5669DBEFB')

class DeviceA:
    id = bytes.fromhex('FFFFFFFFFFFFFFFE')
    dspubkey = bytes.fromhex('86FB5EB3CA0507226BE7197058B9EC041D3A3758D9D9C91902ACA3391F4E58AEF13AFF63CC4EF68942B9B94904DC1B890EDBEABD16B992110624968E894E560E')
    kapubkey = bytes.fromhex('2DB45A3F21889438B42C8F464C75292BACF5FDDB5DA0B492501B299CBFE92D8FDB90FC8FF4026129838B1BCAD1402CAE47FE7D8084E409A41AFCE16D63579C5F')

# Critical Command from SupplierA to Device A: ECS04b Reset Meter Balance on the ESME.
message = bytes.fromhex('DD00000000000081A91100000000DF0901000000000000000108123456789ABCDEF008FFFFFFFFFFFFFFFE000200B335D92000000100030300700000130A00FF020300700000130A01FF020300700000130A02FF02030500000000050000000005000000004059045AB0F554622B0360340B9D87B5A23ED5723B41DE3F206E58CDD10F915B9FE2E12E2DA3632478A8DF678E418895869AC1E55318CCE04D120D2D6B44DC167B5D832D15B57A56D620F198B3')

#sig = gbcs.calculate_signature(message, SupplierA.dsprvkey)

if not gbcs.verify_signature(message, SupplierA.dspubkey):
    raise Exception

mac = gbcs.calculate_mac(message, ACB.kaprvkey, DeviceA.kapubkey, 12)
if mac != message[-12:]:
    raise Exception

# Tests the gbcs.gcm_decrypt and gbcs.gcm_encrypt functions with the values in Example 6 of
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf
key = bytes.fromhex('FEFFE9928665731C6D6A8F9467308308')
iv = bytes.fromhex('CAFEBABEFACEDBADDECAF888')
aad = bytes.fromhex('3AD77BB40D7A3660A89ECAF32466EF97F5D3D585')
plaintext = bytes.fromhex('D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39')
ciphertext = bytes.fromhex('42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091')
tag = bytes.fromhex('F07C2528EEA2FCA1211F905E')
p = gbcs.gcm_decrypt(iv, aad, ciphertext, tag, key)
if p != plaintext:
    raise Exception
c, t = gbcs.gcm_encrypt(iv, aad, plaintext, len(tag), key)
if c != ciphertext or t != tag:
    raise Exception

# Use cases.
hash = bytes(32)
counter = 1234567890
cs06 = gbcs.build_cs06_command(SupplierA, DeviceA, ACB, hash, counter)
print(cs06.hex())
