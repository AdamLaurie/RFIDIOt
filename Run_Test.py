#!/usr/bin/env python3

#
#
# Primitive testing script, needs to be automated and replaced
#
#

#pylint: disable=import-outside-toplevel

import sys


def test_mifarekeys() -> bool:
    try:
        from mifarekeys import gen_MifarePWD
    except ImportError as _e:
        print(f'Failed to import file "mifarekeys.py": {_e}')
        print("mifarekeys: Test SKIPPED")
        return False

    key_A = bytearray.fromhex('A0A1A2A3A4A5')
    key_B = bytearray.fromhex('B0B1B2B3B4B5')
    expected_result = ['8C7F46D76CE01266', '40424446484A7E00', '007E60626466686A']
    results = gen_MifarePWD(key_A, key_B)
    if expected_result != results:
        print("mifarekeys: Test Fail")
        print(f"\tExpected {expected_result}")
        print(f"\tReceived {results}")
        return False

    key_A = bytearray.fromhex('FFFFFFFFFFFF')
    key_B = bytearray.fromhex('FFFFFFFFFFFF')
    expected_result = ['0B54570745FE3AE7', 'FEFEFEFEFEFE7E00', '007EFEFEFEFEFEFE']
    results = gen_MifarePWD(key_A, key_B)
    if expected_result != results:
        print("mifarekeys: Test Fail")
        print(f"\tExpected {expected_result}")
        print(f"\tReceived {results}")
        return False

    print("mifarekeys: Test Pass")
    return True


def test_conversion_functions() -> bool:

    return_val = True

    in_val = ["DE", "AD", "BE", "EF"]
    out_val = [222, 173, 190, 239]
    dat = rfi.HexArrayToList(in_val)
    if dat != out_val:
        print("HexArrayToList: Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False

    in_val = "DEADBEEF"
    out_val = [222, 173, 190, 239]
    dat = rfi.HexToList(in_val)
    if dat != out_val:
        print("HexToList: Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False

    in_val = "DEADBEEF"
    out_val = ['DE', 'AD', 'BE', 'EF']
    dat = rfi.HexArraysToArray(in_val)
    if dat != out_val:
        print("HexArraysToArray: Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False

    in_val = "10101010"
    out_val = "1001100110011001"
    dat = rfi.BinaryToManchester(in_val)
    if dat != out_val:
        print("BinaryToManchester: Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False

    in_val = "\x03Hello\x85\xf1World!\x10"
    out_val = '.Hello..World!.'
    dat = rfi.ReadablePrint(in_val)
    # dat = rfi._ReadablePrint(my_string)
    if dat != out_val:
        print("ReadablePrint: str Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False

    in_val = b"\x03Hello\x85\xf1World!\x10"
    out_val = '.Hello..World!.'
    dat = rfi.ReadablePrint(in_val)
    # dat = rfi._ReadablePrint(my_string)
    if dat != out_val:
        print("ReadablePrint: bytes Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False

    in_val = b'\x01\x03\x07\x0F\x1F\x3F\x7F\xFF'
    out_val = '0000000100000011000001110000111100011111001111110111111111111111'
    dat = rfi.ToBinaryString(in_val)
    if dat != out_val:
        print("ToBinaryString: bytes Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False

    in_val = "\x01\x03\x07\x0F\x1F\x3F\x7F\xFF"
    dat = rfi.ToBinaryString(in_val)
    if dat != out_val:
        print("ToBinaryString: str Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False

    in_val = b'\x01\x03\x07\x0F\x1F\x3F\x7F\xFF'
    out_val = '0103070f1f3f7fff'
    dat = rfi.ToHex(in_val)
    if dat != out_val:
        print("ToHex: bytes Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False

    in_val = "\x01\x03\x07\x0F\x1F\x3F\x7F\xFF"
    dat = rfi.ToHex(in_val)
    if dat != out_val:
        print("ToHex: str Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False

    in_val = '0103070f1f3f7fff'
    out_val = b'\x01\x03\x07\x0F\x1F\x3F\x7F\xFF'
    dat = rfi.ToBinary(in_val)
    if dat != out_val:
        print("ToBinary: Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False

    in_val = bytes([0x12, 0x34, 0x56, 0x78])
    out_val = bytes([0x84, 0xc2, 0xa6, 0xe1])
    # 84c2a6e1
    dat = rfi.NibbleReverse(in_val)
    if dat != out_val:
        print("NibbleReverse: byte Test Fail")
        print(f"\t{dat.hex()} != {out_val.hex()}")
        return_val = False

    in_val = '\x124Vx'
    out_val = bytes([0x84, 0xc2, 0xa6, 0xe1])
    # 84c2a6e1
    dat = rfi.NibbleReverse(in_val)
    if dat != out_val:
        print("NibbleReverse: str Test Fail")
        print(f"\t{dat.hex()} != {out_val.hex()}")
        return_val = False

    # in_val = '112233aabbccddff'
    # out_val = '8844cc55dd33bbff'
    in_val = '12345678'
    out_val = '84c2a6e1'
    dat = rfi.HexNibbleReverse(in_val)
    if dat != out_val:
        print("_HexNibbleReverse: Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False

    in_val = '112233aabbccddff'
    out_val = '8844cc55dd33bbff'
    dat = rfi.HexNibbleReverse(in_val)
    if dat != out_val:
        print("HexNibbleReverse: Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False

# ('HexNibbleReverse:', '8844cc55dd33bbff')
# 112233AABBCCDDFF

    if return_val:
        print("Conversion Functions: Test Pass")

    return return_val

def _ToHex(data):
    "convert binary data to hex printable"
    if isinstance(data, (bytes, bytearray)):
        return data.hex()
    string= ''
    for x in range(len(data)):
        string += '%02x' % ord(data[x])
    return string

def test_crypto_functions() -> bool:

    return_val = True

    in_val = b'\xde\xad\xbe\xef'
    out_val = "dfadbfef"
    dat = rfi.DESParity(in_val).hex()
    if dat != out_val:
        print("DESParity: Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False
    else:
        print("DESParity: Test Pass")

    in_val = b'\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef'
    out_val = 'ef3489f7b9e6525d5776dafb32ad2c62'
    dat = rfi.DESKey(in_val, rfi.KMAC, 16).hex()
    if dat != out_val:
        print("DESKey: Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False
    else:
        print("DESKey: Test Pass")

    out_val = b'\x80\x00\x00\x00\x00\x00\x00\x00'
    dat = rfi.PADBlock('')
    if dat != out_val:
        print("PADBlock: Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False

    message = "The quick brown fox jumps over the lazy dog"
    key = b'\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef'
    ssc = ''
    out_val = '9be9c94b596eff37'
    dat = rfi.DESMAC(message, key, ssc).hex()
    if dat != out_val:
        print("DESMAC: str Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False
    else:
        print("DESMAC: str Test Pass")

    message = b"The quick brown fox jumps over the lazy dog"
    key = b'\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef'
    ssc = ''
    out_val = '9be9c94b596eff37'
    dat = rfi.DESMAC(message, key, ssc).hex()
    if dat != out_val:
        print("DESMAC: byte Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False
    else:
        print("DESMAC: byte Test Pass")

    message = b"The quick brown fox jumps over the lazy dog"
    key = b'\xa1\x10n\x08L=uv&vR\x85\xec\xcbp)\xe6Tu\xd0y\xb3*\x07'
    ssc = ''
    out_val = 'c38c8b6ef4653ddf'
    dat = rfi.DES3MAC(message, key, ssc).hex()
    if dat != out_val:
        print("DES3MAC: Test Fail")
        print(f"\t{dat} != {out_val}")
        return_val = False
    else:
        print("DES3MAC: Test Pass")

    if return_val:
        print("Crypto Functions: Test Pass")

    return return_val

def test_get_error_str() -> bool:

    test_cases = {
        "6200": "No information given",
        'xxxxxxx': "gemeral error",
        "6700": "Wrong length",
        "6800": "No information given",
        "PC00": "No TAG present!",
        0: "NFC_SUCCESS, Success (no error)",
        -1: "NFC_EIO, Input / output error",
        -80: "NFC_ESOFT Software error",
    }

    for k, v in test_cases.items():
        x = rfi.get_error_str(k)
        if x != v:
            print("get_error_str: Test Fail")
            print(f"\tExpected {v}")
            print(f"\tReceived {x}")
            break
    else:
        print("get_error_str: Test Pass")
        return True

    return False

def test_rfidiot_lib() -> bool:

    test_get_error_str()

    print()

    test_conversion_functions()

    print()

    test_crypto_functions()

def text_aid_lookup() -> bool:
    try:
        from AID_lookup import AID_Lookup
    except ImportError as _e:
        print(f'Failed to import file "AID_Lookup.py": {_e}')
        print("AID_Lookup: Test SKIPPED")
        return False

    if not AID_Lookup().self_test():
        print("text_aid_lookup: Test Fail")
        return False

# make this a test somehow
#    i = 0
#    for x in AID_Lookup.list_aids():
#        print(x)
#        i += 1
#        if i > 20:
#            break

    print("text_aid_lookup: Test Pass")
    return True

if __name__ == '__main__':

    print("\n---Script Tests---")
    assert test_mifarekeys()


    # make sure this is last because it mucks with argv
    print("\n---Module Library Tests---")

    text_aid_lookup()

    sys.argv.append('-n')
    import rfidiot
    rfi = rfidiot.card

    test_rfidiot_lib()

