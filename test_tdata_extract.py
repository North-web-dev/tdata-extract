import struct
from tdata_extract import parse_mtp, format_output, _ige_dec


def test_parse_mtp_wide_ids():
    # kWideIdsTag + user_id + main_dc + count=1 + (dc, 256-byte key)
    key = bytes(range(256))
    ser = struct.pack(">Q", 0xFFFFFFFFFFFFFFFF)
    ser += struct.pack(">Q", 7740265849)      # user_id
    ser += struct.pack(">i", 2)               # main_dc
    ser += struct.pack(">i", 1)               # count
    ser += struct.pack(">i", 2) + key         # dc=2 + key
    uid, dc, keys = parse_mtp(ser)
    assert uid == 7740265849 and dc == 2
    assert keys[2] == key and keys[2].hex() == key.hex()


def test_parse_mtp_legacy_narrow():
    key = bytes(256)
    ser = struct.pack(">i", 12345) + struct.pack(">i", 4)   # narrow user_id, dc
    ser += struct.pack(">i", 1) + struct.pack(">i", 4) + key
    uid, dc, keys = parse_mtp(ser)
    assert uid == 12345 and dc == 4 and 4 in keys


def test_format_output_json():
    import json
    rows = [{"user_id": 1, "dc_id": 2, "auth_key": "dead"}]
    assert json.loads(format_output(rows, True)) == rows


def test_ige_roundtrip():
    # IGE decrypt of a known ECB-built ciphertext is internally consistent
    key = bytes(range(32)); iv = bytes(range(32)); pt = bytes(range(48))
    # encrypt with IGE (mirror of _ige_dec) to verify decrypt inverts it
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    def ige_enc(pt, key, iv):
        pc, pp = iv[:16], iv[16:32]; out = bytearray()
        e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        for i in range(0, len(pt), 16):
            p = pt[i:i+16]
            c = bytes(a ^ b for a, b in zip(e.update(bytes(x ^ y for x, y in zip(p, pc))), pp))
            out += c; pc, pp = c, p
        return bytes(out)
    ct = ige_enc(pt, key, iv)
    assert _ige_dec(ct, key, iv) == pt
