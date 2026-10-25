import struct
import pytest
from tdata_extract import parse_mtp, format_output, _ige_dec, extract, PasscodeError


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


# --- end-to-end: build a format-accurate tdata, then extract from it ---------
import hashlib  # noqa: E402
from tdata_extract import _prepare_aes, create_local_key  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402


def _ige_enc(pt, key, iv):
    pc, pp = iv[:16], iv[16:32]; out = bytearray()
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    for i in range(0, len(pt), 16):
        p = pt[i:i + 16]
        c = bytes(a ^ b for a, b in zip(e.update(bytes(x ^ y for x, y in zip(p, pc))), pp))
        out += c; pc, pp = c, p
    return bytes(out)


def _enc_local(data, key):
    full = struct.pack("<I", len(data) + 4) + data
    if len(full) % 16:
        full += b"\x00" * (16 - len(full) % 16)
    msg = hashlib.sha1(full).digest()[:16]
    ak, iv = _prepare_aes(key, msg, x=8)
    return msg + _ige_enc(full, ak, iv)


def _tdf(body):
    inner = b"TDF$" + struct.pack("<I", 0x0100000A) + body
    return inner + hashlib.md5(inner).digest()


def _qba(b):
    return struct.pack(">I", len(b)) + b


def _build_tdata(base, user_id, dc_id, auth_key, passcode=b""):
    base.mkdir(parents=True, exist_ok=True)
    salt = bytes(range(32)); local_key = bytes((i * 7) % 256 for i in range(256))
    key_enc = _enc_local(local_key, create_local_key(salt, passcode))
    (base / "key_datas").write_bytes(_tdf(_qba(salt) + _qba(key_enc)))
    ser = struct.pack(">Q", 0xFFFFFFFFFFFFFFFF) + struct.pack(">Q", user_id)
    ser += struct.pack(">i", dc_id) + struct.pack(">i", 1) + struct.pack(">i", dc_id) + auth_key
    mtp = struct.pack(">I", 0x4B) + struct.pack(">I", len(ser)) + ser
    blob = _enc_local(b"\x00\x00\x00\x01filler" + mtp, local_key)
    (base / "A7FDF864FBC10B77s").write_bytes(_tdf(_qba(blob)))


def test_extract_end_to_end(tmp_path):
    key = bytes((i * 3 + 1) % 256 for i in range(256))
    _build_tdata(tmp_path / "tdata", 7740265849, 2, key)
    rows = extract(str(tmp_path / "tdata"))
    assert rows == [{"user_id": 7740265849, "dc_id": 2, "auth_key": key.hex()}]
    assert len(rows[0]["auth_key"]) == 512


def test_extract_passcode(tmp_path):
    key = bytes((i * 5 + 2) % 256 for i in range(256))
    _build_tdata(tmp_path / "tdata", 42, 4, key, passcode=b"hunter2")
    assert extract(str(tmp_path / "tdata"), b"hunter2")[0]["auth_key"] == key.hex()
    with pytest.raises(PasscodeError):
        extract(str(tmp_path / "tdata"), b"wrong")
    with pytest.raises(PasscodeError):
        extract(str(tmp_path / "tdata"))
