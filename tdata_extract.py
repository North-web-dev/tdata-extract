"""Extract the Auth Key (hex) + DC ID from a Telegram Desktop tdata folder.

Works on modern Telegram Desktop (v6.x, tested on 6.9). Pure local parse — no
network, no login. No opentele dependency: it reads the MTP authorization block
directly (whose format is unchanged since 2021) and bypasses the account `map`,
which is what breaks opentele on new tdata (new lskType keys). Handles the local
passcode if one is set.
"""
from __future__ import annotations
import argparse, json, os, struct, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _aes_ecb_dec(key: bytes, data: bytes) -> bytes:
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return d.update(data) + d.finalize()


def _ige_dec(ct: bytes, key: bytes, iv: bytes) -> bytes:
    prev_c, prev_p = iv[:16], iv[16:32]
    out = bytearray()
    for i in range(0, len(ct), 16):
        c = ct[i:i + 16]
        p = bytes(a ^ b for a, b in zip(_aes_ecb_dec(key, bytes(x ^ y for x, y in zip(c, prev_p))), prev_c))
        out += p
        prev_c, prev_p = c, p
    return bytes(out)


def _prepare_aes(key: bytes, msg: bytes, x: int = 8):
    a = hashlib.sha1(msg + key[x:x + 32]).digest()
    b = hashlib.sha1(key[x + 32:x + 48] + msg + key[x + 48:x + 64]).digest()
    c = hashlib.sha1(key[x + 64:x + 96] + msg).digest()
    d = hashlib.sha1(msg + key[x + 96:x + 128]).digest()
    return a[0:8] + b[8:20] + c[4:16], a[8:20] + b[0:8] + c[16:20] + d[0:8]


def decrypt_local(blob: bytes, key: bytes) -> bytes:
    msg, ct = blob[:16], blob[16:]
    ak, iv = _prepare_aes(key, msg, x=8)
    plain = _ige_dec(ct, ak, iv)
    if hashlib.sha1(plain).digest()[:16] != msg:
        raise ValueError("decrypt failed (wrong passcode?)")
    return plain[4:struct.unpack("<I", plain[:4])[0]]


def read_tdf(path: str):
    if not os.path.exists(path) and os.path.exists(path + "s"):
        path += "s"
    b = open(path, "rb").read()
    if b[:4] != b"TDF$":
        raise ValueError("not a TDF file")
    return b[8:-16]


class _BE:
    def __init__(self, d): self.d, self.p = d, 0
    def i32(self): v = struct.unpack(">i", self.d[self.p:self.p + 4])[0]; self.p += 4; return v
    def u32(self): v = struct.unpack(">I", self.d[self.p:self.p + 4])[0]; self.p += 4; return v
    def u64(self): v = struct.unpack(">Q", self.d[self.p:self.p + 8])[0]; self.p += 8; return v
    def qba(self):
        n = self.u32()
        if n == 0xFFFFFFFF:
            return b""
        v = self.d[self.p:self.p + n]; self.p += n; return v


def create_local_key(salt: bytes, passcode: bytes = b"") -> bytes:
    it = 100000 if passcode else 1
    hk = hashlib.sha512(salt + passcode + salt).digest()
    return hashlib.pbkdf2_hmac("sha512", hk, salt, it, dklen=256)


def parse_mtp(serialized: bytes):
    """Parse a dbiMtpAuthorization block -> (user_id, main_dc_id, {dc_id: key})."""
    s = _BE(serialized)
    if s.u64() == 0xFFFFFFFFFFFFFFFF:      # kWideIdsTag (64-bit ids, since 2021)
        user_id, main_dc = s.u64(), s.i32()
    else:
        s.p = 0
        user_id, main_dc = s.i32() & 0xffffffff, s.i32()
    n = s.i32()
    keys = {}
    for _ in range(n):
        dc = s.i32(); keys[dc] = s.d[s.p:s.p + 256]; s.p += 256
    return user_id, main_dc, keys


def _scan_mtp(plain: bytes):
    # dbiMtpAuthorization (0x4B) followed by a QByteArray starting with kWideIdsTag
    sig, i = b"\x00\x00\x00\x4b", 0
    i = plain.find(sig)
    while i != -1:
        try:
            n = struct.unpack(">I", plain[i + 4:i + 8])[0]
            if 20 <= n <= 1_000_000 and plain[i + 8:i + 16] == b"\xff" * 8:
                return parse_mtp(plain[i + 8:i + 8 + n])
        except Exception:
            pass
        i = plain.find(sig, i + 1)
    return None


class PasscodeError(Exception):
    """key_data decrypt failed — usually a missing or wrong --passcode."""


def extract(base: str, passcode: bytes = b"") -> list:
    body = read_tdf(os.path.join(base, "key_data"))
    ks = _BE(body)
    salt, key_enc = ks.qba(), ks.qba()
    try:
        local_key = decrypt_local(key_enc, create_local_key(salt, passcode))[:256]
    except ValueError:
        raise PasscodeError(
            "could not unlock key_data — "
            + ("wrong --passcode" if passcode else "this tdata is passcode-protected; pass --passcode"))

    out, seen = [], set()
    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith("s"):
                continue
            try:
                plain = decrypt_local(_BE(read_tdf(os.path.join(root, fn))).qba(), local_key)
            except Exception:
                continue
            r = _scan_mtp(plain)
            if r:
                uid, dc, keys = r
                if dc in keys and (uid, dc) not in seen:
                    seen.add((uid, dc))
                    out.append({"user_id": uid, "dc_id": dc, "auth_key": keys[dc].hex()})
    return out


def format_output(rows, as_json):
    if as_json:
        return json.dumps(rows, indent=2)
    return "\n".join(f"user_id={r['user_id']} dc_id={r['dc_id']}\n    auth_key={r['auth_key']}" for r in rows)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Extract auth_key(hex)+dc_id from a Telegram Desktop tdata folder (v6.x).")
    ap.add_argument("tdata", help="path to the tdata folder")
    ap.add_argument("--passcode", default="", help="local passcode, if one is set")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--out", help="write to a file instead of stdout")
    a = ap.parse_args(argv)
    if not os.path.isdir(a.tdata):
        raise SystemExit(f"not a directory: {a.tdata}")
    try:
        rows = extract(a.tdata, a.passcode.encode())
    except PasscodeError as e:
        raise SystemExit(str(e))
    if not rows:
        raise SystemExit("no auth keys found (wrong path/passcode, or empty tdata)")
    text = format_output(rows, a.json)
    if a.out:
        open(a.out, "w").write(text + "\n")
        print(f"wrote {len(rows)} account(s) -> {a.out}")
    else:
        print(text)


if __name__ == "__main__":
    main()
