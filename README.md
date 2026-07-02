# tdata-extract

Extract the **Auth Key (hex)** and **DC ID** from a Telegram Desktop `tdata`
folder. Everything runs locally — the tool reads and decrypts `tdata` on disk,
with **no network access and no login**. It handles the local passcode if the
desktop client has one set.

**Works on current Telegram Desktop (v6.x, tested on 6.9).** No `opentele`
dependency — a self-contained parser, so it does not break when a new release
bumps the tdata format.

## Install

```
pip install -r requirements.txt   # just `cryptography`
```

## Usage

```
python tdata_extract.py <path/to/tdata> [--passcode PASS] [--json] [--out FILE]
```

Example:

```
$ python tdata_extract.py ~/Telegram/tdata
user_id=123456789 dc_id=2
    auth_key=a1b2c3…            # 256-byte key, 512 hex chars
```

JSON (`--json`):

```json
[
  { "user_id": 123456789, "dc_id": 2, "auth_key": "a1b2c3…" }
]
```

The `dc_id` + `auth_key` pair is what MTProto libraries (Telethon, Pyrogram,
TDLib) need to attach to an existing session. All accounts in a multi-account
`tdata` are extracted.

## How it works

`tdata` stores each account's session in the encrypted **MTP authorization**
block (`dbiMtpAuthorization`), whose layout has been **stable since 2021** (the
64-bit user-id migration). Older extractors (opentele) fail on new releases
because they fully parse the account `map`, which keeps gaining new `lskType`
keys each version (custom-emoji, prefs, webview tokens, …) — an unknown key
aborts the whole load with *"No account has been loaded."*

This tool sidesteps that entirely:

1. Read `key_datas` → derive the **local key** (PBKDF2-HMAC-SHA512 from the
   salt + optional passcode).
2. Walk every `tdata` file, AES-IGE-decrypt each with the local key.
3. Locate the `dbiMtpAuthorization` block by signature and parse
   `user_id`, `main_dc_id`, and the per-DC 256-byte `auth_key` directly — the
   `map` is never needed.

Because it reads only the stable auth block, it is resilient to `map`/draft
format churn across Telegram Desktop versions.

## Notes

- A wrong `--passcode` yields "no auth keys found" (the decrypt check fails).
- Legacy narrow-id `tdata` (pre-2021) is also handled.

## Disclaimer

Provided **as is, without warranty of any kind**. Use it only on `tdata` for
accounts **you own and are authorized to access**. Auth keys grant full account
access — handle them like passwords. Extracting or using session data from
accounts you do not own may be illegal and violates Telegram's Terms of Service.
The authors accept no liability for misuse.

## License

MIT — see [LICENSE](LICENSE).
