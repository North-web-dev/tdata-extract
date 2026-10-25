# tdata-extract

Extract the **Auth Key** (hex) and **DC ID** from a Telegram Desktop `tdata`
folder — **fully local, offline, passcode-aware**. No network, no login, no API
credentials. Built for the forensics / account-migration niche where you need
to attach an MTProto library to an existing Desktop session.

**Works on current Telegram Desktop (v6.x, tested on 6.9).** No `opentele`
dependency — a self-contained parser, so it keeps working when a new release
bumps the `tdata` format.

## Install

```
pip install -r requirements.txt   # just `cryptography`
```

Python 3.8+.

## Usage

```
python tdata_extract.py <path/to/tdata> [--passcode PASS] [--json] [--out FILE]
```

| Flag | Meaning |
|---|---|
| `--passcode PASS` | The Desktop **local passcode**, if one is set. Omit it if there is none. |
| `--json` | Emit JSON instead of plain text. |
| `--out FILE` | Write to `FILE` instead of stdout. |

Example:

```
$ python tdata_extract.py ~/Telegram/tdata
user_id=123456789 dc_id=2
    auth_key=a1b2c3…            # 256-byte key = 512 hex chars
```

JSON (`--json`):

```json
[
  { "user_id": 123456789, "dc_id": 2, "auth_key": "a1b2c3…" }
]
```

The `dc_id` + `auth_key` pair is exactly what MTProto libraries (Telethon,
Pyrogram, TDLib) need to attach to an existing session. **All** accounts in a
multi-account `tdata` are extracted. A wrong or missing passcode exits with a
clear message (`could not unlock key_data …`), not a key.

## How it works

`tdata` stores each account's session in the encrypted **MTP authorization**
block (`dbiMtpAuthorization`), whose layout has been **stable since 2021** (the
64-bit user-id migration). Older extractors (opentele) break on new releases
because they fully parse the account `map`, which keeps gaining new `lskType`
keys each version (custom-emoji, prefs, webview tokens, …) — one unknown key
aborts the whole load with *"No account has been loaded."*

This tool sidesteps that entirely:

1. Read `key_datas` → derive the **local key** (PBKDF2-HMAC-SHA512 over the
   salt + optional passcode).
2. Walk every `tdata` file and AES-IGE-decrypt each with the local key.
3. Locate the `dbiMtpAuthorization` block by signature and parse `user_id`,
   `main_dc_id`, and the per-DC 256-byte `auth_key` directly — the `map` is
   never touched.

Because it reads only the stable auth block, it is resilient to `map`/draft
format churn across Telegram Desktop versions.

## Security & ethics

- **Use only on `tdata` for accounts you own and are authorized to access.**
  Extracting or using session data from other people's accounts may be illegal
  and violates Telegram's Terms of Service.
- An `auth_key` **is a full account credential** — equivalent to being logged
  in, and it bypasses your 2FA/cloud password. Treat it like a private key:
  keep it offline, do not paste it into chats, pastebins, or issue trackers,
  and delete extracted copies when you are done.
- The tool itself makes **no network connection** and never transmits anything.

## Limits (honest)

- Reads the **MTP auth block only** — not message history, drafts, cache, or
  the account `map`. If that is what you need, use `opentele`/TDLib directly.
- Tested against Telegram Desktop **v6.x**. Pre-2021 legacy *narrow-id* `tdata`
  is handled; other ancient layouts are not a target.
- Requires a readable, **unlocked-on-disk** `tdata` plus the passcode if one is
  set. It cannot brute-force or recover a forgotten passcode.
- A hardware-key / system-keychain–sealed `tdata` is out of scope.

## Support

If this saved you time, a ⭐ on the repo helps — and tips are welcome:

| Coin | Address |
|---|---|
| **BTC** | `bc1q0sfghv7yfl594gjurhyhlhdgm0dtwh4dkjha36` |
| **ETH / USDT-ERC20 / BNB-BEP20** | `0xB827b5a8B6c5111946c5D872933b2C23484E87dE` |
| **SOL** | `3ch5aHrPp3CierhiNXmqmtFH2dMHh6Gfv7a97KtLMMCh` |
| **USDT-TRC20 / TRX** | `TUAyz7TjgJdFVD2oFHWUUTNrzzAnBRgySG` |
| **TON** | `UQAJmYVuR3hh02etjaPKJF-h6jcpdSnq9ZIFvI64NEskS6tx` |

## Disclaimer

Provided **as is, without warranty of any kind**. The authors accept no
liability for misuse.

## License

MIT — see [LICENSE](LICENSE).
