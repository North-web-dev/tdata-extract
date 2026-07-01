# tdata-extract

Extract the **Auth Key (hex)** and **DC ID** from a Telegram Desktop `tdata`
folder. Everything runs locally — the tool reads and decrypts `tdata` on disk,
with no network access and no login. It handles the local passcode if the
desktop client has one set.

Backed by [opentele](https://github.com/thedemons/opentele), which reverse
engineers the `tdata` format.

## Install

```
pip install -r requirements.txt
```

## Usage

```
python tdata_extract.py <path/to/tdata> [--passcode PASS] [--json] [--out FILE]
```

Example:

```
$ python tdata_extract.py ~/Telegram/tdata
[0] user_id=123456789 dc_id=2
    auth_key=a1b2c3...  (256-byte key, 512 hex chars)
```

JSON output (`--json`):

```json
[
  { "index": 0, "dc_id": 2, "auth_key": "a1b2c3…", "user_id": 123456789 }
]
```

The `dc_id` + `auth_key` pair is what MTProto libraries (Telethon, Pyrogram,
TDLib) need to attach to an existing session.

## Notes

- `tdata` versions drift with new Telegram Desktop releases. If no accounts load
  from a valid folder, opentele may be behind the newest format — update it
  (`pip install -U opentele`) or open an issue.
- A wrong `--passcode` also yields "no accounts loaded".

## Disclaimer

Provided **as is, without warranty of any kind**. Use it only on `tdata` for
accounts **you own and are authorized to access**. Auth keys grant full account
access — handle them like passwords. Extracting or using session data from
accounts you do not own may be illegal and violates Telegram's Terms of Service.
The authors accept no liability for misuse.

## License

MIT — see [LICENSE](LICENSE).
