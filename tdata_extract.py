"""Extract the Auth Key (hex) and DC ID from a Telegram Desktop `tdata` folder.

Reads and decrypts `tdata` locally — no network, no login. Handles the local
passcode if the desktop client set one. Backed by opentele.
"""
from __future__ import annotations

import argparse
import json
import os
from typing import Optional


def extract_accounts(tdesk) -> list:
    """Pull (index, dc_id, auth_key hex, user_id) for every account in a TDesktop."""
    rows = []
    for acc in tdesk.accounts:
        rows.append({
            "index": acc.index,
            "dc_id": acc.authKey.dcId,
            "auth_key": acc.authKey.key.hex(),
            "user_id": getattr(acc, "UserId", None),
        })
    return rows


def format_output(rows: list, as_json: bool) -> str:
    if as_json:
        return json.dumps(rows, indent=2)
    return "\n".join(
        f"[{r['index']}] user_id={r['user_id']} dc_id={r['dc_id']}\n"
        f"    auth_key={r['auth_key']}"
        for r in rows
    )


def load_tdesktop(path: str, passcode: Optional[str]):
    # Imported lazily so the pure functions above stay testable without opentele.
    from opentele.td import TDesktop
    return TDesktop(path, passcode=passcode or None)


def run(path: str, passcode: str, as_json: bool) -> str:
    if not os.path.isdir(path):
        raise SystemExit(f"not a directory: {path}")
    tdesk = load_tdesktop(path, passcode)
    if not tdesk.isLoaded() or not tdesk.accounts:
        raise SystemExit(
            "no accounts loaded — wrong path, wrong passcode, or an unsupported "
            "tdata version (opentele may lag the newest Telegram Desktop format)."
        )
    return format_output(extract_accounts(tdesk), as_json)


def main(argv: Optional[list] = None) -> None:
    ap = argparse.ArgumentParser(
        description="Extract auth_key (hex) + dc_id from a Telegram Desktop tdata folder.")
    ap.add_argument("tdata", help="path to the tdata folder")
    ap.add_argument("--passcode", default="", help="local passcode, if one is set")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--out", help="write to a file instead of stdout")
    a = ap.parse_args(argv)

    text = run(a.tdata, a.passcode, a.json)
    if a.out:
        with open(a.out, "w") as f:
            f.write(text + "\n")
        print(f"wrote result -> {a.out}")
    else:
        print(text)


if __name__ == "__main__":
    main()
