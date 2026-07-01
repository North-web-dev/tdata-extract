import json
import types

from tdata_extract import extract_accounts, format_output


def _acc(index, dc_id, key_bytes, user_id):
    authkey = types.SimpleNamespace(dcId=dc_id, key=key_bytes)
    return types.SimpleNamespace(index=index, authKey=authkey, UserId=user_id)


def _tdesk(accounts):
    return types.SimpleNamespace(accounts=accounts, isLoaded=lambda: True)


def test_extract_accounts_maps_fields():
    tdesk = _tdesk([_acc(0, 2, b"\x01\x02\x03", 111), _acc(1, 4, b"\xab\xcd", 222)])
    rows = extract_accounts(tdesk)
    assert rows[0] == {"index": 0, "dc_id": 2, "auth_key": "010203", "user_id": 111}
    assert rows[1]["auth_key"] == "abcd"
    assert rows[1]["dc_id"] == 4


def test_format_output_text():
    rows = [{"index": 0, "dc_id": 2, "auth_key": "dead", "user_id": 111}]
    out = format_output(rows, as_json=False)
    assert "dc_id=2" in out and "auth_key=dead" in out and "user_id=111" in out


def test_format_output_json_roundtrip():
    rows = [{"index": 0, "dc_id": 2, "auth_key": "dead", "user_id": 111}]
    assert json.loads(format_output(rows, as_json=True)) == rows
