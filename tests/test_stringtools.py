from pathlib import Path
import base64

from pcat.stringtools import custom_flag_regex, decode_interesting, extract_strings_from_bytes, find_matches


def test_extract_strings_from_bytes():
    data = b"\x00hello world\x00abc\x00password=secret123\n"
    assert "hello world" in extract_strings_from_bytes(data, min_len=5)
    assert "password=secret123\n" in extract_strings_from_bytes(data, min_len=5)


def test_find_matches_literal_and_regex():
    rows = [("raw-file", "flag{demo}"), ("packet:1", "password=test")]
    assert find_matches(rows, "FLAG", ignore_case=True) == [("raw-file", "flag{demo}")]
    assert find_matches(rows, r"password=.*", regex=True) == [("packet:1", "password=test")]


def test_decode_interesting_base64_and_hex():
    decoded = decode_interesting("Zm9vYmFyMTIzNDU2Nzg5MA== 666c61677b746573747d")
    assert any("foobar1234567890" in item for item in decoded)
    assert any("flag{test}" in item for item in decoded)


def test_custom_flag_regex():
    pattern = custom_flag_regex("CTF101{<flag>}")
    rows = [("raw-file", "CTF101{abc123}")]
    assert find_matches(rows, pattern, regex=True)


def test_decode_short_base64_fragment():
    decoded = decode_interesting("cGljb0NURg==")
    assert any("picoCTF" in item for item in decoded)


def test_decode_base85_when_hint_is_present():
    token = base64.b85encode(b"password Shinen").decode()
    decoded = decode_interesting(f"decode this with base85 {token}")
    assert any("password Shinen" in item for item in decoded)
