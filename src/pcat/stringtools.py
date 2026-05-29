from __future__ import annotations

import base64
import binascii
import re
from pathlib import Path

from .errors import InvalidArgumentError


STRING_RE_TEMPLATE = rb"[\x09\x0a\x0d\x20-\x7e]{%d,}"
BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/=]{8,}")
HEX_LIKE = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
BASE85_TOKEN = re.compile(r"[!-~]{12,}")

INFRASTRUCTURE_NOISE = (
    "ocsp",
    "ssdp",
    "upnp",
    "uuid:",
    "urn:schemas-upnp-org",
    "notify * http",
    "_services._dns-sd",
    "m-search * http",
)


FLAG_PATTERNS = [
    r"flag\{[^}\r\n]{1,200}\}",
    r"ctf\{[^}\r\n]{1,200}\}",
    r"picoCTF\{[^}\r\n]{1,200}\}",
    r"HTB\{[^}\r\n]{1,200}\}",
    r"TCP1P\{[^}\r\n]{1,200}\}",
    r"DUCTF\{[^}\r\n]{1,200}\}",
]

CREDENTIAL_PATTERNS = [
    r"(?i)username=[^&\s]{1,120}",
    r"(?i)user=[^&\s]{1,120}",
    r"(?i)login=[^&\s]{1,120}",
    r"(?i)password=[^&\s]{1,120}",
    r"(?i)passwd=[^&\s]{1,120}",
    r"(?i)\bpass\s*[:=]\s*[^&\s]{1,120}",
    r"(?i)pwd=[^&\s]{1,120}",
    r"(?i)token=[A-Za-z0-9._\-+/=]{8,200}",
    r"(?i)secret=[A-Za-z0-9._\-+/=]{4,200}",
    r"(?i)api[_-]?key=[A-Za-z0-9._\-+/=]{8,200}",
    r"(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]{8,}",
    r"(?i)Authorization:\s*Bearer\s+[A-Za-z0-9._\-+/=]{8,}",
]


def extract_strings_from_bytes(data: bytes, min_len: int = 5) -> list[str]:
    regex = re.compile(STRING_RE_TEMPLATE % min_len)
    results = []
    for match in regex.finditer(data):
        text = match.group(0).decode("utf-8", errors="ignore")
        if text.strip():
            results.append(text)
    return results


def raw_file_strings(path: Path, min_len: int = 5) -> list[tuple[str, str]]:
    data = path.read_bytes()
    return [("raw-file", item) for item in extract_strings_from_bytes(data, min_len)]


def strings_from_payload_hex(rows: list[tuple[str, str]], min_len: int = 5) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    for source, payload_hex in rows:
        if not payload_hex:
            continue
        try:
            payload = bytes.fromhex(payload_hex.replace(":", ""))
        except ValueError:
            continue
        for item in extract_strings_from_bytes(payload, min_len):
            results.append((source, item))
    return results


def dedupe_strings(rows: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen = set()
    deduped = []
    for source, text in rows:
        key = (source, text)
        if key not in seen:
            seen.add(key)
            deduped.append((source, text))
    return deduped


def find_matches(
    rows: list[tuple[str, str]],
    pattern: str,
    regex: bool = False,
    ignore_case: bool = False,
) -> list[tuple[str, str]]:
    flags = re.IGNORECASE if ignore_case else 0
    try:
        compiled = re.compile(pattern if regex else re.escape(pattern), flags)
    except re.error as exc:
        raise InvalidArgumentError(f"Invalid regex pattern: {exc}") from exc
    return [(source, text) for source, text in rows if compiled.search(text)]


def custom_flag_regex(template: str) -> str:
    if "<flag>" not in template:
        return re.escape(template)
    before, after = template.split("<flag>", 1)
    return re.escape(before) + r"[^}\r\n]{1,200}" + re.escape(after)


def detect_flags(rows: list[tuple[str, str]], custom_template: str = "") -> list[tuple[str, str]]:
    patterns = list(FLAG_PATTERNS)
    if custom_template:
        patterns.insert(0, custom_flag_regex(custom_template))
    hits = []
    seen = set()
    for source, text in rows:
        match_text = flag_match_text(text, patterns)
        if match_text:
            key = (source, match_text)
            if key not in seen:
                seen.add(key)
                hits.append((source, match_text))
    return hits


def flag_match_text(text: str, patterns: list[str]) -> str:
    for candidate in flag_candidates(text):
        matches: list[tuple[int, int, str]] = []
        for pattern in patterns:
            for match in re.finditer(pattern, candidate, flags=re.IGNORECASE):
                matched = match.group(0)
                matches.append((match.start(), -len(matched), matched))
        if matches:
            return sorted(matches)[0][2]
    return ""


def flag_candidates(text: str) -> list[str]:
    candidates = [text]
    if "{" in text and "}" in text:
        compact = re.sub(r"[\s\x00]+", "", text)
        if compact != text:
            candidates.append(compact)
    return candidates


def detect_credentials(rows: list[tuple[str, str]]) -> list[tuple[str, str]]:
    hits = []
    for source, text in rows:
        for pattern in CREDENTIAL_PATTERNS:
            if re.search(pattern, text):
                hits.append((source, text))
                break
    return hits


def decode_interesting(text: str) -> list[str]:
    decoded = []
    for token in clean_base64_tokens(text):
        try:
            raw = base64.b64decode(pad_base64(token), validate=True)
            decoded_text = raw.decode("utf-8", errors="ignore")
            if is_useful_decoded_text(decoded_text):
                decoded.append(f"base64:{token} -> {decoded_text[:200]}")
        except Exception:
            pass
    for match in HEX_LIKE.finditer(text):
        token = match.group(0)
        try:
            raw = binascii.unhexlify(token)
            decoded_text = raw.decode("utf-8", errors="ignore")
            if is_useful_decoded_text(decoded_text):
                decoded.append(f"hex:{token[:80]} -> {decoded_text[:200]}")
        except Exception:
            pass
    if "base85" in text.lower() or "b85" in text.lower():
        decoded.extend(decode_base85_near_hint(text))
    return decoded


def decode_base64_value(value: str) -> str:
    token = value.strip()
    if not token:
        return ""
    try:
        raw = base64.b64decode(pad_base64(token), validate=True)
    except Exception:
        return ""
    decoded = raw.decode("utf-8", errors="ignore").strip()
    if is_useful_decoded_text(decoded):
        return decoded
    return ""


def clean_base64_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    seen = set()
    for match in BASE64_TOKEN.finditer(text):
        raw = match.group(0)
        candidates = trim_base64_candidates(raw)
        for token in candidates:
            if token not in seen:
                seen.add(token)
                tokens.append(token)
    return tokens


def trim_base64_candidates(raw: str) -> list[str]:
    candidates: list[str] = []
    if "=" in raw:
        raw = raw[: raw.rfind("=") + 1]
    raw = raw.strip("=") + ("=" * (len(raw) - len(raw.rstrip("="))))
    raw = raw.rstrip("=") + raw[len(raw.rstrip("=")):]
    raw = raw.strip()
    for end in range(len(raw), 7, -1):
        token = raw[:end].rstrip("=")
        if len(token) < 8:
            continue
        padded = pad_base64(token)
        if len(padded) % 4 == 0:
            candidates.append(padded)
            break
    return candidates


def pad_base64(token: str) -> str:
    token = token.strip()
    token = token.rstrip("=")
    return token + "=" * (-len(token) % 4)


def is_useful_decoded_text(text: str) -> bool:
    if not text:
        return False
    stripped = text.strip()
    if len(stripped) < 3:
        return False
    if is_infrastructure_noise(stripped):
        return False
    printable = sum((ch.isprintable() or ch in "\r\n\t") for ch in stripped)
    if printable < max(3, int(len(stripped) * 0.85)):
        return False
    letters = sum(ch.isalpha() for ch in stripped)
    alnum = sum(ch.isalnum() for ch in stripped)
    clue_chars = sum(ch in "{}_:-/=.@ " for ch in stripped)
    if letters + clue_chars < max(3, int(len(stripped) * 0.35)):
        return False
    if alnum < max(3, int(len(stripped) * 0.25)):
        return False
    return True


def is_infrastructure_noise(text: str) -> bool:
    lowered = text.lower()
    if any(token in lowered for token in INFRASTRUCTURE_NOISE):
        return True
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", lowered):
        return True
    return False


def decode_base85_near_hint(text: str) -> list[str]:
    decoded: list[str] = []
    for match in BASE85_TOKEN.finditer(text):
        token = match.group(0).strip()
        if len(token) < 12:
            continue
        try:
            raw = base64.b85decode(token)
            decoded_text = raw.decode("utf-8", errors="ignore")
            if is_useful_decoded_text(decoded_text):
                decoded.append(f"base85:{token[:80]} -> {decoded_text[:200]}")
        except Exception:
            pass
    return decoded
