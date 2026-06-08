"""Pure helpers for editing an ``authorized_keys`` file (no I/O, unit-testable).

Refactored from a standalone VPS tool. Keys are matched by their base64 *body*
(validated as real base64), so a key is deduped / removed regardless of differing
comments or options, and malformed/junk lines are ignored rather than mistaken
for keys.
"""
from __future__ import annotations

import base64
import binascii

# OpenSSH public-key type tokens we recognise (the token before the base64 body).
KEY_TYPES = frozenset({
    "ssh-rsa", "ssh-dss", "ssh-ed25519",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
})


def _decoded_wire_type(body: str) -> str | None:
    """The SSH wire-format type string encoded in a base64 key body, or ``None``.

    A real public-key blob starts with a length-prefixed type string (e.g.
    ``ssh-ed25519``). Decoding and reading it rejects base64-looking junk (a plain
    comment word can be valid base64 but won't encode a matching type header).
    """
    if len(body) < 20:
        return None
    try:
        blob = base64.b64decode(body, validate=True)
    except (ValueError, binascii.Error):
        return None
    if len(blob) < 4:
        return None
    n = int.from_bytes(blob[:4], "big")
    if n <= 0 or 4 + n > len(blob):
        return None
    try:
        return blob[4:4 + n].decode("ascii")
    except UnicodeDecodeError:
        return None


def _split_key_line(line: str) -> tuple[str, str, str, str] | None:
    """``(options, type, body, comment)`` for a real key line, else ``None``.

    The body is the base64 blob - the stable identity of the key; options and
    comment are cosmetic. Blanks, comments, and malformed lines return ``None``.
    The body must base64-decode to a wire-type matching the line's type token.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    tokens = stripped.split()
    type_index = next((i for i, t in enumerate(tokens) if t in KEY_TYPES), None)
    if type_index is None or type_index + 1 >= len(tokens):
        return None
    key_type = tokens[type_index]
    body = tokens[type_index + 1]
    if _decoded_wire_type(body) != key_type:
        return None
    return (" ".join(tokens[:type_index]), key_type,
            body, " ".join(tokens[type_index + 2:]))


def key_body(line: str) -> str:
    """The base64 body of a key line - its stable identity. ``''`` if not a key."""
    parsed = _split_key_line(line)
    return parsed[2] if parsed else ""


def is_valid_public_key(line: str) -> bool:
    """True if the line parses as a real OpenSSH public key."""
    return _split_key_line(line) is not None


def same_key(a: str, b: str) -> bool:
    body = key_body(a)
    return bool(body) and body == key_body(b)


def key_lines(text: str) -> list[str]:
    """Real key lines from an authorized_keys file (blanks/comments/junk dropped)."""
    return [ln for ln in text.splitlines() if is_valid_public_key(ln)]


def count_keys(text: str) -> int:
    """How many real keys are in this text."""
    return len(key_lines(text))


def add_key_to_text(text: str, new_line: str) -> tuple[str, bool]:
    """Append ``new_line`` unless its body is already present. Returns (text, added).

    Raises ``ValueError`` if ``new_line`` isn't a valid public key.
    """
    body = key_body(new_line)
    if not body:
        raise ValueError("not a valid public key")
    if any(same_key(ln, new_line) for ln in text.splitlines()):
        return text, False
    base = text.rstrip("\n")
    return (base + "\n" if base else "") + new_line.strip() + "\n", True


def remove_key_from_text(text: str, target_line: str) -> tuple[str, int]:
    """Remove every line whose body matches ``target_line``. Returns (text, count)."""
    body = key_body(target_line)
    if not body:
        return text, 0
    kept: list[str] = []
    removed = 0
    for line in text.splitlines():
        if key_body(line) == body:
            removed += 1
            continue
        kept.append(line)
    out = "\n".join(kept).rstrip("\n")
    return (out + "\n" if out else ""), removed
