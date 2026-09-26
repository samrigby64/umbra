"""PGP fingerprint recovery.

A PGP fingerprint is the most durable identifier a dark-web operator has. Vendors
rotate onion addresses after every takedown, change display names between markets,
and burn wallets — but they keep the key, because their reputation (and every
signed message proving they are who they claim) is bound to it. Two listings on
two different markets sharing a fingerprint is the strongest "same actor" evidence
available without law-enforcement data.

So recording that a key *exists* is close to worthless; we need its value. Two
routes, in order of preference:

1. Compute it from the armoured key block. This is canonical and works even when
   the page never prints the fingerprint anywhere.
2. Scrape the ``gpg --fingerprint`` display format if a block isn't present.

Deliberately narrow: these feed entity resolution, and a false fingerprint merges
two unrelated actors into one — a much worse outcome than missing one. A bare
40-hex run is *not* accepted without PGP context nearby, because SHA-1 digests and
large decimal numbers look identical to a loose matcher.
"""

from __future__ import annotations

import base64
import hashlib
import re
import struct

_ARMOR = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)-----END PGP PUBLIC KEY BLOCK-----",
    re.S,
)

# ``gpg --fingerprint`` prints 10 groups of 4 hex, with a wider gap mid-way:
#   Key fingerprint = 0123 4567 89AB CDEF 0123  4567 89AB CDEF 0123 4567
# Ten grouped quads in a row is distinctive enough to stand on its own.
_SPACED = re.compile(r"\b(?:[A-F0-9]{4}[ \t]+){9}[A-F0-9]{4}\b", re.I)

# A bare 40-hex run is only a fingerprint if something nearby says so — otherwise
# it is just as likely a SHA-1 digest, a git commit, or a session token. The
# optional ``0x`` matters: keyservers write key IDs that way, and without it the
# leading word boundary can never match the digit after the ``x``.
_BARE = re.compile(r"\b(?:0x)?([A-F0-9]{40})\b", re.I)
_PGP_CONTEXT = re.compile(r"(?:pgp|gpg|fingerprint|key\s*id|public\s+key)", re.I)
_CONTEXT_WINDOW = 120


def _packet_body(data: bytes) -> bytes | None:
    """Return the body of the first OpenPGP packet if it is a public-key packet."""
    if len(data) < 3 or not data[0] & 0x80:
        return None
    b0 = data[0]
    if b0 & 0x40:  # RFC 4880 new-format header
        tag = b0 & 0x3F
        first = data[1]
        if first < 192:
            length, header = first, 2
        elif first < 224:
            length, header = ((first - 192) << 8) + data[2] + 192, 3
        elif first == 255:
            length, header = struct.unpack(">I", data[2:6])[0], 6
        else:
            return None  # partial body length: not used for key packets
    else:  # old-format header
        tag = (b0 >> 2) & 0x0F
        length_type = b0 & 0x03
        if length_type == 0:
            length, header = data[1], 2
        elif length_type == 1:
            length, header = struct.unpack(">H", data[1:3])[0], 3
        elif length_type == 2:
            length, header = struct.unpack(">I", data[1:5])[0], 5
        else:
            return None  # indeterminate length
    if tag != 6:  # 6 = Public-Key Packet; a transferable key always starts with one
        return None
    body = data[header : header + length]
    return body if len(body) == length else None


def fingerprint_from_armor(block: str) -> str | None:
    """Compute the v4 fingerprint of an armoured public key block.

    RFC 4880 §12.2: the fingerprint is SHA-1 over ``0x99``, the two-byte packet
    body length, and the body itself.
    """
    lines = [line.strip() for line in block.splitlines()]
    # Skip blank lines and armour headers ("Version: GnuPG v2", "Comment: ...").
    # Base64 never contains a colon, so that alone identifies a header line — and
    # leaving one in is not a harmless no-op: every letter of "Version" is itself
    # a valid base64 character, so it decodes to plausible garbage rather than
    # raising, and the fingerprint comes out silently wrong.
    start = 0
    while start < len(lines) and (not lines[start] or ":" in lines[start]):
        start += 1
    b64 = "".join(line for line in lines[start:] if line and not line.startswith("="))
    if not b64:
        return None
    try:
        data = base64.b64decode(b64, validate=False)
    except Exception:
        return None

    body = _packet_body(data)
    if not body or body[0] != 4:
        # v3 keys use a different (MD5) scheme and are long dead; v6 (RFC 9580)
        # is SHA-256 based and not yet seen in the wild here. Skip rather than
        # emit something that isn't a fingerprint.
        return None
    digest = hashlib.sha1(b"\x99" + struct.pack(">H", len(body)) + body).hexdigest()
    return digest.upper()


def find_fingerprints(text: str) -> list[str]:
    """Extract every PGP fingerprint in ``text`` as 40 uppercase hex chars."""
    found: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        if value not in seen:
            seen.add(value)
            found.append(value)

    for match in _ARMOR.finditer(text):
        fingerprint = fingerprint_from_armor(match.group(1))
        if fingerprint:
            add(fingerprint)

    for match in _SPACED.finditer(text):
        add(re.sub(r"[ \t]", "", match.group(0)).upper())

    for match in _BARE.finditer(text):
        start = max(0, match.start() - _CONTEXT_WINDOW)
        if _PGP_CONTEXT.search(text[start : match.start()]):
            add(match.group(1).upper())

    return found
