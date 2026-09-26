"""Standalone Python 3 evidence verifier. No Umbra or third-party imports.

Obtain this script through a trusted channel, independently of an untrusted ZIP.
"""
import argparse
import hashlib
import hmac
import json
import re
import zipfile
from pathlib import Path, PurePosixPath


def verify(path, key=None):
    with zipfile.ZipFile(path) as z:
        entries = z.infolist()
        names = [x.filename for x in entries]
        if len(names) != len(set(names)) or len(names) > 10000:
            raise ValueError("Duplicate members or excessive member count")
        if any(x.startswith(("/", "\\")) or "\\" in x or
               ".." in PurePosixPath(x).parts or ":" in x for x in names):
            raise ValueError("Unsafe archive path")
        if sum(x.file_size for x in entries) > 2_000_000_000:
            raise ValueError("Archive exceeds 2 GB verification limit")
        def read(name, maximum=10_000_000):
            if z.getinfo(name).file_size > maximum:
                raise ValueError("Oversized metadata")
            return z.read(name)
        def digest(name):
            h = hashlib.sha256()
            with z.open(name) as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    h.update(chunk)
            return h.hexdigest()
        checksums = read("checksums.sha256")
        expected = {}
        for line in checksums.decode("utf-8").splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
            if not match or match[2] in expected:
                raise ValueError("Invalid checksum list")
            expected[match[2]] = match[1]
        if set(names) - {"checksums.sha256", "signature.txt"} != set(expected):
            raise ValueError("Archive members do not match checksum list")
        for name, wanted in expected.items():
            if not hmac.compare_digest(digest(name), wanted):
                raise ValueError("File checksum mismatch: " + name)
        manifest = json.loads(read("manifest.json"))
        if manifest.get("tool") != "umbra" or manifest.get("bundle_version") not in ("1.1", "1.2"):
            raise ValueError("Unsupported bundle format")
        items = manifest["items"]
        if len(items) != manifest["item_count"]:
            raise ValueError("Item count mismatch")
        signed = "signature.txt" in names
        if bool(manifest["integrity"]["signed"]) != signed:
            raise ValueError("Signature declaration mismatch")
        authenticated = False
        if key is not None:
            if not signed:
                raise ValueError("Expected a signed bundle")
            signature = read("signature.txt").decode("ascii")
            wanted = hmac.new(key, checksums, hashlib.sha256).hexdigest()
            exact = "algorithm: HMAC-SHA256\nover: checksums.sha256\nsignature: " + wanted + "\n"
            if not hmac.compare_digest(exact, signature):
                raise ValueError("Signature authentication failed")
            authenticated = True
        verifiable = 0
        for item in items:
            included, capture = item["included"], item["capture"]
            for kind in ("text", "html"):
                name = included.get(kind + "_file")
                if name and (name not in expected or
                             digest(name) != included.get(kind + "_sha256")):
                    raise ValueError("Artifact hash mismatch")
            body = included.get("body_file")
            matches = bool(body and body in expected and
                           digest(body) == capture.get("body_sha256"))
            if body and not matches:
                raise ValueError("Captured body does not match capture hash")
            if item["body_verifiable"] != matches or item["complete_body_verifiable"] != (
                matches and capture["truncated"] is False
            ):
                raise ValueError("Capture verification claim is inconsistent")
            verifiable += int(matches)
        return {"valid": True, "items": len(items), "verifiable_bodies": verifiable,
                "authenticated": authenticated,
                "notice": "Internal consistency only unless authenticated; no trusted timestamp or proof of source identity."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle")
    parser.add_argument("--key-file", help="Exact UTF-8 HMAC key bytes; no trailing newline")
    args = parser.parse_args()
    try:
        result = verify(args.bundle, Path(args.key_file).read_bytes() if args.key_file else None)
    except (ValueError, KeyError, OSError, zipfile.BadZipFile) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}))
        raise SystemExit(1)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
