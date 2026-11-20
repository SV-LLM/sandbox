#!/usr/bin/env python3
"""Deterministic stdlib zipapp and wheel builder. No build-time downloads."""
import base64
import csv
import hashlib
import io
import pathlib
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent
DIST = ROOT / "dist"
VERSION = "0.1.0"
NAME = "stegverse_verify_mcp"


def archive(path, members):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in sorted(members.items()):
            info = zipfile.ZipInfo(name, (2026, 11, 19, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            z.writestr(info, data)


def build():
    DIST.mkdir(exist_ok=True)
    source = (ROOT / "verify_mcp.py").read_bytes()
    archive(DIST / "stegverse-verify-mcp.pyz", {
        "verify_mcp.py": source,
        "__main__.py": b"from verify_mcp import main\nmain()\n"
    })
    prefix = NAME + "-" + VERSION + ".dist-info/"
    metadata = ("Metadata-Version: 2.1\nName: stegverse-verify-mcp\nVersion: " + VERSION
                + "\nSummary: Read-only MCP projection of the 8374 public evidence checker"
                + "\nRequires-Python: >=3.10\nDescription-Content-Type: text/markdown\n\n"
                + (ROOT / "README.md").read_text(encoding="utf-8")).encode()
    members = {
        "verify_mcp.py": source,
        prefix + "METADATA": metadata,
        prefix + "WHEEL": b"Wheel-Version: 1.0\nGenerator: q57-stdlib\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        prefix + "entry_points.txt": b"[console_scripts]\nstegverse-verify-mcp = verify_mcp:main\n"
    }
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for name, data in sorted(members.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow([name, "sha256=" + digest, len(data)])
    writer.writerow([prefix + "RECORD", "", ""])
    members[prefix + "RECORD"] = record.getvalue().encode()
    archive(DIST / (NAME + "-" + VERSION + "-py3-none-any.whl"), members)
    for p in sorted(DIST.iterdir()):
        if p.is_file():
            print(p.name, len(p.read_bytes()), hashlib.sha256(p.read_bytes()).hexdigest())


if __name__ == "__main__":
    build()
