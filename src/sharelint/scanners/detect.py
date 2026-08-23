"""Content-based format detection; extensions are hints, never the authority."""

from __future__ import annotations

from pathlib import PurePosixPath

TEXT_EXTENSIONS = {
    ".cfg",
    ".conf",
    ".csv",
    ".env",
    ".html",
    ".ini",
    ".json",
    ".log",
    ".md",
    ".rst",
    ".sql",
    ".toml",
    ".tsv",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


def extension(name: str) -> str:
    return PurePosixPath(name.replace("\\", "/")).suffix.lower()


def detect_kind(name: str, data: bytes) -> str:
    head = data[:64]
    suffix = extension(name)
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if head[:4] in {b"II*\x00", b"MM\x00*"}:
        return "tiff"
    if head.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "webp"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        if suffix in {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"}:
            return "office-ole"
        return "ole"
    stripped = data[:4096].lstrip().lower()
    if stripped.startswith(b"<?xml") and b"<svg" in stripped:
        return "svg"
    if stripped.startswith(b"<svg"):
        return "svg"
    if suffix in TEXT_EXTENSIONS or looks_like_text(data):
        return "text"
    return "binary"


def looks_like_text(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:8192]
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        return True
    if b"\x00" in sample:
        return False
    try:
        decoded = sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not decoded:
        return True
    controls = sum(ord(char) < 32 and char not in "\n\r\t\f\b" for char in decoded)
    return controls / len(decoded) < 0.02


def decode_text(data: bytes, max_chars: int) -> str | None:
    sample = data[: max_chars * 4]
    encodings: tuple[str, ...]
    if sample.startswith(b"\xff\xfe"):
        encodings = ("utf-16-le",)
    elif sample.startswith(b"\xfe\xff"):
        encodings = ("utf-16-be",)
    else:
        encodings = ("utf-8",)
    for encoding in encodings:
        try:
            return sample.decode(encoding)[:max_chars]
        except UnicodeDecodeError:
            continue
    return None
