import hashlib
import re
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detect_file_type(path: Path) -> str:
    head = path.read_bytes()[:16]
    suffix = path.suffix.lower()
    signatures = {
        b"\xff\xd8\xff": "image/jpeg",
        b"\x89PNG\r\n\x1a\n": "image/png",
        b"%PDF": "application/pdf",
        b"PK\x03\x04": "application/zip",
    }
    for sig, mime in signatures.items():
        if head.startswith(sig):
            if mime == "application/zip" and suffix in {".docx", ".docm"}:
                return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            return mime
    return f"application/octet-stream ({suffix})"


def _image_metadata(path: Path) -> dict[str, Any]:
    from PIL import Image

    with Image.open(path) as img:
        info = {str(key): str(value) for key, value in img.info.items() if key != "icc_profile"}
        exif = {}
        try:
            exif_data = img.getexif()
            for key, value in exif_data.items():
                if isinstance(value, bytes):
                    value = value.decode("utf-8", "replace")
                exif[str(key)] = str(value)
        except Exception:
            exif = {}
        return {
            "format": img.format,
            "mode": img.mode,
            "width": img.width,
            "height": img.height,
            "info": info,
            "exif": exif,
        }


def _pdf_metadata(path: Path) -> dict[str, Any]:
    from PyPDF2 import PdfReader

    reader = PdfReader(str(path))
    meta = {}
    for key, value in (reader.metadata or {}).items():
        if value is not None:
            meta[str(key).replace("/", "")] = str(value)
    return {
        "pages": len(reader.pages),
        "encrypted": reader.is_encrypted,
        "metadata": meta,
    }


def _docx_metadata(path: Path) -> dict[str, Any]:
    from docx import Document

    doc = Document(str(path))
    props = doc.core_properties
    custom = {}
    with zipfile.ZipFile(path) as archive:
        if "docProps/custom.xml" in archive.namelist():
            root = ElementTree.fromstring(archive.read("docProps/custom.xml"))
            for prop in root.iter():
                if not prop.tag.endswith("property"):
                    continue
                name = prop.attrib.get("name", "")
                values = [elem.text or "" for elem in prop.iter() if elem.text and not elem.tag.endswith("property")]
                custom[name] = " ".join(values)
    return {
        "title": props.title,
        "subject": props.subject,
        "author": props.author,
        "keywords": props.keywords,
        "comments": props.comments,
        "category": props.category,
        "created": str(props.created),
        "modified": str(props.modified),
        "custom_properties": custom,
    }


def hidden_info(path: Path, file_type: str, metadata: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    if file_type == "image/jpeg":
        data = path.read_bytes()
        eoi = data.rfind(b"\xff\xd9")
        trailing = len(data) - eoi - 2 if eoi >= 0 else 0
        if trailing > 16:
            findings.append({"kind": "trailing_data", "description": "JPEG 文件末尾存在额外数据", "bytes": trailing})
    if file_type.startswith("application/vnd.openxmlformats") and metadata.get("custom_properties"):
        findings.append({"kind": "custom_properties", "description": "DOCX 包含自定义属性", "count": len(metadata["custom_properties"])})
    text = str(metadata)
    suspicious = ["password", "secret", "api_key", "token", "credential"]
    for word in suspicious:
        if re.search(word, text, re.IGNORECASE):
            findings.append({"kind": "sensitive_keyword", "description": f"元数据包含敏感关键词 {word}"})
    return {"hidden": bool(findings), "findings": findings}


def extract_metadata(path: Path) -> dict[str, Any]:
    file_type = detect_file_type(path)
    if file_type in {"image/jpeg", "image/png"}:
        metadata = _image_metadata(path)
    elif file_type == "application/pdf":
        metadata = _pdf_metadata(path)
    elif file_type.startswith("application/vnd.openxmlformats"):
        metadata = _docx_metadata(path)
    else:
        metadata = {"unsupported": True}
    return {
        "file_type": file_type,
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
        "metadata": metadata,
        "hidden_info": hidden_info(path, file_type, metadata),
    }
