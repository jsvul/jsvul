import os
import re
from pathlib import Path


wrong_characters_pattern = re.compile(r'[<>]')


def sanitized_path(file_path: Path) -> Path:
    new_filename = wrong_characters_pattern.sub('_', str(file_path.name))
    return file_path.with_name(new_filename)


def download_file(file_url: str, file_path: Path):
    import requests
    import tempfile

    from util.common import request_with_retries

    file_path = sanitized_path(file_path)

    file_path.parent.mkdir(parents=True, exist_ok=True)
    if file_path.exists():
        return

    r = request_with_retries(4, requests.get, file_url, stream=True, timeout=15)
    with tempfile.NamedTemporaryFile(dir=file_path.parent, delete=False) as tmp:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                tmp.write(chunk)

        tmp_path = Path(tmp.name)

    os.replace(tmp_path, file_path)


def read_file(file_path: Path):
    file_path = sanitized_path(file_path)
    return file_path.read_text(encoding="utf-8", errors="replace")


def write_patch(file_path, patch, force=False):
    patch_file_path = file_path.with_suffix(file_path.suffix + ".patch")
    patch_file_path.parent.mkdir(parents=True, exist_ok=True)
    if patch_file_path.exists():
        if not force:
            return

        patch_file_path.unlink()

    tmp = patch_file_path.with_suffix(patch_file_path.suffix + ".tmp")
    with open(tmp, "wb") as w:
        w.write(patch.encode("utf-8"))
        if not patch.endswith("\n"):
            w.write(b"\n")

    os.replace(tmp, patch_file_path)


def generate_file_sha(file_path: Path) -> str:
    import hashlib

    file_data = file_path.read_bytes()
    header = f"blob {len(file_data)}\0".encode("utf-8")
    sha1 = hashlib.sha1(header + file_data).hexdigest()

    return sha1
