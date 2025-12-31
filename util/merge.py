from pathlib import Path


def project_from_metadata_file_path(file_path: Path) -> str:
    return f"{file_path.parent.name}/{file_path.stem}"
