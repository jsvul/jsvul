import shutil
from collections import defaultdict
from pathlib import Path

from util.cache import write_cache
from util.common import GitHubFile, MergedCommitData
from util.label import ExtractedFunction


def get_affected_vuln_functions(
        filtered_files: list[GitHubFile], commit_functions_data: dict[str, list[ExtractedFunction]]
) -> list[tuple[str, ExtractedFunction]]:
    return [
        (file_name, function)
        for file_name, functions in commit_functions_data.items()
        if any(file_name in [f.previous_filename, f.filename] for f in filtered_files)
        for function in functions
        if function.affected
    ]


def _copy_functions(
        data_dir_to: Path, project: str, fix_sha: str,
        vuln_functions: dict[str, list[ExtractedFunction]],
        fix_functions: dict[str, list[ExtractedFunction]]
) -> None:
    functions_dir_to = data_dir_to / "functions" / project / fix_sha
    functions_dir_to.mkdir(parents=True, exist_ok=True)
    write_cache(functions_dir_to / "vuln.json", vuln_functions)
    write_cache(functions_dir_to / "fix.json", fix_functions)


def _copy_file(data_dir_from: Path, data_dir_to: Path, project: str, sha: str, file_path: str, vuln: bool) -> None:
    file_dir_from = data_dir_from / "files" / project / sha / file_path
    if not file_dir_from.exists():
        if not vuln:
            return

        raise ValueError(f"{file_path} doesn't exist")

    file_dir_to = data_dir_to / "files" / project / sha / file_path
    file_dir_to.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(file_dir_from, file_dir_to)


def copy_relevant_files_and_functions(
        affected_vuln_functions: list[tuple[str, ExtractedFunction]], fix_functions: dict[str, list[ExtractedFunction]],
        data_dir_from: Path, data_dir_to: Path, project: str, mcd: MergedCommitData, fix_sha: str
) -> None:
    vuln_functions_map = defaultdict(list)
    for filename, ef in affected_vuln_functions:
        vuln_functions_map[filename].append(ef)

    new_mcd_files = [f for f in mcd.files if (f.previous_filename or f.filename) in vuln_functions_map]
    if not new_mcd_files:
        raise ValueError(f"{fix_sha} doesn't have any vuln functions")

    mcd.files = new_mcd_files

    fix_functions_map = defaultdict(list)
    for f in mcd.files:
        if f.filename in fix_functions:
            fix_functions_map[f.filename] = fix_functions[f.filename]

    for vuln_file_name, _ in affected_vuln_functions:
        matched_files = [f for f in mcd.files if (f.previous_filename or f.filename) == vuln_file_name]
        if len(matched_files) > 1:
            raise RuntimeError(f"Found multiple files {matched_files}")

        matched_file = matched_files[0]

        _copy_file(data_dir_from, data_dir_to, project, mcd.vuln_sha, vuln_file_name, vuln=True)
        _copy_file(data_dir_from, data_dir_to, project, fix_sha, matched_file.filename, vuln=False)

    _copy_functions(
        data_dir_to=data_dir_to, project=project, fix_sha=fix_sha,
        vuln_functions=vuln_functions_map, fix_functions=fix_functions_map
    )


def hash_function(code: str) -> str:
    """
    Return the SHA-256 hex digest of the given code string.
    """
    import hashlib
    return hashlib.sha256(code.encode("utf-8")).hexdigest()
