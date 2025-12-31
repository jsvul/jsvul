import logging
import re
from pathlib import Path

from tqdm import tqdm

from merge_datasets.git_diff import generate_git_diff
from filter_datasets.util.statistics import list_jsons
from util.cache import read_cache, write_cache, convert_merged_data
from util.common import get_data_dirs, GitHubFile, MergedCommitData
from util.file import write_patch, generate_file_sha
from util.merge import project_from_metadata_file_path

logger = logging.getLogger(__name__)

GENERATION_CACHE_DIR, _, _ = get_data_dirs("patches_generated")

DATA_DIR = Path()

diff_header_pattern = re.compile(r'@@ -\d+,(\d+) \+\d+,(\d+) @@')
diff_part_pattern = re.compile(r'@@.*?@@[\s\S]*?(?=^@@|(?![\s\S]))', re.MULTILINE)


def _init_globals(data_dir: Path):
    global DATA_DIR

    DATA_DIR = data_dir


def _calculate_changes_from_diff(diff_lines: list[str]) -> tuple[int, int, int]:
    added, removed = 0, 0
    for line in diff_lines:
        if line.startswith("+"):
            added += 1

        if line.startswith("-"):
            removed += 1

    changes = added + removed
    return added, removed, changes


def _get_new_patch(new_file_path: Path, old_file_path: Path) -> tuple[str, int, int, int]:
    new_patch = generate_git_diff(old_file_path, new_file_path)
    new_patch_lines = new_patch.splitlines()
    added, removed, changes = _calculate_changes_from_diff(new_patch_lines)
    return new_patch, added, removed, changes


def _remove_dir_if_empty(dir_path: Path):
    import os

    try:
        os.rmdir(dir_path)

    except OSError:
        pass


def _process_file(project: str, sha: str, mcd: MergedCommitData, file: GitHubFile):
    new_file = GitHubFile(**file.to_dict())
    project_dir = DATA_DIR / "files" / project

    fix_file_path = project_dir / sha / file.filename
    vuln_file_path = project_dir / mcd.vuln_sha / (file.previous_filename or file.filename)

    new_patch, new_additions, new_deletions, new_changes = _get_new_patch(
        new_file_path=fix_file_path, old_file_path=vuln_file_path
    )

    if new_changes == 0:
        return None

    write_patch(fix_file_path, new_patch, force=True)
    new_file.additions = new_additions
    new_file.deletions = new_deletions
    new_file.changes = new_changes
    new_file.sha = generate_file_sha(fix_file_path)
    return new_file


def _process_commit_data(log_prefix: str, project: str, sha: str, mcd: MergedCommitData):
    new_mcd = MergedCommitData(**mcd.to_dict())
    files_cnt = len(mcd.files)
    remove_files = []
    for i, f in enumerate(mcd.files):
        if f.status not in ["modified", "renamed"]:
            continue

        logger.debug(f"{log_prefix} - {i + 1}/{files_cnt}: {f.filename}")
        new_f = _process_file(project=project, sha=sha, mcd=mcd, file=f)
        if new_f is not None:
            new_mcd.files[i] = new_f

        else:
            remove_files.append(i)

    new_mcd.files = [f for i, f in enumerate(new_mcd.files) if i not in remove_files]

    new_mcd.additions = sum(f.additions for f in new_mcd.files)
    new_mcd.deletions = sum(f.deletions for f in new_mcd.files)
    new_mcd.changes = sum(f.changes for f in new_mcd.files)
    return new_mcd


def _process_metadata_json(metadata_path: Path):
    project = project_from_metadata_file_path(metadata_path)
    mpd = read_cache(metadata_path, convert_merged_data)
    if not mpd:
        return

    new_mpd = {}
    sha_cnt = len(mpd)
    for i, (sha, mcd) in enumerate(mpd.items(), 1):
        new_mcd = _process_commit_data(
            log_prefix=f"{i}/{sha_cnt}: {sha}",
            project=project,
            sha=sha,
            mcd=mcd
        )
        if new_mcd.changes > 0:
            new_mpd[sha] = new_mcd

    if new_mpd:
        write_cache(file_name=metadata_path, cache=new_mpd)

    else:
        metadata_path.unlink()
        _remove_dir_if_empty(metadata_path.parent)


def main(data_dir: Path):
    _init_globals(data_dir)
    json_list = list_jsons(data_dir / "metadata")
    generation_cache_path = GENERATION_CACHE_DIR / "projects.json"
    generation_cache = read_cache(generation_cache_path)
    with tqdm(total=len(json_list)) as pbar:
        for json_file in json_list:
            pbar.update(1)
            relative_metadata_path = json_file.relative_to(data_dir / "metadata")
            if relative_metadata_path.as_posix() in generation_cache:
                continue

            _process_metadata_json(
                metadata_path=json_file
            )
            generation_cache[relative_metadata_path.as_posix()] = True
            write_cache(generation_cache_path, generation_cache)


if __name__ == "__main__":
    _, _, dd = get_data_dirs("saved/latest/05_prettier")
    main(data_dir=dd)
