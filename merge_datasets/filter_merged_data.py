import logging
import os
import shutil
from collections import defaultdict
from dataclasses import dataclass, astuple
from pathlib import Path

from dotenv import load_dotenv
from tqdm import tqdm

from filter_datasets.util.statistics import list_jsons
from util.cache import read_cache, write_cache, convert_merged_data
from util.common import get_data_dirs, MergedCommitData, GitHubFile
from util.file import read_file
from util.filter import is_js_file, is_relevant_file, is_test_file, is_probably_minified
from util.merge import project_from_metadata_file_path

logger = logging.getLogger(__name__)

load_dotenv()

JSMH_PATH = os.getenv("JSMH_PATH")


@dataclass
class FilterParameters:
    data_dir: Path
    project: str
    fix_sha: str
    vuln_sha: str
    files: list[GitHubFile]


def filter_added_removed_files(params: FilterParameters):
    return [f for f in params.files if f.changes > 0 and f.status not in ["added", "removed"]]


def filter_minified_files(params: FilterParameters):
    import subprocess

    def _get_simplified_code(file_path: Path) -> str:
        tmp_file_path = file_path.with_name(file_path.name + ".tmp")
        cmd = [
            "node", JSMH_PATH,
            "-s", ".tmp",
            str(file_path),
        ]
        out = subprocess.run(cmd, capture_output=True)
        stdout = out.stdout.decode("utf-8", errors="replace")
        if stdout.split("\n")[-2] != "SUCCESS":
            logger.debug(f"Failed to extract functions from files.\nCmd: '{cmd}'\nSTDOUT:\n{stdout}")
            code = read_file(file_path)

        else:
            code = read_file(tmp_file_path)

        tmp_file_path.unlink(missing_ok=True)
        return code

    files_dir = params.data_dir / "files" / params.project
    changed_files = [f for f in params.files if f.changes > 0]
    fix_files = [
        (files_dir / params.fix_sha / f.filename, f)
        for f in changed_files
        if f.status != "removed" and is_js_file(f.filename)
    ]
    vuln_files = [
        (files_dir / params.vuln_sha / (f.previous_filename or f.filename), f)
        for f in changed_files
        if f.status != "added" and is_js_file(f.previous_filename or f.filename)
    ]
    result = defaultdict(int)
    for fp, f in fix_files + vuln_files:
        content = _get_simplified_code(fp)
        if not is_probably_minified(content):
            result[astuple(f)] += 1

    return [GitHubFile(*f) for f, cnt in result.items() if cnt > 1]


def filter_irrelevant_files(params: FilterParameters):
    relevant_files = [
        f
        for f in params.files
        if f.changes > 0 and is_js_file(f.filename) and is_relevant_file(f.filename)
    ]
    relevant_files_2 = [
        f
        for f in relevant_files
        if f.status != "renamed" or (is_js_file(f.previous_filename) and is_relevant_file(f.previous_filename))
    ]
    if relevant_files != relevant_files_2:
        raise ValueError(f"{relevant_files} != {relevant_files_2}")

    return relevant_files


def filter_test_files(params: FilterParameters):
    relevant_files = [
        f
        for f in params.files
        if f.changes > 0 and is_js_file(f.filename) and not is_test_file(f.filename)
    ]
    relevant_files_2 = [
        f
        for f in relevant_files
        if f.status != "renamed" or (is_js_file(f.previous_filename) and not is_test_file(f.previous_filename))
    ]
    if relevant_files != relevant_files_2:
        raise ValueError(f"{relevant_files} != {relevant_files_2}")

    return relevant_files


def _filter_files(params: FilterParameters, filters: list):
    filtered_files = []
    for filt in filters:
        filtered_files = filt(params)
        params.files = filtered_files

    return filtered_files


def _copy_file(data_dir_from: Path, data_dir_to: Path, project, sha, filename):
    file_to = data_dir_to / "files" / project / sha / filename
    if file_to.exists():
        return

    file_to.parent.mkdir(parents=True, exist_ok=True)
    file_from = data_dir_from / "files" / project / sha / filename
    shutil.copy(file_from, file_to)


def main(data_dir_from: Path, data_dir_to: Path, filters):
    metadata_list = list_jsons(data_dir_from / "metadata")
    cnt = sum(len(read_cache(mdf, convert_merged_data)) for mdf in metadata_list)
    with tqdm(total=cnt) as pbar:
        for metadata_file in metadata_list:
            project = project_from_metadata_file_path(metadata_file)
            mpd: dict[str, MergedCommitData] = read_cache(metadata_file, convert_merged_data)
            new_mpd = {}
            for fix_sha, mcd in mpd.items():
                pbar.update(1)
                if filters:
                    filtered_files = _filter_files(
                        params=FilterParameters(
                            data_dir=data_dir_from, project=project, fix_sha=fix_sha, vuln_sha=mcd.vuln_sha, files=mcd.files
                        ),
                        filters=filters
                    )

                else:
                    filtered_files = mcd.files

                if not filtered_files:
                    logger.debug(f"https://github.com/{project}/commit/{fix_sha}")
                    continue

                mcd.files = filtered_files
                mcd.additions = sum(f.additions for f in filtered_files)
                mcd.deletions = sum(f.deletions for f in filtered_files)
                mcd.changes = sum(f.changes for f in filtered_files)
                for f in filtered_files:
                    _copy_file(data_dir_from, data_dir_to, project, fix_sha, f.filename)
                    _copy_file(data_dir_from, data_dir_to, project, mcd.vuln_sha, (f.previous_filename or f.filename))

                new_mpd[fix_sha] = mcd

            if new_mpd:
                write_cache(data_dir_to / "metadata" / f"{project}.json", new_mpd)


if __name__ == '__main__':
    _, _, ddf = get_data_dirs("merged_data")
    _, _, ddt = get_data_dirs("merged_data_filtered")
    data_filters = [filter_added_removed_files, filter_irrelevant_files, filter_test_files, filter_minified_files]
    main(data_dir_from=ddf, data_dir_to=ddt, filters=data_filters)
