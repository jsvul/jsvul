import logging
import shutil
from collections import defaultdict
from pathlib import Path

from tqdm import tqdm

from filter_datasets.util.statistics import list_jsons
from util.cache import read_cache, write_cache, convert_merged_data
from util.common import get_data_dirs, MergedCommitData
from util.merge import project_from_metadata_file_path

logger = logging.getLogger(__name__)

FILES_FROM = Path()
METADATA_FROM = Path()

FILES_TO = Path()
METADATA_TO = Path()

DUPLICATIONS = {}


def _init_globals(data_dir_from: Path, data_dir_to: Path, collected_info_dir: Path):
    global FILES_FROM
    global METADATA_FROM
    global FILES_TO
    global METADATA_TO
    global DUPLICATIONS

    FILES_FROM = data_dir_from / "files"
    METADATA_FROM = data_dir_from / "metadata"

    FILES_TO = data_dir_to / "files"
    METADATA_TO = data_dir_to / "metadata"

    DUPLICATIONS = read_cache(collected_info_dir / "duplications.json")


def _copy_files(project, sha, files: list[str], copy_patches=False):
    from_dir = FILES_FROM / project / sha
    to_dir = FILES_TO / project / sha

    if not from_dir.exists():
        raise ValueError("source not exists")

    for file_name in files:
        js_file_to = to_dir / file_name
        js_file_from = from_dir / file_name
        if not js_file_to.exists():
            js_file_to.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(js_file_from, js_file_to)

        if not copy_patches:
            continue

        patch_file_from = js_file_from.with_name(js_file_from.name + ".patch")
        if not patch_file_from.exists():
            continue

        patch_file_to = js_file_to.with_name(js_file_to.name + ".patch")
        if not patch_file_to.exists():
            shutil.copy(patch_file_from, patch_file_to)


def _copy_non_duplicates():
    keep_for_merge = defaultdict(lambda: defaultdict(dict))
    json_list_from = list_jsons(METADATA_FROM)
    mcd_cnt = sum(len(read_cache(j, convert_merged_data)) for j in json_list_from)
    logger.info("Remove duplications and collect commits to merge")
    with tqdm(total=mcd_cnt) as pbar:
        for metadata_file_path_from in json_list_from:
            project = project_from_metadata_file_path(metadata_file_path_from)
            mdp_from: dict[str, MergedCommitData] = read_cache(metadata_file_path_from, convert_merged_data)
            mdp_to = {}
            mdp_path_to = METADATA_TO / f"{project}.json"
            for fix_sha, mcd_from in mdp_from.items():
                pbar.update(1)
                vuln_sha = mcd_from.vuln_sha
                if d := DUPLICATIONS.get(project, {}).get(fix_sha):
                    if d["merge"]:
                        kfm = keep_for_merge[project][fix_sha]
                        kfm["mcd"] = mcd_from
                        kfm["project"] = d["project"]
                        kfm["sha"] = d["sha"]

                else:
                    fix_files = [
                        f.filename
                        for f in mcd_from.files
                        if f.changes > 0 and f.status in ["added", "modified", "renamed"]
                    ]
                    if fix_files:
                        _copy_files(project=project, sha=fix_sha, files=fix_files, copy_patches=True)

                    vuln_files = [
                        (f.previous_filename or f.filename)
                        for f in mcd_from.files
                        if f.changes > 0 and f.status in ["removed", "modified", "renamed"]
                    ]
                    if vuln_files:
                        _copy_files(project=project, sha=vuln_sha, files=vuln_files)

                    if fix_files or vuln_files:
                        mdp_to[fix_sha] = mcd_from

            if mdp_to:
                write_cache(mdp_path_to, mdp_to)

    logger.info("Merge commits")
    kfm_cnt = sum(len(p_data) for p_data in keep_for_merge.values())
    with tqdm(total=kfm_cnt) as pbar:
        for project, p_data in keep_for_merge.items():
            for fix_sha, kfm in p_data.items():
                pbar.update(1)
                keep_project = kfm["project"]
                mpd_to_path = METADATA_TO / f"{keep_project}.json"
                mdp_to = read_cache(mpd_to_path, convert_merged_data)

                keep_sha = kfm["sha"]
                if keep_sha not in mdp_to:
                    keep_sha = DUPLICATIONS[keep_project][keep_sha]["sha"]

                mdp_to[keep_sha].merge_data_from(kfm["mcd"])

                write_cache(mpd_to_path, mdp_to)


def main(data_dir_from: Path, data_dir_to: Path, collected_info_dir: Path):
    _init_globals(data_dir_from, data_dir_to, collected_info_dir)
    _copy_non_duplicates()


if __name__ == "__main__":
    _, cid, ddf = get_data_dirs("01_filtered")
    _, _, ddt = get_data_dirs("02_no_dup")
    main(data_dir_from=ddf, data_dir_to=ddt, collected_info_dir=cid)
