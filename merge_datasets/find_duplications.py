import itertools
import logging
from collections import deque
from pathlib import Path

from tqdm import tqdm

from filter_datasets.util.statistics import list_jsons
from util.cache import read_cache, convert_merged_data
from util.common import get_data_dirs, MergedCommitData
from util.git import get_commit_url
from util.merge import project_from_metadata_file_path

logger = logging.getLogger(__name__)


def _write_header_to_csv(csv_path: Path):
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="") as f:
        f.write("type,this_url,that_url\n")


def _write_to_csv(csv_path: Path, type, this_metadata_file_path, this_sha, that_metadata_file_path, that_sha):
    this_project = project_from_metadata_file_path(this_metadata_file_path)
    that_project = project_from_metadata_file_path(that_metadata_file_path)
    this_url = get_commit_url(this_project, this_sha)
    that_url = get_commit_url(that_project, that_sha)
    with open(csv_path, "a", newline="") as f:
        f.write(f"{type},{this_url},{that_url}\n")


def main(data_dir: Path, collected_info_dir: Path):
    csv_path = collected_info_dir / "duplications.csv"
    files_sha_list = deque()
    json_list = list_jsons(dir_path=data_dir / "metadata")
    logger.info("collect commits' data")
    with tqdm(total=len(json_list)) as pbar:
        for metadata_json in json_list:
            pbar.update(1)
            mpd: dict[str, MergedCommitData] = read_cache(metadata_json, convert_merged_data)
            for fix_sha, mcd in mpd.items():
                files_sha_set = {
                    (file.sha, file.filename, file.status)
                    for file in mcd.files
                    if file.changes > 0
                }
                files_sha_list.append((files_sha_set, metadata_json, fix_sha))

    logger.info("write duplications.csv")
    _write_header_to_csv(csv_path=csv_path)
    full_match_cnt = partial_match_cnt = 0
    for (this_set, this_mdfp, this_fs), (that_set, that_mdfp, that_fs) in itertools.combinations(files_sha_list, 2):
        if not this_set or not that_set:
            continue

        if this_set == that_set:
            full_match_cnt += 1
            _write_to_csv(csv_path, "full_match", this_mdfp, this_fs, that_mdfp, that_fs)

        elif not this_set.isdisjoint(that_set):
            if any(
                    a_filename == b_filename and (a_sha != b_sha or a_status != b_status)
                    for (a_sha, a_filename, a_status), (b_sha, b_filename, b_status)
                    in itertools.product(this_set, that_set)
            ):
                continue

            partial_match_cnt += 1
            _write_to_csv(csv_path, "partial_match", this_mdfp, this_fs, that_mdfp, that_fs)

    logger.info(f"full_match_cnt: {full_match_cnt}")
    logger.info(f"partial_match_cnt: {partial_match_cnt}")


if __name__ == "__main__":
    _, cid, dd = get_data_dirs("merged_data_no_dup_fixed_eslint_prettier_diffs")
    main(data_dir=dd, collected_info_dir=cid)
