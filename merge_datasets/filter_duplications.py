import csv
import logging
from pathlib import Path

from tqdm import tqdm

from util.advisory import url_from_ghsa
from util.cache import write_cache, read_cache, convert_merged_data
from util.common import get_data_dirs, MergedCommitData
from util.nvd import url_from_cve
from util.regex import match_commit
from util.snyk import url_from_snyk_id

logger = logging.getLogger(__name__)

CSV_PATH = Path()
DUPLICATIONS_PATH = Path()
SKIPPED_DUPLICATIONS_PATH = Path()

duplications = {}
skipped_duplications = {}


def _init_globals(collected_info_dir: Path):
    global CSV_PATH
    global DUPLICATIONS_PATH
    global SKIPPED_DUPLICATIONS_PATH
    global duplications
    global skipped_duplications

    CSV_PATH = collected_info_dir / "duplications.csv"
    DUPLICATIONS_PATH = collected_info_dir / "duplications.json"
    SKIPPED_DUPLICATIONS_PATH = collected_info_dir / "skipped_duplications.json"

    duplications = read_cache(DUPLICATIONS_PATH)
    skipped_duplications = read_cache(SKIPPED_DUPLICATIONS_PATH)


def _store_duplicate(drop_project, drop_sha, keep_project, keep_sha, merge=False):
    if drop_project not in duplications:
        duplications[drop_project] = {}

    if drop_sha in duplications[drop_project]:
        raise RuntimeError(f"Duplicate sha {drop_sha} in project {drop_project}")

    duplications[drop_project][drop_sha] = {"merge": merge, "project": keep_project, "sha": keep_sha}
    if merge:
        logger.info(f"Stored {drop_project} {drop_sha} for merge into {keep_project} {keep_sha} ")

    else:
        logger.info(f"Stored {drop_project} {drop_sha} for drop because it's duplicate of {keep_project} {keep_sha} ")

    write_cache(DUPLICATIONS_PATH, duplications)


def _skip_duplicate(this_project, this_sha, that_project, that_sha):
    if this_project not in skipped_duplications:
        skipped_duplications[this_project] = {}

    if this_sha not in skipped_duplications[this_project]:
        skipped_duplications[this_project][this_sha] = {}

    if that_project not in skipped_duplications[this_project][this_sha]:
        skipped_duplications[this_project][this_sha][that_project] = []

    if that_sha not in skipped_duplications[this_project][this_sha][that_project]:
        skipped_duplications[this_project][this_sha][that_project].append(that_sha)
        logger.info(f"Stored {this_project} {this_sha} - {that_project} {that_sha} for skip")

    else:
        raise RuntimeError(f"Duplicate sha {this_sha} in project {this_project}")

    write_cache(SKIPPED_DUPLICATIONS_PATH, skipped_duplications)


def _is_duplicate_already_stored(drop_project, drop_sha):
    if d := duplications.get(drop_project, {}).get(drop_sha):
        logger.debug(f"{drop_project} {drop_sha} is already stored for {"merge" if d["merge"] else "drop"}")
        return True

    return False


def _is_duplicate_already_skipped(this_project, this_sha, that_project, that_sha):
    if d := skipped_duplications.get(this_project, {}).get(this_sha, {}).get(that_project, []):
        if that_sha in d:
            logger.debug(f"{this_project} {this_sha} - {that_project} {that_sha} duplication is already skipped")
            return True

    return False


def _is_pair_already_stored(this_project, this_sha, that_project, that_sha):
    return _is_duplicate_already_stored(
        drop_project=this_project, drop_sha=this_sha
    ) or _is_duplicate_already_stored(
        drop_project=that_project, drop_sha=that_sha
    ) or _is_duplicate_already_skipped(
        this_project=this_project, this_sha=this_sha, that_project=that_project, that_sha=that_sha
    )


def _print(num, this_url, md: MergedCommitData):
    logger.info(f"{num} - url: {this_url}")
    logger.info(f"{num} - files cnt: {len(md.files)}")
    logger.info(f"{num} - commit msg: {repr(md.commit_msg)}")
    for cve in md.cve:
        logger.info(f"{num} {url_from_cve(cve)}")

    for ghsa in md.github:
        logger.info(f"{num} {url_from_ghsa(ghsa)}")

    for snyk_id in md.snyk:
        logger.info(f"{num} {url_from_snyk_id(snyk_id)}")

    logger.info(f"{num} - CWE: {md.cwe} OTHERS: {md.others}")
    for source, s_data in md.sources.items():
        logger.info(f"{num} - {source}: {s_data}")


def main(data_dir: Path, collected_info_dir: Path):
    _init_globals(collected_info_dir)
    logger.info("filter duplications")
    with open(CSV_PATH, newline="") as f:
        csv_rows = list(csv.DictReader(f))
        with tqdm(total=len(csv_rows)) as pbar:
            for row in csv_rows:
                pbar.update(1)

                this_project, this_sha = match_commit(row["this_url"])
                that_project, that_sha = match_commit(row["that_url"])
                if _is_pair_already_stored(
                        this_project=this_project, this_sha=this_sha, that_project=that_project, that_sha=that_sha
                ):
                    continue

                metadata_dir = data_dir / "metadata"

                this_md: MergedCommitData = read_cache(metadata_dir / f"{this_project}.json", convert_merged_data)[this_sha]
                that_md: MergedCommitData = read_cache(metadata_dir / f"{that_project}.json", convert_merged_data)[that_sha]

                logger.info("----------------------- new duplication ----------------------------")
                _print("0", row["this_url"], this_md)
                _print("1", row["that_url"], that_md)

                while True:
                    keep = input("keep 0 or 1? 2 = ignore. If metadata merge is also required, type 0m or 1m: ")
                    if keep not in ["0", "1", "2", "0m", "1m"]:
                        logger.warning("Invalid input. Please try again.")
                        continue

                    if keep.startswith("0"):
                        _store_duplicate(
                            keep_project=this_project, keep_sha=this_sha,
                            drop_project=that_project, drop_sha=that_sha,
                            merge=keep == "0m"
                        )

                    elif keep.startswith("1"):
                        _store_duplicate(
                            keep_project=that_project, keep_sha=that_sha,
                            drop_project=this_project, drop_sha=this_sha,
                            merge=keep == "1m"
                        )

                    elif keep == "2":
                        _skip_duplicate(
                            this_project=this_project, this_sha=this_sha, that_project=that_project, that_sha=that_sha
                        )
                        break

                    else:
                        logger.warning("wrong answer, try again")
                        continue

                    break


if __name__ == "__main__":
    _, cid, dd = get_data_dirs("merged_data_no_dup_fixed_eslint_prettier_diffs")
    main(data_dir=dd, collected_info_dir=cid)
