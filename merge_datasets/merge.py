import logging
from pathlib import Path
from urllib.parse import quote

from tqdm import tqdm

from util.advisory import collect_cves_from_ghsa, collect_cwes_from_ghsa, collect_publish_time_from_ghsa
from util.cache import read_cache, write_cache, convert_filtered_data, convert_merged_data
from util.common import get_data_dirs, GitHubFile, MergedCommitData, order_dict, Date
from util.file import download_file
from util.filter import is_js_file
from util.git import get_stats_and_files, get_diff_files, get_parents_and_files, get_commit_message, get_commit_url
from util.nvd import collect_cwes_from_cve, is_cve_valid, get_publish_time
from util.snyk import collect_cves_from_snyk_url, collect_cwes_from_snyk_url, get_introduce_time, url_from_snyk_id

logger = logging.getLogger(__name__)

FILES_DIR = Path()

# sometimes direct parent is not the real vulnerable commit
# project -> fix_sha -> vuln_sha
REAL_VULN_COMMITS = {
    "angular/angular.js": {
        "48fa3aadd546036c7e69f71046f659ab1de244c6": "2df721965bccdfbbaeed5d5624892accf698e768"
    }
}


def _init_globals(data_dir: Path):
    global FILES_DIR

    FILES_DIR = data_dir / "files"


def _get_filtered_data_file_path(dataset_name: str):
    _, collected_info_dir, _ = get_data_dirs(dataset_name)
    return collected_info_dir / "filtered_data.json"


def _write_file(project: str, sha: str, file_name: str):
    url = f"https://raw.githubusercontent.com/{project}/{sha}/{quote(file_name)}"

    js_file_path = FILES_DIR / project / sha / file_name
    download_file(url, js_file_path)


def _write_changed_files(project: str, fix_sha: str, vuln_sha: str, changed_files: list[dict]):
    for f in changed_files:
        if f["status"] in ["modified", "renamed"]:
            _write_file(project=project, sha=fix_sha, file_name=f["filename"])
            _write_file(project=project, sha=vuln_sha, file_name=f.get("previous_filename", f["filename"]))

        if f["status"] == "added":
            _write_file(project=project, sha=fix_sha, file_name=f["filename"])

        if f["status"] == "removed":
            _write_file(project=project, sha=vuln_sha, file_name=f["filename"])


def get_parent_sha(project, fix_sha):
    if project in REAL_VULN_COMMITS and fix_sha in REAL_VULN_COMMITS[project]:
        return REAL_VULN_COMMITS[project][fix_sha]

    parents, files = get_parents_and_files(project, fix_sha)
    url = get_commit_url(project, fix_sha)

    files = order_dict(files)

    vuln_sha = ""
    parents_cnt = 0
    for parent_sha in parents:
        diff_files = get_diff_files(project, fix_sha, parent_sha)
        diff_files = order_dict(diff_files)
        if files == diff_files:
            parents_cnt += 1
            vuln_sha = parent_sha

    if parents_cnt > 1:
        raise ValueError(f"Multiple valid parents found for {url}. Parents: {parents}")

    elif parents_cnt < 1:
        raise ValueError(f"No valid parents found for {url}. Parents: {parents}")

    return vuln_sha


def _fill_array(target_array, vuln_ids, vuln_url_prefix, collect_values_from_vuln_url, check_value):
    values_from_vuln_url = set()
    for vuln_id in vuln_ids:
        vuln_url = f"{vuln_url_prefix}{vuln_id}"
        logger.debug(f" {vuln_url}")
        for value in collect_values_from_vuln_url(vuln_url):
            values_from_vuln_url.add(value)

    values_from_vuln_url = {cve for cve in values_from_vuln_url if check_value(cve)}
    if len(values_from_vuln_url) > 1 and "CWE" not in value:
        logger.debug(f"CWE not in {value}")

    for value in values_from_vuln_url:
        target_array.append(value)


def _list_without_none(date_list) -> list[Date]:
    return [t for t in date_list if t is not None]


def _get_timestamp(mcd: MergedCommitData):
    dates = []

    dates.extend(_list_without_none(get_publish_time(cve) for cve in mcd.cve))
    dates.extend(_list_without_none(collect_publish_time_from_ghsa(ghsa) for ghsa in mcd.github))
    dates.extend(_list_without_none(get_introduce_time(url_from_snyk_id(snyk_id)) for snyk_id in mcd.snyk))

    if not dates:
        return None

    return sorted(dates)[0]


def _process_entry(mpd_path, mpd, project, fix_sha, dataset, filtered_data):
    if fix_sha not in mpd:
        stats, files = get_stats_and_files(project, fix_sha)
        if not stats or not files:
            logger.debug(f"No stats or files for {project} {fix_sha}")
            return

        if stats["total"] != sum(f["changes"] for f in files):
            logger.debug(f"Stats mismatch for {project} {fix_sha}, skipping...")
            return

        changed_files = [f for f in files if f["changes"] > 0 and f["raw_url"] and f["blob_url"]]

        if not any(is_js_file(f["filename"]) for f in changed_files):
            logger.debug(f"No js files in {project} {fix_sha}, skipping...")
            logger.debug(f"https://github.com/{project}/commit/{fix_sha}")
            return

        vuln_sha = get_parent_sha(project, fix_sha)

        _write_changed_files(project, fix_sha, vuln_sha, changed_files)
        mpd[fix_sha] = MergedCommitData(
            vuln_sha=vuln_sha,
            commit_msg=get_commit_message(project, fix_sha),
            files=[GitHubFile.from_dict(f, force=True) for f in files],
            additions=stats.get("additions"),
            deletions=stats.get("deletions"),
            changes=stats.get("total"),
        )

    mcd: MergedCommitData = mpd[fix_sha]
    if dataset in mcd.sources:
        logger.debug(f"Entry for {project} {fix_sha} from {dataset} already exists, skipping...")
        return

    mcd.cve = mcd.cve or filtered_data.cve or []
    if not mcd.cve and filtered_data.github:
        _fill_array(
            target_array=mcd.cve, vuln_ids=filtered_data.github,
            vuln_url_prefix="https://github.com/advisories/",
            collect_values_from_vuln_url=collect_cves_from_ghsa,
            check_value=is_cve_valid
        )

    if not mcd.cve and filtered_data.snyk:
        _fill_array(
            target_array=mcd.cve, vuln_ids=filtered_data.snyk,
            vuln_url_prefix="https://security.snyk.io/vuln/",
            collect_values_from_vuln_url=collect_cves_from_snyk_url,
            check_value=is_cve_valid
        )

    if not mcd.cve:
        logger.debug(f"No CVE for {project} {fix_sha}")
        logger.debug(filtered_data.to_dict())
        logger.debug("")

    mcd.cwe = mcd.cwe or filtered_data.cwe or []
    if not mcd.cwe and mcd.cve:
        cwes_from_cve = set()
        for cve in mcd.cve:
            cwes_from_cve |= collect_cwes_from_cve(cve)

        mcd.cwe = list(cwes_from_cve)

    if not mcd.cwe and filtered_data.github:
        _fill_array(
            target_array=mcd.cwe, vuln_ids=filtered_data.github,
            vuln_url_prefix="https://github.com/advisories/",
            collect_values_from_vuln_url=collect_cwes_from_ghsa,
            check_value=lambda _: True
        )

    if not mcd.cwe and filtered_data.snyk:
        _fill_array(
            target_array=mcd.cwe, vuln_ids=filtered_data.snyk,
            vuln_url_prefix="https://security.snyk.io/vuln/",
            collect_values_from_vuln_url=collect_cwes_from_snyk_url,
            check_value=lambda _: True
        )

    if not mcd.cwe:
        logger.debug(f"No CWE for {project} {fix_sha}")
        logger.debug(filtered_data.to_dict())
        logger.debug("")

    if filtered_data.github:
        mcd.github = list(set(mcd.github + filtered_data.github))

    if filtered_data.snyk:
        mcd.snyk = list(set(mcd.snyk + filtered_data.snyk))

    if filtered_data.others:
        mcd.others = list(set(mcd.others + filtered_data.others))

    publish_time = _get_timestamp(mcd)
    if not mcd.publish_time:
        mcd.publish_time = publish_time

    else:
        mcd.publish_time = min(mcd.publish_time, publish_time)

    mcd.sources[dataset] = filtered_data.to_cve_data()
    if filtered_data.vuln_sha and mcd.vuln_sha != filtered_data.vuln_sha:
        raise ValueError(f"Vulnerable SHA mismatch for {project} {fix_sha}, skipping...")

    write_cache(mpd_path, mpd)


def main(datasets: list[str], data_dir: Path):
    _init_globals(data_dir)
    dataset_cnt = len(datasets)
    logger.info(f"merge datasets: {datasets}")
    for i, dataset in enumerate(datasets, 1):
        logger.info(f"{i}/{dataset_cnt}: {dataset}")
        data_file = _get_filtered_data_file_path(dataset_name=dataset)
        if not data_file.exists():
            raise ValueError(f"Data file for {dataset} does not exist, skipping...")

        data = read_cache(data_file, convert_filtered_data)
        fd_cnt = sum(len(p_data) for p_data in data.values())
        with tqdm(total=fd_cnt) as pbar:
            for project, p_data in data.items():
                mpd_path = data_dir / "metadata" / f"{project}.json"
                mpd = read_cache(mpd_path, convert_merged_data)
                for fix_sha, filtered_data in p_data.items():
                    pbar.update(1)
                    _process_entry(
                        mpd_path=mpd_path, mpd=mpd,
                        project=project, fix_sha=fix_sha,
                        dataset=dataset, filtered_data=filtered_data
                    )


if __name__ == "__main__":
    _, _, dd = get_data_dirs("merged_data")
    all_datasets = ["nvd", "osv", "ossf_cve_benchmark", "js_vuln", "cvefixes", "crossvul", "secbenchjs"]
    main(datasets=all_datasets, data_dir=dd)
