import logging

import pandas as pd

from collections import defaultdict
from pathlib import Path

from util.cache import write_cache
from util.common import get_data_dirs
from util.filter import is_js_file
from util.git import get_full_commit_sha, resolve_repo
from util.regex import match_commit

logger = logging.getLogger(__name__)

renamed_repos = {
    "crypto-browserify/crypto-browserify": "browserify/crypto-browserify",
    "zhuangya/node-slug": "dodo/node-slug"
}

removed_repos = {
    "cnpm/node-operadriver": "cnpm/node-operadriver has been removed from github",
    "groupon/selenium-download": "groupon/selenium-download has been removed from github",
}


def process_csv(data_dir: Path, collected_info_dir: Path):
    logger.info(f"Filtering csv data of js_vul")
    result = defaultdict(lambda: defaultdict(list))
    df = pd.read_csv(data_dir / "JSVulnerabilityDataSet-1.0.csv")

    for index, row in df.iterrows():
        project, vuln_sha = match_commit(row['full_repo_path'])
        if not project or not vuln_sha:
            raise ValueError(f"Could not extract project or commit hash from {row['full_repo_path']}")

        if project in renamed_repos:
            project = renamed_repos[project]

        if project in removed_repos:
            continue

        new_project = resolve_repo(project).lower()
        file = row['path']
        if not is_js_file(file):
            continue

        vuln_sha = get_full_commit_sha(new_project, vuln_sha).lower()
        if row["Vuln"] == 1 and file not in result[new_project][vuln_sha]:
            result[new_project][vuln_sha].append(file)

    write_cache(collected_info_dir / "csv_data.json", result)
    return result


if __name__ == "__main__":
    _, cid, dd = get_data_dirs(Path(__file__).parent.name)
    process_csv(data_dir=dd, collected_info_dir=cid)
