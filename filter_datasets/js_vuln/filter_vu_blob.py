import json
import logging
from collections import defaultdict
from pathlib import Path

from merge_datasets.merge import get_parent_sha
from util.cache import write_cache
from util.common import get_data_dirs
from util.git import get_full_commit_sha, resolve_repo
from util.regex import match_cve, match_cwe, match_commit

logger = logging.getLogger(__name__)

renamed_repos = {
    "crypto-browserify/crypto-browserify": "browserify/crypto-browserify",
    "zhuangya/node-slug": "dodo/node-slug"
}

removed_repos = {
    "cnpm/node-operadriver": "cnpm/node-operadriver has been removed from github",
    "groupon/selenium-download": "groupon/selenium-download has been removed from github",
}

removed_commits = {
    "rendrjs/rendr-handlebars": {
        "35a134970fe96fee1e448dd62b053cd77a8ca15c"
    }
}


def _default_entry(cve, cwe, vuln_id, fixing_sha):
    return {
        "cve": [*cve],
        "cwe": [cwe] if cwe else [],
        "vuln_id": [vuln_id],
        "fixing_sha": [fixing_sha],
    }


def _update_entry(d, cve, cwe, vuln_id, fixing_sha):
    d["cve"].extend(c for c in cve if c not in d["cve"])
    if cwe and cwe not in d["cwe"]:
        d["cwe"].append(cwe)

    if vuln_id and vuln_id not in d["vuln_id"]:
        d["vuln_id"].append(vuln_id)

    if fixing_sha and fixing_sha not in d["fixing_sha"]:
        d["fixing_sha"].append(fixing_sha)


def main(data_dir: Path, collected_info_dir: Path):
    logger.info(f"Filtering vu_blob data of js_vul")
    result = defaultdict(lambda: defaultdict(dict))
    with open(data_dir / "vu_blob.json", "r") as f:
        data = json.load(f)

    for entry in data:
        parent_hash = entry["parent_hash"]
        if len(parent_hash) < 1:
            continue

        cve_ids = {match_cve(cve) for cve in entry["cve_ids"]}
        cve = {cve for cve in cve_ids if cve}

        cwe = match_cwe(entry["cwe_id"])

        vuln_id = entry["vuln_id"]
        if len(parent_hash) > 1:
            raise ValueError(f"WTF: {entry}")

        parent_hash = next(iter(parent_hash)).lower()
        if entry["commits"]:
            for commit_url in entry["commits"]:
                project, fix_sha = match_commit(commit_url)
                if not project or not fix_sha:
                    raise ValueError(f"Could not process url: {commit_url}")

                if project in removed_repos:
                    continue

                old_project = project
                if project in renamed_repos:
                    project = renamed_repos[project]

                project = resolve_repo(project).lower()
                parent_hash = get_full_commit_sha(project, parent_hash)
                if not parent_hash:
                    parent_hash = get_parent_sha(project, fix_sha)

                parent_hash = parent_hash.lower()
                fix_sha = get_full_commit_sha(project, fix_sha).lower()
                if parent_hash not in result[project]:
                    result[project][parent_hash] = _default_entry(cve, cwe, vuln_id, fix_sha)
                    if old_project != project:
                        result[project][parent_hash]["old_project"] = old_project

                else:
                    d = result[project][parent_hash]
                    _update_entry(d, cve, cwe, vuln_id, fix_sha)

    write_cache(collected_info_dir / "vu_blob_data.json", result)
    return result


if __name__ == "__main__":
    _, cid, dd = get_data_dirs(Path(__file__).parent.name)
    main(data_dir=dd, collected_info_dir=cid)
