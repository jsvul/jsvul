import json
import logging

from collections import defaultdict
from pathlib import Path

from tqdm import tqdm

from filter_datasets.util.filter_data import update_result
from filter_datasets.util.statistics import list_jsons
from util.advisory import ghsa_from_url
from util.cache import write_cache
from util.common import get_data_dirs, FilteredData
from util.git import get_merge_commit_sha
from util.regex import match_commit, match_pr
from util.snyk import snyk_id_from_url

logger = logging.getLogger(__name__)


def filter_js_files(data_dir: Path, collected_info_dir: Path):
    logger.info("Filtering secbenchjs")
    result = defaultdict(lambda: defaultdict(FilteredData))
    cve_files = list_jsons(data_dir)
    with tqdm(total=len(cve_files)) as pbar:
        for cve_file in cve_files:
            pbar.update(1)
            with open(cve_file, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)

            if "fixCommit" not in cve_data or cve_data["fixCommit"] in ["N/A", "n/a", ""]:
                continue

            project, fix_sha = match_commit(cve_data["fixCommit"])
            if not project or not fix_sha:
                project, pr_id = match_pr(cve_data["fixCommit"])
                fix_sha = get_merge_commit_sha(project, pr_id)
                if not fix_sha:
                    continue

            file = cve_data.get("sink")
            files = []
            if file:
                file = file.split(":")[0]
                files.append(file)

            cves = [cve_data.get("id", "")]

            snyk = []
            github = []
            for url in (cve_data.get("links") or cve_data.get("link") or {}).values():
                if "snyk.io/" in url:
                    snyk_id = snyk_id_from_url(url)
                    if not snyk_id:
                        raise ValueError(f"Invalid Snyk URL: {url}")

                    snyk.append(snyk_id)

                if "github.com/advisories/" in url:
                    github_id = ghsa_from_url(url)
                    if not github_id:
                        if "ghsl" not in url.lower():
                            raise ValueError(f"Invalid GitHub Advisory URL: {url}")

                    else:
                        github.append(github_id)

            update_result(
                result=result,
                project=project,
                fix_sha=fix_sha,
                cves=cves,
                files=files,
                caller=__file__,
                snyk=snyk,
                github=github
            )

    write_cache(collected_info_dir / "filtered_data.json", result)
    return result


if __name__ == "__main__":
    _, cid, dd = get_data_dirs(Path(__file__).parent.name)
    filter_js_files(data_dir=dd, collected_info_dir=cid)
