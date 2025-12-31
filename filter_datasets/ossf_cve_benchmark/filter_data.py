import json
import logging
from collections import defaultdict
from pathlib import Path

from tqdm import tqdm

from filter_datasets.util.filter_data import update_result
from filter_datasets.util.statistics import list_jsons
from util.cache import write_cache
from util.common import get_data_dirs, FilteredData

logger = logging.getLogger(__name__)


def filter_js_files(data_dir: Path, collected_info_dir: Path):
    logger.info("Filtering ossf_cve_benchmark")
    result = defaultdict(lambda: defaultdict(FilteredData))
    cve_files = list_jsons(data_dir)
    with tqdm(total=len(cve_files)) as pbar:
        for cve_file in cve_files:
            pbar.update(1)
            with open(cve_file, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)

            project = cve_data["repository"].split("github.com/")[1].replace('.git', '').lower()
            fix_sha = cve_data["postPatch"]["commit"]
            vuln_sha = cve_data["prePatch"]["commit"]

            files = [
                w["location"]["file"]
                for w in cve_data["prePatch"]["weaknesses"]
            ]

            cves = [cve_data["CVE"]]
            cwes = cve_data["CWEs"]

            update_result(
                result=result,
                project=project,
                fix_sha=fix_sha,
                cves=cves,
                cwes=cwes,
                files=files,
                caller=__file__,
                vuln_sha=vuln_sha
            )

    write_cache(collected_info_dir / "filtered_data.json", result)
    return result


if __name__ == "__main__":
    _, cid, dd = get_data_dirs(Path(__file__).parent.name)
    filter_js_files(data_dir=dd, collected_info_dir=cid)
