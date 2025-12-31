import json
import logging

from collections import defaultdict
from pathlib import Path

from tqdm import tqdm

from filter_datasets.util.filter_data import update_result
from util.cache import write_cache
from util.common import get_data_dirs, FilteredData
from util.filter import is_js_file
from util.regex import match_commit

logger = logging.getLogger(__name__)


def filter_js_files(data_dir: Path, collected_info_dir: Path):
    logger.info("Filtering crossvul")
    result = defaultdict(lambda: defaultdict(FilteredData))

    with open(data_dir / "metadata.json", "r", encoding="utf-8") as f:
        metadata = json.load(f)

    with tqdm(total=len(metadata)) as pbar:
        for entry in metadata:
            pbar.update(1)
            project, fix_sha = match_commit(entry["url"])
            if not project or not fix_sha:
                continue

            files = [f["original_name"] for f in entry.get("files", [])]
            js_files = list({f for f in files if is_js_file(f)})
            if not js_files:
                continue

            cves = [entry["cve"]]
            cwes = [entry["cwe"]]

            update_result(
                result=result,
                project=project,
                fix_sha=fix_sha,
                cves=cves,
                cwes=cwes,
                files=js_files,
                caller=__file__
            )

    write_cache(collected_info_dir / "filtered_data.json", result)
    return result


if __name__ == "__main__":
    _, cid, dd = get_data_dirs(Path(__file__).parent.name)
    filter_js_files(data_dir=dd, collected_info_dir=cid)
