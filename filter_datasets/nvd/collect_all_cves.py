import logging

from pathlib import Path

from util.cache import write_cache
from util.common import get_data_dirs
from util.nvd import get_all_cve_from

logger = logging.getLogger(__name__)
STEP_SIZE = 2000


def main(data_dir: Path):
    data_dir.mkdir(parents=True, exist_ok=True)
    data = get_all_cve_from(start_index=0)
    total_results = data.get("totalResults", 0)
    for start_index in range(0, total_results, STEP_SIZE):
        logger.info(f"Fetching CVEs from index {start_index} to {min(start_index + STEP_SIZE, total_results)}")
        data = get_all_cve_from(start_index=start_index)
        cve_items = data.get("vulnerabilities", [])
        for item in cve_items:
            cve = item["cve"]
            write_cache(data_dir / f"{cve["id"]}.json", cve)


if __name__ == "__main__":
    _, _, dd = get_data_dirs("nvd")
    main(data_dir=dd)
