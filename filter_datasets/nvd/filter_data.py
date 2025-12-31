import logging
from pathlib import Path

from filter_datasets.util.filter_data import filter_js_files_from_cve_data
from util.cache import write_cache
from util.common import get_data_dirs

logger = logging.getLogger(__name__)


def _filter_fix_references(ref):
    return "Patch" in ref.get("tags", [])


def _check_for_skip(cve):
    vuln_status = cve["vulnStatus"].lower()
    return vuln_status not in ["analyzed", "modified"]


def filter_js_files(data_dir: Path, collected_info_dir: Path):
    logger.info("Filtering nvd")
    result = filter_js_files_from_cve_data(
        caller=__file__, data_dir=data_dir, is_reference_a_fix=_filter_fix_references, check_for_skip=_check_for_skip
    )

    write_cache(collected_info_dir / "filtered_data.json", result)
    return result


if __name__ == "__main__":
    _, cid, dd = get_data_dirs(Path(__file__).parent.name)
    filter_js_files(data_dir=dd, collected_info_dir=cid)
