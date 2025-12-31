import logging
from pathlib import Path

from filter_datasets.util.filter_data import filter_js_files_from_cve_data
from util.cache import write_cache
from util.common import get_data_dirs

logger = logging.getLogger(__name__)


def _filter_fix_references(ref):
    return ref["type"] == "FIX"


def _check_for_skip(data):
    if "withdrawn" in data:
        return True

    if "details" in data:
        details = data["details"].lower()
        if (details.startswith("rejected reason:") or
                "this advisory has been withdrawn" in details or
                "not a vulnerability" in details):
            return True

    return False


def filter_js_files(data_dir: Path, collected_info_dir: Path):
    logger.info("Filtering osv")
    result = filter_js_files_from_cve_data(
        caller=__file__, data_dir=data_dir, is_reference_a_fix=_filter_fix_references, check_for_skip=_check_for_skip
    )

    write_cache(collected_info_dir / "filtered_data.json", result)
    return result


if __name__ == "__main__":
    _, cid, dd = get_data_dirs(Path(__file__).parent.name)
    filter_js_files(data_dir=dd, collected_info_dir=cid)
