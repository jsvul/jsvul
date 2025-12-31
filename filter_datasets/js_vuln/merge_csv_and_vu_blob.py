import logging
from collections import defaultdict
from pathlib import Path

from filter_datasets.js_vuln.utils import load_json_file
from util.cache import write_cache
from util.common import get_data_dirs

logger = logging.getLogger(__name__)


def main(_, collected_info_dir: Path):
    logger.info("Merging csv and vu_blob of js_vul")
    result = defaultdict(dict)

    csv_data = load_json_file(collected_info_dir / "csv_data.json")
    vu_blob_data = load_json_file(collected_info_dir / "vu_blob_data.json")

    for project, p_data in csv_data.items():
        for vuln_sha, files in p_data.items():
            vb_data = vu_blob_data[project][vuln_sha]
            fixing_commit_sha_list = vb_data["fixing_sha"]
            for fix_sha in fixing_commit_sha_list:
                if fix_sha not in result[project]:
                    result[project][fix_sha] = {
                        "files": files,
                        "vuln_sha": vuln_sha,
                        "cve": vb_data["cve"],
                        "cwe": vb_data["cwe"],
                        "vuln_id": vb_data["vuln_id"],
                    }
                    if "old_project" in vb_data:
                        result[project][fix_sha]["old_project"] = vb_data["old_project"]

                else:
                    raise ValueError(
                        f"Duplicate fixing commit sha {fix_sha} for {project} {vuln_sha} in vu_blob_data"
                    )

    write_cache(collected_info_dir / "merged_csv_and_vu_blob.json", result)
    return result


if __name__ == "__main__":
    _, cid, _ = get_data_dirs(Path(__file__).parent.name)
    main(_, collected_info_dir=cid)
