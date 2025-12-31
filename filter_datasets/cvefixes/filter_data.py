import ast
import logging
import sqlite3

from collections import defaultdict
from pathlib import Path

from tqdm import tqdm

from filter_datasets.util.filter_data import update_result
from util.cache import cache, write_cache
from util.common import get_data_dirs, FilteredData
from util.filter import js_file_endings

logger = logging.getLogger(__name__)

CACHE_DIR, DATA_DIR = Path(), Path()

SEPARATOR = "#"


def _init_globals(data_dir: Path):
    global DATA_DIR, CACHE_DIR

    DATA_DIR = data_dir
    cd, _, _ = get_data_dirs(Path(__file__).parent.name)
    CACHE_DIR = cd


def execute_query(query):
    with sqlite3.connect(DATA_DIR / "CVEfixes.db") as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        return cursor.fetchall()


def get_key_from_row(row, columns, index_columns):
    index_col_indices = [i for i, c in enumerate(columns) if c in index_columns]
    return SEPARATOR.join(row[i] for i in index_col_indices)


def get_value_from_row(row, columns, index_columns):
    data_col_indices = [(i, c) for i, c in enumerate(columns) if c not in index_columns]
    return {c: row[i] for i, c in data_col_indices}


def load_table_data(filename, table_name, columns, index_columns, where=None):
    filename = CACHE_DIR / filename

    @cache(filename)
    def collect_data_from():
        query = f"select {', '.join(columns)} from {table_name}"
        if where:
            query = f"{query} where {where}"

        rows = execute_query(query)
        result = {
            get_key_from_row(row, columns, index_columns): get_value_from_row(row, columns, index_columns)
            for row in rows
        }
        return result

    return collect_data_from()


def _process_cve_fixes(cve_fixes):
    fixes = defaultdict(dict)

    for k, v in cve_fixes.items():
        hash, cve_id = k.split(SEPARATOR)
        repo_url = v["repo_url"].lower()
        cve_id = cve_id.upper()
        hash = hash.lower()

        if "repo_url" not in fixes[hash]:
            fixes[hash]["repo_url"] = repo_url

        if "cve_ids" not in fixes[hash]:
            fixes[hash]["cve_ids"] = [cve_id]

        else:
            fixes[hash]["cve_ids"].append(cve_id)

    return fixes


def _process_cwes_list(cwes_list):
    cwes = defaultdict(list)

    for k, v in cwes_list.items():
        cve_id, cwe_id = k.split(SEPARATOR)
        cve_id = cve_id.upper()
        cwe_id = cwe_id.upper()
        if cwe_id not in cwes[cve_id]:
            cwes[cve_id].append(cwe_id)

    return cwes


def _load_data():
    js_file_check = ' or '.join(map(lambda e: f"filename like '%{e}'", js_file_endings))
    file_changes = load_table_data(
        "js_file_changes.json",
        table_name="file_change",
        columns=["file_change_id", "hash", "old_path", "new_path"],
        index_columns=["file_change_id"],
        where=f"{js_file_check}"
    )

    cve_fixes = load_table_data(
        "fixes.json",
        table_name="fixes",
        index_columns=["hash", "cve_id"],
        columns=["hash", "repo_url", "cve_id"]
    )

    fixes = _process_cve_fixes(cve_fixes)

    cwes_list = load_table_data(
        "cwes.json",
        table_name="cwe_classification",
        index_columns=["cve_id", "cwe_id"],
        columns=["cve_id", "cwe_id"]
    )

    cwes = _process_cwes_list(cwes_list)

    commits = load_table_data(
        "commits.json",
        table_name="commits",
        columns=["hash", "parents"],
        index_columns=["hash"]
    )

    return file_changes, fixes, cwes, commits


def filter_js_files(data_dir: Path, collected_info_dir: Path):
    logger.info("Filtering cvefixes")
    _init_globals(data_dir=data_dir)
    result = defaultdict(lambda: defaultdict(FilteredData))
    file_changes, fixes, cwe_map, commits = _load_data()
    with tqdm(total=len(file_changes)) as pbar:
        for fc_id, fc in file_changes.items():
            pbar.update(1)
            fix = fixes[fc["hash"]]

            project = '/'.join(fix["repo_url"].split("/")[-2:]).replace(".git", "")
            fix_sha = fc["hash"]
            parents = ast.literal_eval(commits[fc["hash"]]["parents"])
            if len(parents) > 1:
                raise ValueError(f"Merge commit found: {project} - {fix_sha}")

            vuln_sha = parents[0]

            files = [fc["new_path"] or fc["old_path"]]

            cves = fix["cve_ids"]
            cwes = [cwe for cve_id in cves for cwe in cwe_map[cve_id]]

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
