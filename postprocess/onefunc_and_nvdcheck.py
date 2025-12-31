import re
from collections import defaultdict
from dataclasses import astuple, dataclass
from pathlib import Path

from tqdm import tqdm

from filter_datasets.util.statistics import list_jsons
from util.cache import read_cache, write_cache, convert_merged_data, convert_extracted_data
from util.common import MergedCommitData, get_data_dirs
import util.nvd as nvd
from util.label import ExtractedFunction
from util.merge import project_from_metadata_file_path
from util.postprocess import get_affected_vuln_functions, copy_relevant_files_and_functions, hash_function


@dataclass
class FunctionInfo:
    filename: str
    vuln: bool
    function_body: str
    function_name: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int


def _ef_to_function_info(filename: str, ef: ExtractedFunction) -> FunctionInfo:
    return FunctionInfo(
        filename=filename, vuln=ef.vuln, function_body=ef.function_body, function_name=ef.function_name,
        start_line=ef.start_line, start_column=ef.start_column, end_line=ef.end_line, end_column=ef.end_column,
    )


def _is_identifier_mentioned(text: str, name: str) -> bool:
    pattern = rf'(?<![A-Za-z0-9_$]){re.escape(str(name))}(?![A-Za-z0-9_$])'
    return bool(re.search(pattern, text))


def _nvdcheck_core(affected_vuln_functions, description: str, filename: str, ef: ExtractedFunction):
    if _is_identifier_mentioned(text=description, name=filename):
        if len([ef for fn, ef in affected_vuln_functions if fn == filename]) == 1:
            return True

    return ef.function_name and _is_identifier_mentioned(text=description, name=ef.function_name)


def _nvdcheck_filter(affected_vuln_functions, mcd):
    commit_cve_descriptions = []
    for cve in mcd.cve:
        descriptions = nvd.get_descriptions(cve)
        if descriptions:
            for description in descriptions:
                commit_cve_descriptions.append(description)

    nvd_mentioned_affected_functions = []

    for filename, ef in affected_vuln_functions:
        for desc in commit_cve_descriptions:
            if _nvdcheck_core(affected_vuln_functions, desc, filename, ef):
                nvd_mentioned_affected_functions.append((filename, ef))
                break

    return nvd_mentioned_affected_functions


def _onefunc_filter(affected_vuln_functions):
    if len(affected_vuln_functions) == 1:
        return affected_vuln_functions

    return []


def _deduplicate_vuln_functions(
        vuln_functions: dict[str, list[ExtractedFunction]], fix_functions: dict[str, list[ExtractedFunction]]
) -> dict[str, list[ExtractedFunction]]:
    functions_store = defaultdict(list)
    for functions in [vuln_functions, fix_functions]:
        for filename, efs in functions.items():
            for ef in efs:
                func_key = hash_function(ef.function_body)
                func_info = _ef_to_function_info(filename=filename, ef=ef)
                functions_store[func_key].append(func_info)

    new_functions: dict[str, list[ExtractedFunction]] = defaultdict(list)
    for filename, efs in vuln_functions.items():
        for ef in efs:
            func_key = hash_function(ef.function_body)
            same_functions = functions_store[func_key]
            if len(same_functions) == 1:
                new_functions[filename].append(ef)
                continue

            if len({f.vuln for f in same_functions}) == 1:  # all functions are vulnerable or fixed with the same hash
                new_functions[filename].append(ef)

    return new_functions


def main(data_dir_from: Path, data_dir_to: Path, dedup: bool):
    metadata_files = list_jsons(data_dir_from / "metadata")
    files_cnt = sum(
        len(read_cache(metadata_file, convert_merged_data))
        for metadata_file in metadata_files
    )
    with tqdm(total=files_cnt) as pbar:
        for md_fp in metadata_files:
            project = project_from_metadata_file_path(md_fp)
            mpd: dict[str, MergedCommitData] = read_cache(md_fp, convert_merged_data)
            new_mpd = {}
            for fix_sha, mcd in mpd.items():
                pbar.update(1)
                filtered_files = [f for f in mcd.files if f.status in ["modified", "renamed"]]
                if not filtered_files:
                    continue

                functions_dir = data_dir_from / "functions" / project / fix_sha

                vuln_functions = read_cache(functions_dir / "vuln.json", convert_extracted_data)
                fix_functions = read_cache(functions_dir / "fix.json", convert_extracted_data)

                if dedup:
                    vuln_functions = _deduplicate_vuln_functions(
                        vuln_functions=vuln_functions, fix_functions=fix_functions
                    )

                affected_vuln_functions = get_affected_vuln_functions(
                    filtered_files=filtered_files, commit_functions_data=vuln_functions
                )

                onefunc_functions = _onefunc_filter(affected_vuln_functions)
                nvdcheck_functions = _nvdcheck_filter(affected_vuln_functions, mcd)
                vuln_functions_3 = [
                    (fn, ExtractedFunction(*ef)) for fn, ef in
                    {(fn, astuple(ef)) for fn, ef in onefunc_functions} |
                    {(fn, astuple(ef)) for fn, ef in nvdcheck_functions}
                ]

                if not vuln_functions_3:
                    continue

                copy_relevant_files_and_functions(
                    vuln_functions_3, fix_functions, data_dir_from, data_dir_to, project, mcd, fix_sha
                )
                new_mpd[fix_sha] = mcd

            if new_mpd:
                write_cache(data_dir_to / "metadata" / f"{project}.json", new_mpd)


if __name__ == "__main__":
    _, _, ddf = get_data_dirs("saved/latest/06_no_dup")
    _, _, ddt = get_data_dirs("saved/latest/07_of_nvdc_new")
    main(data_dir_from=ddf, data_dir_to=ddt, dedup=True)
