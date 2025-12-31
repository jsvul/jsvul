import logging
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from tqdm import tqdm

from filter_datasets.util.statistics import list_jsons
from util.cache import read_cache, write_cache, convert_merged_data, convert_extracted_data
from util.common import MergedCommitData, get_data_dirs, Date
from util.label import ExtractedFunction
from util.merge import project_from_metadata_file_path
from util.postprocess import hash_function

logger = logging.getLogger(__name__)


@dataclass
class FunctionInfo:
    project: str
    fix_sha: str
    publish_time: Date | None
    filename: str
    vuln: bool
    function_body: str
    function_name: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int


def _ef_to_function_info(project: str, fix_sha: str, publish_time: Date | None, filename: str, ef: ExtractedFunction):
    return FunctionInfo(
        project=project, fix_sha=fix_sha, publish_time=publish_time, filename=filename,
        vuln=ef.vuln, function_body=ef.function_body, function_name=ef.function_name,
        start_line=ef.start_line, start_column=ef.start_column,
        end_line=ef.end_line, end_column=ef.end_column,
    )


def _process_functions_info(
        project: str, fix_sha: str, publish_time: Date | None,
        functions: dict[str, list[ExtractedFunction]],
        functions_store: dict[str, list[FunctionInfo]]
):
    for filename, efs in functions.items():
        for ef in efs:
            functions_store[hash_function(ef.function_body)].append(_ef_to_function_info(
                project=project, fix_sha=fix_sha, publish_time=publish_time, filename=filename, ef=ef
            ))


def _remove_duplicated_functions(
        project: str, fix_sha: str, publish_time: Date | None,
        functions: dict[str, list[ExtractedFunction]],
        functions_store: dict[str, list[FunctionInfo]]
) -> dict[str, list[ExtractedFunction]]:
    new_functions: dict[str, list[ExtractedFunction]] = defaultdict(list)
    for filename, efs in functions.items():
        for ef in efs:
            function_hash = hash_function(ef.function_body)
            same_functions = functions_store[function_hash]
            if len(same_functions) == 1:
                new_functions[filename].append(ef)
                continue

            this_function_info = _ef_to_function_info(
                project=project, fix_sha=fix_sha, publish_time=publish_time, filename=filename, ef=ef
            )

            if len({f.vuln for f in same_functions}) == 1:  # all functions are vulnerable or fixed with the same hash
                if same_functions[0] == this_function_info:  # save only first of all matching functions
                    new_functions[filename].append(ef)

            else:  # there are vulnerable and fixed functions with the same hash
                first_vulnerable_function = next(f for f in same_functions if f.vuln)
                if first_vulnerable_function == this_function_info:
                    new_functions[filename].append(ef)

    return new_functions


def main(data_dir_from: Path, data_dir_to: Path):
    functions_store: dict[str, list[FunctionInfo]] = defaultdict(list)
    metadata_files = list_jsons(data_dir_from / "metadata")
    mcd_cnt = sum(
        len(read_cache(metadata_file, convert_merged_data))
        for metadata_file in metadata_files
    )
    logger.info("hash all functions")
    with tqdm(total=mcd_cnt) as pbar:
        for md_fp in metadata_files:
            project = project_from_metadata_file_path(md_fp)
            mpd: dict[str, MergedCommitData] = read_cache(md_fp, convert_merged_data)
            for fix_sha, mcd in mpd.items():
                pbar.update(1)
                for func_file_name in ["vuln.json", "fix.json"]:
                    functions_file_from = data_dir_from / "functions" / project / fix_sha / func_file_name
                    functions: dict[str, list[ExtractedFunction]] = read_cache(
                        functions_file_from, convert_extracted_data
                    )

                    _process_functions_info(
                        project=project, fix_sha=fix_sha, publish_time=mcd.publish_time,
                        functions=functions, functions_store=functions_store
                    )

    functions_store = {
        func_key: sorted(func_list, key=lambda fi: fi.publish_time or Date(2050))
        for func_key, func_list in functions_store.items()
    }

    logger.info("remove duplicates")
    with tqdm(total=mcd_cnt) as pbar:
        for md_fp_from in metadata_files:
            project = project_from_metadata_file_path(md_fp_from)
            mpd: dict[str, MergedCommitData] = read_cache(md_fp_from, convert_merged_data)
            new_mpd: dict[str, MergedCommitData] = {}
            for fix_sha, mcd in mpd.items():
                pbar.update(1)
                for func_file_name in ["vuln.json", "fix.json"]:
                    functions_file_from = data_dir_from / "functions" / project / fix_sha / func_file_name
                    functions: dict[str, list[ExtractedFunction]] = read_cache(
                        functions_file_from, convert_extracted_data
                    )

                    new_functions = _remove_duplicated_functions(
                        project=project, fix_sha=fix_sha, publish_time=mcd.publish_time,
                        functions=functions, functions_store=functions_store
                    )

                    if new_functions:
                        new_mpd[fix_sha] = mcd
                        functions_file_to = data_dir_to / "functions" / project / fix_sha / func_file_name
                        write_cache(functions_file_to, new_functions)

            if new_mpd:
                md_fp_to = data_dir_to / "metadata" / f"{project}.json"
                write_cache(md_fp_to, new_mpd)


if __name__ == "__main__":
    _, _, ddf = get_data_dirs("07_of_nvdc")
    _, _, ddt = get_data_dirs("08_final_test")
    main(data_dir_from=ddf, data_dir_to=ddt)
