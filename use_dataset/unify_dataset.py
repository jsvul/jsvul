import json
from pathlib import Path

from filter_datasets.util.statistics import list_files, list_jsons
from util.cache import read_cache, convert_extracted_data, convert_merged_data
from util.common import get_data_dirs, MergedCommitData, Date, json_defaults
from util.data import UnifiedFunctionData, FunctionLoc
from util.label import ExtractedFunction
from util.merge import project_from_metadata_file_path


def _calculate_distribution(number_of_items, distributions: list[float]) -> list[int]:
    result = []
    for distribution in distributions:
        percentage = distribution / sum(distributions)
        result.append(int(percentage * number_of_items))

    while sum(result) != number_of_items:
        result[0] += 1

    return result


def _write_functions(
        func_data: dict[str, list[ExtractedFunction]], out_file: Path, project: str, sha: str, mcd: MergedCommitData
):
    for filename, efl in func_data.items():
        for ef in efl:
            with open(out_file, mode="a", encoding="utf-8") as f:
                f.write(json.dumps(UnifiedFunctionData(
                    id=f"{project}::{sha}::{filename}::{ef.start_line}::{ef.start_column}",
                    project=project, sha=sha, file=filename,
                    loc=FunctionLoc(
                        start_line=ef.start_line, start_column=ef.start_column,
                        end_line=ef.end_line, end_column=ef.end_column,
                    ),
                    body=ef.function_body, name=str(ef.function_name),
                    cwe=mcd.cwe, cve=mcd.cve, ghsa=mcd.github, snyk=mcd.snyk, other=mcd.others,
                    publish_time=mcd.publish_time, label=int(ef.vuln),
                ), default=json_defaults) + "\n")


def main(data_dir: Path, jsonl_dir: Path, distributions: list[float], only_pairs=False) -> None:
    vuln_functions_path = list_files(data_dir / "functions", "vuln.json")
    vuln_functions_cnt = sum(
        1
        for vfp in vuln_functions_path
        for efl in read_cache(vfp, convert_extracted_data).values()
        for ef in efl
        if ef.vuln
    )

    distributed_cnt_list = _calculate_distribution(vuln_functions_cnt, distributions)

    commits = []
    for md_fp in list_jsons(data_dir / "metadata"):
        mpd: dict[str, MergedCommitData] = read_cache(md_fp, convert_merged_data)
        for fix_sha, mcd in mpd.items():
            time_to_sort_by = mcd.publish_time
            if not time_to_sort_by:
                time_to_sort_by = Date(1950, 1, 1)

            if not time_to_sort_by.month:
                time_to_sort_by.month = 1

            if not time_to_sort_by.day:
                time_to_sort_by.day = 1

            commits.append((time_to_sort_by or Date(1950), project_from_metadata_file_path(md_fp), fix_sha))

    sorted_commits = sorted(commits, key=lambda c: c[0])
    sorted_commits_idx = 0

    if not jsonl_dir.exists():
        jsonl_dir.mkdir(parents=True)

    for i, distribution_cnt in enumerate(distributed_cnt_list, 1):
        jsonl_file_path = jsonl_dir / f"{i:02d}_data.jsonl"
        while distribution_cnt > 0:
            if sorted_commits_idx == len(sorted_commits):
                break

            _, project, fix_sha = sorted_commits[sorted_commits_idx]
            sorted_commits_idx += 1
            mpd: dict[str, MergedCommitData] = read_cache(data_dir / "metadata" / f"{project}.json", convert_merged_data)
            mcd = mpd[fix_sha]
            commit_func_dir = data_dir / "functions" / project / fix_sha
            vuln_functions_file = commit_func_dir / "vuln.json"
            vuln_func_data: dict[str, list[ExtractedFunction]] = read_cache(vuln_functions_file, convert_extracted_data)

            vuln_func_cnt = sum(len(efl) for efl in vuln_func_data.values())
            distribution_cnt -= vuln_func_cnt

            fix_functions_file = commit_func_dir / "fix.json"
            fix_func_data: dict[str, list[ExtractedFunction]] = read_cache(fix_functions_file, convert_extracted_data)
            if only_pairs:
                fix_func_data = {
                    filename: [
                        ef for ef in efl
                        if ef.affected and any(
                            ef.function_name and ef.function_name == vef.function_name
                            for vfn, vefl in vuln_func_data.items()
                            for vef in vefl
                        )
                    ]
                    for filename, efl in fix_func_data.items()
                }

            if only_pairs and not fix_func_data:
                continue

            _write_functions(
                func_data=vuln_func_data, out_file=jsonl_file_path,
                project=project, sha=mcd.vuln_sha, mcd=mcd
            )

            _write_functions(
                func_data=fix_func_data, out_file=jsonl_file_path,
                project=project, sha=fix_sha, mcd=mcd
            )


if __name__ == "__main__":
    _, _, dd = get_data_dirs("saved/no_min/08_final")
    _, _, jdd = get_data_dirs("unified_data_only_name_pairs")
    main(data_dir=dd, jsonl_dir=jdd, distributions=[8, 1, 1], only_pairs=True)
