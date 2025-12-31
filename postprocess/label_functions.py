import re
from collections import defaultdict
from pathlib import Path

from tqdm import tqdm

from filter_datasets.util.statistics import list_jsons
from util.cache import read_cache, write_cache, convert_merged_data, convert_extracted_data
from util.common import MergedCommitData, get_data_dirs, GitHubFile
from util.file import read_file
from util.label import Change, DirectChange, MappedChange, Loc, ExtractedFunction
from util.merge import project_from_metadata_file_path

diff_header_pattern = re.compile(r'@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@')
diff_part_pattern = re.compile(r'@@.*?@@[\s\S]*?(?=^@@|(?![\s\S]))', re.MULTILINE)


def _get_changes_of_diff_part(diff_part: str, vuln_start_line: int, fix_start_line: int) -> list[tuple[Change, Change]]:
    diff_lines = diff_part.splitlines()
    vuln_line = vuln_start_line
    fix_line = fix_start_line
    diff_lines_cnt = len(diff_lines)
    diff_changes: list[tuple[Change, Change]] = []
    for idx, line in enumerate(diff_lines, 1):
        if not line:
            if idx == diff_lines_cnt:
                break

            raise ValueError(f"empty line is not the last")

        tag = line[0]
        if tag == ' ':
            vuln_line += 1
            fix_line += 1

        elif tag == '-':
            diff_changes.append((DirectChange(vuln_line), MappedChange(fix_line)))
            vuln_line += 1

        elif tag == '+':
            diff_changes.append((MappedChange(vuln_line), DirectChange(fix_line)))
            fix_line += 1

    return diff_changes


def _mark_functions(matched_functions: list[tuple[Loc, list[ExtractedFunction]]], vuln: bool) -> None:
    for _, f_list in matched_functions:
        for f in f_list:
            f.affected = True
            f.vuln = vuln


def _get_matched_functions(functions_map: dict[Loc, list], changes):
    return [(loc, f_list) for loc, f_list in functions_map.items() if loc.match_changes(changes)]


def _squash_diff_changes(diff_changes: list[tuple[Change, Change]]) -> list[tuple[list[Change], list[Change]]]:
    if not diff_changes:
        return []

    squashed_changes = [([diff_changes[0][0]], [diff_changes[0][1]])]
    for vuln_change, fix_change in diff_changes[1:]:
        last_squashed_vuln_changes, last_squashed_fix_changes = squashed_changes[-1]
        if last_squashed_vuln_changes[-1] == vuln_change:
            last_squashed_fix_changes.append(fix_change)

        elif last_squashed_fix_changes[-1] == fix_change:
            last_squashed_vuln_changes.append(vuln_change)

        elif isinstance(last_squashed_vuln_changes[-1], DirectChange) and isinstance(vuln_change, MappedChange) and last_squashed_vuln_changes[-1].line + 1 == vuln_change.line:
            if isinstance(last_squashed_fix_changes[-1], MappedChange):
                last_squashed_fix_changes[-1] = fix_change

            else:
                last_squashed_fix_changes.append(fix_change)

        else:
            squashed_changes.append(([vuln_change], [fix_change]))

    return squashed_changes


def _label_functions_in_file(
        fix_commit_dir: Path, f: GitHubFile,
        extracted_fix_functions: dict[str, list[ExtractedFunction]],
        extracted_vuln_functions: dict[str, list[ExtractedFunction]]
):
    if f.status == "removed":
        for e in extracted_vuln_functions.get(f.previous_filename or f.filename, []):
            e.affected = True
            e.vuln = True

    elif f.status == "added":
        for e in extracted_fix_functions.get(f.filename, []):
            e.affected = True
            e.vuln = False

    else:
        file_path = fix_commit_dir / f.filename
        patch_file = file_path.with_name(file_path.name + ".patch")
        diff_text = read_file(patch_file)
        for diff_part in diff_part_pattern.findall(diff_text):
            match = diff_header_pattern.search(diff_part)
            if not match:
                raise ValueError(f"{diff_part} has no valid diff header")

            before_start_line, after_start_line = map(int, match.groups())
            diff_changes = _get_changes_of_diff_part(diff_part, before_start_line, after_start_line)

            fix_functions_map = defaultdict(list)
            for func in extracted_fix_functions.get(f.filename, []):
                fix_functions_map[Loc(func.start_line, func.end_line)].append(func)

            vuln_functions_map = defaultdict(list)
            for func in extracted_vuln_functions.get(f.previous_filename or f.filename, []):
                vuln_functions_map[Loc(func.start_line, func.end_line)].append(func)

            squashed_diff_changes: list[tuple[list[Change], list[Change]]] = _squash_diff_changes(diff_changes)
            for vuln_changes, fix_changes in squashed_diff_changes:
                matched_vuln_functions = _get_matched_functions(vuln_functions_map, vuln_changes)
                _mark_functions(matched_vuln_functions, True)

                matched_fix_functions  = _get_matched_functions(fix_functions_map,  fix_changes)
                _mark_functions(matched_fix_functions, False)


def main(data_dir: Path):
    metadata_files = list_jsons(data_dir / "metadata")
    files_cnt = sum(
        len(mcd.files)
        for metadata_file in metadata_files
        for _, mcd in read_cache(metadata_file, convert_merged_data).items()
    )
    with tqdm(total=files_cnt) as pbar:
        for metadata_file in metadata_files:
            project = project_from_metadata_file_path(metadata_file)
            mpd: dict[str, MergedCommitData] = read_cache(metadata_file, convert_merged_data)
            for fix_sha, mcd in mpd.items():
                functions_dir = data_dir / "functions" / project / fix_sha
                extracted_fix_functions  = read_cache(functions_dir / "fix.json", convert_extracted_data)
                extracted_vuln_functions = read_cache(functions_dir / "vuln.json", convert_extracted_data)
                for f in mcd.files:
                    pbar.update(1)

                    _label_functions_in_file(
                        fix_commit_dir=data_dir / "files" / project / fix_sha, f=f,
                        extracted_fix_functions=extracted_fix_functions,
                        extracted_vuln_functions=extracted_vuln_functions
                    )

                write_cache(functions_dir / "fix.json",  extracted_fix_functions)
                write_cache(functions_dir / "vuln.json", extracted_vuln_functions)


if __name__ == "__main__":
    _, _, dd = get_data_dirs("no_min_save/merged_data_formatted_no_dup")
    main(data_dir=dd)
