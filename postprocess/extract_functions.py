import os
import subprocess
from pathlib import Path

from dotenv import load_dotenv
from tqdm import tqdm

from filter_datasets.util.statistics import list_jsons
from util.cache import read_cache, write_cache, convert_merged_data
from util.common import get_data_dirs, MergedCommitData
from util.merge import project_from_metadata_file_path

load_dotenv()

JSFE_PATH = os.getenv("JSFE_PATH")


def _persist_results(extracted_functions_path, extracted_functions):
    if extracted_functions:
        write_cache(extracted_functions_path, extracted_functions)

    else:
        extracted_functions_path.unlink()
        try:
            extracted_functions_path.parent.rmdir()
            extracted_functions_path.parent.parent.rmdir()

        except:
            pass


def _extract_functions_from_files(tool_output: Path, files__root_dir: Path, files_list: list[str]):
    cmd = [
        "node", JSFE_PATH,
        "-r", str(files__root_dir),
        "-o", str(tool_output),
        "-d", "1",
        *files_list,
    ]
    out = subprocess.run(cmd, capture_output=True)
    stdout = out.stdout.decode("utf-8", errors="replace")
    if stdout.split("\n")[-2] != "SUCCESS":
        raise ValueError(f"Failed to extract functions from files.\nCmd: '{cmd}'\nSTDOUT:\n{stdout}")


def _extract_functions(tool_output, files_root_dir, relevant_files):
    if relevant_files:
        _extract_functions_from_files(tool_output, files_root_dir, relevant_files)

        extracted_functions = read_cache(tool_output)
        extracted_functions = {k: v for k, v in extracted_functions.items() if v}

        _persist_results(tool_output, extracted_functions)


def _extract_fix_functions(tool_output_dir, files_root_dir, filtered_files):
    relevant_fix_files = [
        f.filename
        for f in filtered_files
        if f.status in ["modified", "renamed", "added"]
    ]
    tool_output = tool_output_dir / "fix.json"
    _extract_functions(tool_output, files_root_dir, relevant_fix_files)


def _extract_vuln_functions(tool_output_dir, files_root_dir, filtered_files):
    relevant_vuln_files = [
        f.previous_filename or f.filename
        for f in filtered_files
        if f.status in ["modified", "renamed", "removed"]
    ]
    tool_output = tool_output_dir / "vuln.json"
    _extract_functions(tool_output, files_root_dir, relevant_vuln_files)


def main(data_dir: Path):
    metadata_files = list_jsons(data_dir / "metadata")
    mcd_cnt = sum(len(read_cache(f, convert_merged_data)) for f in metadata_files)
    with tqdm(total=mcd_cnt) as pbar:
        for metadata_file in metadata_files:
            project = project_from_metadata_file_path(metadata_file)
            mpd: dict[str, MergedCommitData] = read_cache(metadata_file, convert_merged_data)
            for fix_sha, mcd in mpd.items():
                pbar.update(1)
                tool_output_dir = data_dir / "functions" / project / fix_sha
                project_files_dir = data_dir / "files" / project
                _extract_fix_functions(
                    tool_output_dir=tool_output_dir,
                    files_root_dir=project_files_dir / fix_sha,
                    filtered_files=mcd.files
                )

                _extract_vuln_functions(
                    tool_output_dir=tool_output_dir,
                    files_root_dir=project_files_dir / mcd.vuln_sha,
                    filtered_files=mcd.files
                )


if __name__ == "__main__":
    _, _, dd = get_data_dirs("merged_data_no_dup_fixed_eslint_prettier_no_dup")
    main(data_dir=dd)
