import subprocess
from pathlib import Path

from tqdm import tqdm

from filter_datasets.util.statistics import list_jsons
from util.cache import read_cache, write_cache, convert_merged_data
from util.common import MergedCommitData
from util.merge import project_from_metadata_file_path


def run_tool(cmd: list[str], cwd: str, _filter_logs):
    out = subprocess.run(cmd, cwd=cwd, capture_output=True)
    stdout = out.stdout.decode("utf-8", errors="replace")
    stderr = out.stderr.decode("utf-8", errors="replace")
    return _filter_logs(stdout, stderr)


def run_for_all_files(metadata_path: Path, cache_path: Path, tool_runner):
    metadata_files = list_jsons(metadata_path)
    mcd_cnt = sum(len(read_cache(f, convert_merged_data)) for f in metadata_files)
    with tqdm(total=mcd_cnt) as pbar:
        for metadata_file in metadata_files:
            project = project_from_metadata_file_path(metadata_file)
            run_cache = read_cache(cache_path / project)
            mpd: dict[str, MergedCommitData] = read_cache(metadata_file, convert_merged_data)
            for sha, mcd in mpd.items():
                pbar.update(1)
                if sha in run_cache:
                    continue

                fix_results, vuln_results = None, None
                fix_files = [
                    str(Path(project) / sha / f.filename)
                    for f in mcd.files
                ]
                if fix_files:
                    fix_results = tool_runner(fix_files)

                relevant_vuln_files = [
                    str(Path(project) / mcd.vuln_sha / (f.previous_filename or f.filename))
                    for f in mcd.files
                ]
                if relevant_vuln_files:
                    vuln_results = tool_runner(relevant_vuln_files)

                if fix_results or vuln_results:
                    continue

                run_cache[sha] = True
                write_cache(cache_path / project, run_cache)
