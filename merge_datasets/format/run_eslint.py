from pathlib import Path

from dotenv import load_dotenv

from merge_datasets.format.util import init_formatter
from util.cache import read_cache, write_cache
from util.common import get_data_dirs
from util.run import run_for_all_files, run_tool

load_dotenv()

RUN_CACHE_DIR, _, _ = get_data_dirs("run")

FILES_DIR = Path()


def _init_globals(data_dir: Path):
    global FILES_DIR

    FILES_DIR = data_dir / "files"


def _filter_eslint_logs(stdout: str, stderr: str):
    if stderr:
        raise ValueError(f"stderr: {stderr}")

    important_lines = []
    prev_line = ""
    for line in stdout.splitlines():
        if "parsing error" in line.lower():
            important_lines.append(prev_line)
            important_lines.append(line)

        prev_line = line

    prev_line = ""
    for line in stderr.splitlines():
        if "parsing error" in line.lower():
            important_lines.append(prev_line)
            important_lines.append(line)

        prev_line = line

    if important_lines:
        raise ValueError(f"errors: {important_lines}")

    return important_lines or (stderr and stderr)


def _run_eslint(filenames: list[str]):
    cmd = ["node", str(Path(r"node_modules\eslint\bin\eslint.js")), *filenames, "--fix"]
    return run_tool(cmd=cmd, cwd=str(FILES_DIR), _filter_logs=_filter_eslint_logs)


def main(data_dir: Path):
    _init_globals(data_dir)
    init_formatter(data_dir=data_dir, config_files=["eslint.config.js"], init_script="init_eslint.cmd")
    package_json_path = data_dir / "files" / "package.json"
    package_json = read_cache(package_json_path)
    package_json["type"] = "module"
    write_cache(package_json_path, package_json)
    run_for_all_files(
        metadata_path=data_dir / "metadata",
        cache_path=RUN_CACHE_DIR / "eslint",
        tool_runner=_run_eslint
    )


if __name__ == "__main__":
    _, _, dd = get_data_dirs("merged_data_no_dup_fixed_eslint")
    main(dd)
