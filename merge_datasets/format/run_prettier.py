import logging
from pathlib import Path

from merge_datasets.format.util import init_formatter
from util.cache import read_cache, write_cache
from util.common import get_data_dirs, play_notification_sound
from util.run import run_for_all_files, run_tool

logger = logging.getLogger(__name__)

RUN_CACHE_DIR, _, _ = get_data_dirs("run")

FILES_DIR = Path()


def _init_globals(data_dir: Path):
    global FILES_DIR

    FILES_DIR = data_dir / "files"


def _filter_prettier_logs(stdout: str, stderr: str):
    if not stdout and not stderr:
        return []

    if stderr:
        raise ValueError(f"stderr: {stderr}")

    if stderr:
        logger.error(stderr)
        return stderr.splitlines()

    important_lines = []
    for line in stdout.splitlines():
        if not line.endswith("(unchanged)"):
            important_lines.append(line)

    if important_lines:
        logger.debug("\n".join(important_lines))

    return important_lines


def _run_prettier(filenames: list[str]):
    cmd = [
        "node", str(Path(r"node_modules\prettier\bin\prettier.cjs")),
        "--write", "--print-width", "120", "--no-cache", "--with-node-modules",
        *filenames,
    ]
    return run_tool(cmd=cmd, cwd=str(FILES_DIR), _filter_logs=_filter_prettier_logs)


def main(data_dir: Path):
    _init_globals(data_dir)
    init_formatter(
        data_dir=data_dir, config_files=["prettier.config.js", ".prettierignore"], init_script="init_prettier.cmd"
    )
    package_json_path = data_dir / "files" / "package.json"
    package_json = read_cache(package_json_path)
    del package_json["type"]
    write_cache(package_json_path, package_json)
    run_for_all_files(
        metadata_path=data_dir / "metadata",
        cache_path=RUN_CACHE_DIR / "prettier",
        tool_runner=_run_prettier
    )


if __name__ == "__main__":
    _, _, dd = get_data_dirs("merged_data_no_dup_fixed_eslint_prettier")
    main(data_dir=dd)
