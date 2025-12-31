import logging
import re
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

npm_success_pattern = re.compile(r"""added \d+ packages?, and audited \d+ packages? in \d+m?s

\d+ packages? (?:are|is) looking for funding
  run `npm fund` for details

found \d+ vulnerabilit(?:ies|y)""", re.MULTILINE)

PARENT_DIR = Path(__file__).parent


def init_formatter(data_dir: Path, config_files: list[str], init_script: str) -> None:
    files_dir = data_dir / "files"
    for config_file in config_files:
        if (files_dir / config_file).exists():
            break

        shutil.copy(PARENT_DIR / config_file, files_dir / config_file)

    else:
        out = subprocess.run([str(PARENT_DIR / init_script)], cwd=str(files_dir), capture_output=True)
        stdout = out.stdout.decode("utf-8", errors="replace")
        stderr = out.stderr.decode("utf-8", errors="replace")
        match = npm_success_pattern.search(stdout)
        if not match:
            logger.error(stderr)
            logger.warning(stdout)
            raise ValueError(f"Failed to run {init_script}")
