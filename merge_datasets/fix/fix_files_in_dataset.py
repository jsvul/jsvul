import csv
import logging
import shutil
from pathlib import Path

from util.common import get_data_dirs

logger = logging.getLogger(__name__)


def _fix(fixed_dir: Path, to_dir: Path, fix_type: str) -> None:
    logger.info(f"Fixing {fix_type}")
    with open(Path(__file__).parent / f"{fix_type}_fixes.csv", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            old_target_path = to_dir / fix_type / (row["where"] or row["what"])
            old_target_path.unlink()

            shutil.copy(fixed_dir / fix_type / row["what"], to_dir / fix_type / row["what"])


def main(from_dir: Path, to_dir: Path):
    shutil.copytree(from_dir, to_dir)

    fixed_dir = Path(__file__).parent
    _fix(fixed_dir, to_dir, "files")
    _fix(fixed_dir, to_dir, "metadata")


if __name__ == "__main__":
    _, _, data_dir_from = get_data_dirs("merged_data_no_dup")
    _, _, data_dir_to = get_data_dirs("merged_data_no_dup_fixed")
    main(from_dir=data_dir_from, to_dir=data_dir_to)
