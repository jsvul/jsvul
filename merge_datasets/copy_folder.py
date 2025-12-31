import shutil
from pathlib import Path

from util.common import get_data_dirs


def main(from_dir: Path, to_dir: Path):
    shutil.copytree(from_dir, to_dir)


if __name__ == "__main__":
    _, _, ddf = get_data_dirs("merged_data_no_dup_fixed_eslint_prettier_diffs_no_dup")
    _, _, ddt = get_data_dirs("merged_data_no_dup_fixed_eslint_prettier_diffs_no_dup_save")
    main(from_dir=ddf, to_dir=ddt)
