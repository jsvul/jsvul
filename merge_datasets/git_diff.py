import subprocess, pathlib

from util.common import get_data_dirs
from util.file import read_file

_, _, TMP_DATA_DIR = get_data_dirs("tmp")


def _write_tmp_file(file_path, tmp_file_name):
    tmp_file_path = TMP_DATA_DIR / tmp_file_name
    tmp_file_path.unlink(missing_ok=True)
    tmp_text = read_file(file_path)
    tmp_file_path.write_text(tmp_text, encoding="utf-8", newline="\n")
    return tmp_file_path


def generate_git_diff(before_path: pathlib.Path, after_path: pathlib.Path) -> str:
    TMP_DATA_DIR.mkdir(exist_ok=True, parents=True)
    a = _write_tmp_file(before_path, "a.js")
    b = _write_tmp_file(after_path, "b.js")
    cmd = [
        "git",
        "-c", "core.safecrlf=false",
        "-c", "diff.indentHeuristic=true",
        "diff", "--no-index", "--unified=3", "--text",
        "--no-color", "--src-prefix=a/", "--dst-prefix=b/",
        str(a), str(b),
    ]
    out = subprocess.run(cmd, capture_output=True)
    stdout = out.stdout.decode("utf-8", errors="replace")
    return "\n".join(stdout.split("\n")[4:])


def _foo(data_dir: pathlib.Path, project, vuln_sha, fix_sha, vuln_filename, fix_filename):
    project_dir = data_dir / "files" / project
    fix_dir = project_dir / fix_sha
    vuln_dir = project_dir / vuln_sha
    before = vuln_dir / vuln_filename
    after = fix_dir / fix_filename

    diff = generate_git_diff(before, after)
    print(diff)


if __name__ == "__main__":
    _, _, dd = get_data_dirs("saved/latest/06_no_dup")
    _foo(
        data_dir=dd, project="cherryhq/cherry-studio",
        vuln_sha="ee32942f7141c932c4ff7facd437b446281a3a0d", fix_sha="40f9601379150854826ff3572ef7372fb0acdc38",
        vuln_filename="src/renderer/src/aiCore/middleware/common/FinalChunkConsumerMiddleware.ts",
        fix_filename="src/renderer/src/aiCore/middleware/common/FinalChunkConsumerMiddleware.ts"
    )
