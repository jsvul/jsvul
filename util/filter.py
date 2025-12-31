import re
from dataclasses import dataclass
from pathlib import Path

from pathspec import PathSpec

from util.common import StoredData

ignore_js_files_lines = Path(Path(__file__).parent.parent / '.ignorejsfiles').read_text().splitlines()


with open(Path(__file__).parent.parent / '.ignorejsfiles') as f:
    ignore_js_files_spec = PathSpec.from_lines('gitwildmatch', f)

with open(Path(__file__).parent.parent / '.ignoremorefiles') as f:
    ignore_more_files_spec = PathSpec.from_lines('gitwildmatch', f)

js_file_endings = (".js", ".jsx", ".jsm", ".mjs", ".cjs", ".ts", ".tsx")


def is_js_file(filename: str) -> bool:
    """
    Check if the given filename is a JavaScript file.
    """
    return filename in ["bin/http-live", "bin/public"] or filename.endswith(js_file_endings)


def is_relevant_file(filename: str) -> bool:
    return not ignore_js_files_spec.match_file(filename)


def is_test_file(filename: str) -> bool:
    """
    Check if the given filename is a test file
    """
    return ignore_more_files_spec.match_file(filename)


@dataclass
class MinifiedStats(StoredData):
    total_chars: int
    num_lines: int
    max_line_len: int
    avg_line_len: float
    long_line_ratio: float
    whitespace_ratio: float
    punctuation_ratio: float
    one_letter_ident_ratio: float | None


IDENT_RE = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b")

def _compute_stats(code: str) -> MinifiedStats:
    total_chars = len(code)
    if total_chars == 0:
        return MinifiedStats(0, 0, 0, 0.0, 0.0, 0.0, 0.0, None)

    lines = code.splitlines() or [code]
    max_line_length = max(len(line) for line in lines)
    num_lines = len(lines)
    avg_line_len = total_chars / num_lines

    num_long_lines = sum(1 for line in lines if len(line) > 200)
    long_line_ratio = num_long_lines / num_lines

    whitespace_count = sum(1 for c in code if c.isspace())
    whitespace_ratio = whitespace_count / total_chars

    punctuation_chars = ";,{}()"
    punctuation_count = sum(1 for c in code if c in punctuation_chars)
    punctuation_ratio = punctuation_count / total_chars

    idents = IDENT_RE.findall(code)
    if idents:
        one_letter_count = sum(1 for ident in idents if len(ident) == 1)
        one_letter_ident_ratio: float | None = one_letter_count / len(idents)
    else:
        one_letter_ident_ratio = None

    return MinifiedStats(
        total_chars=total_chars,
        num_lines=num_lines,
        max_line_len=max_line_length,
        avg_line_len=avg_line_len,
        long_line_ratio=long_line_ratio,
        whitespace_ratio=whitespace_ratio,
        punctuation_ratio=punctuation_ratio,
        one_letter_ident_ratio=one_letter_ident_ratio,
    )


def is_probably_minified(code: str, *, min_size: int = 400) -> bool:
    """
    Heuristically decide if a JS file is minified, without relying on the filename.

    Returns (is_minified, stats).
    """

    stats = _compute_stats(code)

    if stats.total_chars < min_size:
        return False

    score = 0

    if stats.avg_line_len >= 1000:
        score += 1

    if stats.long_line_ratio >= 0.4:
        score += 1

    elif stats.long_line_ratio < 0.001:
        score -= 1

    if stats.whitespace_ratio < 0.15:
        score += 1

    if stats.punctuation_ratio > 0.05:
        score += 1

    if stats.one_letter_ident_ratio is not None and stats.one_letter_ident_ratio > 0.3:
        score += 1

    is_minified = score >= 3
    return is_minified
