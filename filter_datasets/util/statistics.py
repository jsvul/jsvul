import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from util.common import json_defaults
from util.filter import js_file_endings

INCORRECT_URLS = defaultdict(set)
NOT_GITHUB_URLS = defaultdict(lambda: 0)

start_with_characters = r"(?<![a-zA-Z0-9])"
optional_protocol = r"(?:[a-zA-Z][a-zA-Z0-9+.-]*://)?"
domain_part = r"[a-zA-Z0-9-]+"
domain = fr"{domain_part}(?:\.{domain_part})+"
any_part = r"[a-zA-Z0-9_-]+"
any_path = fr"{any_part}(?:\.{any_part})*"
value = r"[a-zA-Z0-9]{1,40}"

any_url_regex = fr"""({start_with_characters}{optional_protocol}({domain})(?:/{any_path})*/(commit|commits|pull)/{value}(?:/{any_part})*)"""

url_part = r"[a-zA-Z0-9._-]+"
repo = fr"{url_part}/{url_part}"
github_url_regex = fr"github\.com/{repo}(?:/{url_part})*/(?:commit|commits|pull)/({value})"

sha_pattern = re.compile(r"^[0-9a-fA-F]{4,40}$")

any_url_pattern = re.compile(any_url_regex, re.IGNORECASE)
github_url_pattern = re.compile(github_url_regex, re.IGNORECASE)


def is_int(value):
    """
    Check if the value is an integer.
    """
    try:
        int(value)
        return True

    except ValueError:
        return False


VALUE_MATCHERS = {
    "commit": sha_pattern.fullmatch,
    "commits": sha_pattern.fullmatch,
    "pull": is_int,
}


def list_jsons(dir_path) -> list[Path]:
    try:
        files = [path for path in dir_path.rglob("*.json") if path.is_file()]
        return files

    except Exception as e:
        print(f"Error listing JSONs: {e}")
        return []


def list_js_files(dir_path) -> list[Path]:
    try:
        files = [
            path for path in dir_path.rglob("*")
            if path.is_file() and path.suffix in js_file_endings
        ]
        return files

    except Exception as e:
        print(f"Error listing files: {e}")
        return []


def list_files(dir_path, suffix) -> list[Path]:
    import os

    try:
        files = []
        for root, dirs, filenames in os.walk(dir_path):
            for name in filenames:
                if name.endswith(suffix):
                    files.append(Path(root) / name)

        return files

    except Exception as e:
        print(f"Error listing files: {e}")
        return []


def has_files(dir_path, suffix) -> bool:
    import os

    for root, dirs, filenames in os.walk(dir_path):
        for name in filenames:
            if name.endswith(suffix):
                return True

    return False


def remove_files(dir_path, suffix):
    try:
        files = list_files(dir_path, suffix)
        for file in files:
            file.unlink()

    except Exception as e:
        print(f"Error removing files: {e}")


def _url_to_pattern(url):
    url_parts = url.split("/")
    result = ""
    for part in url_parts:
        if part in ["commit", "commits", "pull", "files"]:
            result += f"/{part}"
            continue

        if not result:
            continue

        if is_int(part):
            result += "/[D]"

        else:
            result += f"/[X]"

    return result


def _url_to_save(url):
    url_parts = url.split("/")
    result = ""
    for part in url_parts:
        if part not in ["commit", "commits", "pull"] and not result:
            continue

        result += f"/{part}"

    return result


def _search_github_in_data(file_name, skip_keys=None):
    print(f"Processing {file_name}")
    if skip_keys is None:
        skip_keys = []

    with open(file_name, 'r', encoding='utf-8') as f:
        data = json.load(f)

    found_values = defaultdict(lambda: defaultdict(list))
    else_types = set()

    def _search(d, path=""):
        """
        Search for a value in a nested dictionary.
        Returns the key if found, otherwise None.
        """
        if isinstance(d, dict):
            for k, v in d.items():
                if k in skip_keys:
                    continue

                if is_int(k):
                    k = f"[D]"

                new_path = f"{path}.{k}"
                _search(v, new_path)

        elif isinstance(d, list):
            for i, vv in enumerate(d):
                new_path = f"{path}.[D]"
                _search(vv, new_path)

        elif isinstance(d, str):
            matches = any_url_pattern.findall(d)
            for matched_url, matched_domain, matched_type in matches:
                if "github.com" not in matched_domain:
                    NOT_GITHUB_URLS[matched_domain] += 1
                    continue

                match = github_url_pattern.search(matched_url)
                if not match:
                    INCORRECT_URLS[matched_type].add(matched_url)
                    continue

                else:
                    val = match.group(1)
                    if not VALUE_MATCHERS[matched_type](val):
                        INCORRECT_URLS[matched_type].add(_url_to_save(matched_url))
                        continue

                found_values[path][_url_to_pattern(matched_url)].append(_url_to_save(matched_url))

        else:
            else_types.add(type(d))

    _search(data, "d")
    return found_values


def _write_json(file_path: Path, data: dict[str, Any]):
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=json_defaults)


def get_statistics(data_dir, collected_info_dir, skip_keys=None):
    found = defaultdict(lambda: defaultdict(lambda: (0, [])))
    for file_name in list_jsons(dir_path=data_dir):
        new_found = _search_github_in_data(file_name=file_name, skip_keys=skip_keys)
        for k, v_data in new_found.items():
            for v, urls in v_data.items():
                old_cnt, old_urls = found[k][v]
                found[k][v] = (old_cnt + len(urls), list(sorted(set(old_urls + urls))))

    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    _write_json(file_path=collected_info_dir / f"github_urls_in_data_{ts}.json", data=found)
    _write_json(file_path=collected_info_dir / f"incorrect_urls_in_data_{ts}.json", data=INCORRECT_URLS)
    _write_json(file_path=collected_info_dir / f"not_github_urls_in_data_{ts}.json", data=NOT_GITHUB_URLS)
