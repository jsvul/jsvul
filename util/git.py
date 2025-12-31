import logging
import os
import requests
import time

from dotenv import load_dotenv

from util.cache import get_cache_file_name, read_cache, write_cache, EMPTY_VALUE
from util.common import get_data_dirs, request_with_retries

logger = logging.getLogger(__name__)

load_dotenv()

GH_TOKEN = os.getenv("GH_TOKEN")

CACHE_DIR, _, _ = get_data_dirs("git_cache")

RESOLVED_REPOS_DIR = CACHE_DIR / "resolved_repos"
RESPONSES_DIR = CACHE_DIR / "responses"
PATCHES_DIR = CACHE_DIR / "patches"


def get_commit_url(project, sha):
    return f"https://github.com/{project}/commit/{sha}"


def _convert_files_array(files):
    """
    Convert the files array from GitHub API to a dictionary having only the relevant key.
    """
    relevant_file_keys = ["sha", "filename", "status", "additions", "deletions", "changes"]
    return [{k: v for k, v in file.items() if k in relevant_file_keys} for file in files]


def _convert_files_diff_array(files):
    """
    Convert the files array from GitHub API to a dictionary having only the relevant key.
    """
    relevant_file_keys = ["filename", "status", "patch"]
    return [{k: v for k, v in file.items() if k in relevant_file_keys} for file in files]


def _send_gh_request(url, allow_redirects=True, accept="application/vnd.github.v3+json"):
    headers = {
        "Authorization": f"token {GH_TOKEN}",
        "Accept": accept,
    }
    r = requests.get(url, headers=headers, allow_redirects=allow_redirects, timeout=15)
    if r.status_code == 403 and r.headers.get("X-RateLimit-Remaining") == "0":
        reset = int(r.headers.get("X-RateLimit-Reset", "0"))
        wait = max(0, reset - int(time.time())) + 1
        time.sleep(wait)
        r = requests.get(url, headers=headers, allow_redirects=allow_redirects, timeout=15)

    return r


def _call_gh_api(url):
    cache_file_name = get_cache_file_name(RESPONSES_DIR, url)
    cache = read_cache(cache_file_name)
    if cache:
        return cache

    r_json = EMPTY_VALUE
    resp = request_with_retries(4, _send_gh_request, url)
    if resp:
        r_json = resp.json() or r_json

    write_cache(cache_file_name, r_json)
    return r_json


def resolve_repo(project, max_hops=10):
    cache_file_name = get_cache_file_name(RESOLVED_REPOS_DIR, project)
    cache = read_cache(cache_file_name)
    if project in cache:
        return cache[project]

    """Return (resolved_full_name, repo_id). None if not found."""
    owner, repo = project.split("/")
    url = f"https://api.github.com/repos/{owner}/{repo}"

    for _ in range(max_hops):
        r = _send_gh_request(url, allow_redirects=False)
        if r.status_code == 200:
            j = r.json()
            result = j["full_name"]
            cache[project] = result
            write_cache(cache_file_name, cache)
            return result

        if r.status_code in (301, 302, 307, 308):
            url = r.headers.get("Location")
            if not url:
                break

            continue

        if r.status_code == 404:
            cache[project] = None
            write_cache(cache_file_name, cache)
            return None

        if r.status_code == 403 and r.headers.get("X-RateLimit-Remaining") == "0":
            reset = int(r.headers.get("X-RateLimit-Reset", "0"))
            wait = max(0, reset - int(time.time())) + 1
            logger.debug(f"Rate limit exceeded, waiting for {wait} seconds...")
            time.sleep(wait)
            continue

        raise RuntimeError(f"GitHub API error {r.status_code}: {r.text[:200]}")

    raise RuntimeError("Too many redirects or missing Location header")


def get_commit_message(project, commit):
    res_json = _call_gh_api(f"https://api.github.com/repos/{project}/commits/{commit}")
    return res_json.get("commit", {}).get("message")


def get_stats_and_files(project, commit):
    if not project or not commit:
        return None, None

    res_json = _call_gh_api(f"https://api.github.com/repos/{project}/commits/{commit}")
    return res_json.get("stats", {}), res_json.get("files", [])


def get_files(project, commit):
    if not project or not commit:
        return None

    res_json = _call_gh_api(f"https://api.github.com/repos/{project}/commits/{commit}")
    return res_json.get("files", [])


def get_parents_and_files(project, commit):
    if not project or not commit:
        return None

    res_json = _call_gh_api(f"https://api.github.com/repos/{project}/commits/{commit}")
    parents = [p["sha"] for p in res_json.get("parents", [])]
    files = _convert_files_array(res_json.get("files", []))
    return parents, files


def get_diff(project, commit):
    if not project or not commit:
        return None

    res_json = _call_gh_api(f"https://api.github.com/repos/{project}/commits/{commit}")
    return _convert_files_diff_array(res_json.get("files", []))


def get_diff_files(project, fixing_sha, vulnerable_sha):
    if not project or not fixing_sha or not vulnerable_sha:
        return None

    res_json = _call_gh_api(f"https://api.github.com/repos/{project}/compare/{vulnerable_sha}...{fixing_sha}")
    return _convert_files_array(res_json.get("files", []))


def get_merge_commit_sha(project, pr_number):
    if not project or not pr_number:
        return None

    res_json = _call_gh_api(f"https://api.github.com/repos/{project}/pulls/{pr_number}")
    return res_json.get("merge_commit_sha")


def get_full_commit_sha(project, sha):
    if not project or not sha:
        return None

    res_json = _call_gh_api(f"https://api.github.com/repos/{project}/commits/{sha}")
    return res_json.get("sha")
