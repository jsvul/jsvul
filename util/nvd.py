import os

import requests
from dotenv import load_dotenv

from util.cache import get_cache_file_name, read_cache, write_cache, EMPTY_VALUE
from util.common import get_data_dirs, request_with_retries, Date
from util.regex import match_cve, match_cwe

load_dotenv()

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY", "")

CACHE_DIR, _, DATA_DIR = get_data_dirs("nvd")
API_CACHE_DIR = CACHE_DIR / "api_cache"


def url_from_cve(cve_id):
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def _call_nvd_api(url, cache_key):
    cache_file = get_cache_file_name(API_CACHE_DIR, cache_key)
    r_json = read_cache(cache_file)
    if r_json:
        return r_json

    headers = {
        "apiKey": API_KEY
    }
    r_json = EMPTY_VALUE
    resp = request_with_retries(4, requests.get, url, headers=headers, timeout=15)
    if resp:
        r_json = resp.json() or r_json

    write_cache(cache_file, r_json)
    return r_json


def _get_cve_info(cve_id):
    cve_id = match_cve(cve_id or "")
    if not cve_id:
        return {}

    cve_data_path = DATA_DIR / f"{cve_id}.json"
    if cve_data_path.exists():
        return read_cache(cve_data_path)

    cve_info = _call_nvd_api(f"{NVD_API}?cveId={cve_id}", f"cveId={cve_id}")
    for vuln in cve_info.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        if cve.get("id") != cve_id:
            continue

        return cve

    return {}


def get_all_cve_from(start_index: int):
    return _call_nvd_api(f"{NVD_API}?startIndex={start_index}", f"startIndex={start_index}")


def is_cve_valid(cve_id):
    status = get_status(cve_id).lower()
    return status in ["analyzed", "modified"]


def is_cve_invalid(cve_id):
    status = get_status(cve_id).lower()
    return status in ["deferred", "rejected"]


def collect_cwes_from_cve(cve_id):
    cve_info = _get_cve_info(cve_id)
    cwes = set()
    weaknesses = cve_info.get("weaknesses", [])
    for weakness in weaknesses:
        description = weakness.get("description", [])
        for desc in description:
            cwe_id = desc.get("value", "")
            cwe_id = match_cwe(cwe_id)
            if cwe_id:
                cwes.add(cwe_id)

    return cwes


def get_status(cve_id):
    cve_info = _get_cve_info(cve_id)
    return cve_info["vulnStatus"] if cve_info else ""


def get_descriptions(cve_id):
    cve_info = _get_cve_info(cve_id)
    return [d["value"] for d in cve_info.get("descriptions", [])]


def _time_split(time: str) -> Date:
    time_parts = time.split("-")
    return Date(int(time_parts[0]), int(time_parts[1]), int(time_parts[2][:2]))


def get_publish_time(cve_id) -> Date:
    cve_info = _get_cve_info(cve_id)
    return _time_split(cve_info["published"]) if cve_info else Date(int(cve_id.split("-")[1]))
