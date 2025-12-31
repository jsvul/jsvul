import logging
import os, re, requests
from typing import Any
import time

from dotenv import load_dotenv

from util.cache import get_cache_file_name, read_cache, write_cache, EMPTY_VALUE
from util.common import get_data_dirs, Date
from util.regex import match_cve, match_cwe

logger = logging.getLogger(__name__)

load_dotenv()

GH_TOKEN = os.getenv("GH_TOKEN")
CACHE_DIR, _, _ = get_data_dirs("advisory_cache")

ghsa_pattern = re.compile(r"GHSA-[A-Za-z0-9-]+", re.IGNORECASE)


def url_from_ghsa(ghsa: str) -> str:
    return f"https://github.com/advisories/{ghsa}"


def ghsa_from_url(url: str) -> str | None:
    m = ghsa_pattern.search(url)
    return m.group(0) if m else None


def _advisory_request(advisory_url: str) -> dict[str, Any]:
    cache_file_name = get_cache_file_name(CACHE_DIR, advisory_url)
    cache = read_cache(cache_file_name)
    if cache:
        return cache

    ghsa = ghsa_from_url(advisory_url)
    if not ghsa:
        logger.debug(f"Invalid advisory URL: {advisory_url}")
        return {}

    headers = {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    r = requests.get(f"https://api.github.com/advisories/{ghsa}", headers=headers, timeout=30)
    if r.status_code == 403 and r.headers.get("X-RateLimit-Remaining") == "0":
        reset = int(r.headers.get("X-RateLimit-Reset", "0"))
        wait = max(0, reset - int(time.time())) + 1
        logger.debug(f"Rate limit exceeded, waiting for {wait} seconds...")
        time.sleep(wait)
        r = requests.get(f"https://api.github.com/advisories/{ghsa}", headers=headers, timeout=30)

    r_json = EMPTY_VALUE
    if r.status_code == 404:
        write_cache(cache_file_name, r_json)
        return r_json

    r.raise_for_status()
    r_json = r.json() or r_json
    write_cache(cache_file_name, r_json)
    return r_json


def collect_cves_from_ghsa(url):
    r_json = _advisory_request(url)
    cves = set()
    if "identifiers" in r_json:
        cve_ids = (match_cve(e["value"]) for e in r_json["identifiers"])
        cves = {cve for cve in cve_ids if cve}

    return cves


def collect_cwes_from_ghsa(url):
    r_json = _advisory_request(url)
    cwes = set()
    if "cwes" in r_json:
        cwe_ids = (match_cwe(e["cwe_id"]) for e in r_json["cwes"])
        cwes = {cwe for cwe in cwe_ids if cwe}

    return cwes


def _time_split(time: str) -> Date:
    time_parts = time.split("-")
    return Date(int(time_parts[0]), int(time_parts[1]), int(time_parts[2][:2]))


def collect_publish_time_from_ghsa(url) -> Date | None:
    r_json = _advisory_request(url)
    return _time_split(r_json["published_at"]) if "published_at" in r_json else None
