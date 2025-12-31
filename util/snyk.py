import re
import requests
from bs4 import BeautifulSoup

from util.cache import get_cache_file_name, read_cache, write_cache
from util.common import get_data_dirs, request_with_retries, Date
from util.regex import match_commit, match_pr, match_cve, match_cwe

CACHE_DIR, _, _ = get_data_dirs("snyk")

snyk_id_pattern = re.compile(r"snyk.io/vuln/([^/?#%]+)", re.IGNORECASE)

introduced_pattern = re.compile(r"introduced: (\d{1,2} [a-zA-Z]{3} \d{4})", re.IGNORECASE)


def url_from_snyk_id(snyk_id: str) -> str:
    return f"https://security.snyk.io/vuln/{snyk_id}"


def snyk_id_from_url(url: str) -> str | None:
    m = snyk_id_pattern.search(url)
    return m.group(1) if m else None


def _get_html_from_url(url):
    cache_file_name = get_cache_file_name(CACHE_DIR, url)
    cache = read_cache(cache_file_name)
    if cache:
        html = cache["html"]

    else:
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Accept-Language": "en-US,en;q=0.9",
        }

        html = None
        resp = request_with_retries(5, requests.get, url, headers=headers, timeout=10)
        if resp:
            html = resp.text

        write_cache(cache_file_name, {"html": html})

    return html


def _get_links_from_url(url, get_link_info, check_link):
    html = _get_html_from_url(url)
    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")
    return list({
        get_link_info(a)
        for a in soup.find_all("a", href=True)
        if check_link(a)
    })


def _get_texts_from_url(url, get_text_info, check_text):
    html = _get_html_from_url(url)
    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")
    return list({
        get_text_info(t)
        for t in soup.find_all(string=True)
        if t.parent.name not in ["script", "style"] and t.strip() and check_text(t)
    })


def _is_commit_link(a):
    text = a.get_text(strip=True).lower()
    commit_texts = ["github commit", "fix commit", "git commit"]
    return any(ct in text for ct in commit_texts) or match_commit(text)[1]


def _is_pr_link(a):
    text = a.get_text(strip=True).lower()
    pr_texts = ["github pr", "github fix pr"]
    return any(prt in text for prt in pr_texts) or match_pr(text)[1]


def _is_cve_link(a):
    text = a.get_text(strip=True)
    return match_cve(text)


def _is_cwe_link(a):
    text = a.get_text(strip=True)
    return match_cwe(text)


def _is_introduced_text(text):
    return introduced_pattern.search(text)


def _get_href_from_a(a):
    return a["href"]


def _get_text_from_a(a):
    return a.get_text(strip=True)


def _get_introduced_text(text):
    return introduced_pattern.search(text).group(1)


def _collect_links_from_snyk_url(url, link_checks):
    results = []
    vuln_id = snyk_id_from_url(url)
    if vuln_id:
        snyk_url = f"https://security.snyk.io/vuln/{vuln_id}"
        for is_commit, get_link_info in link_checks:
            results.append(_get_links_from_url(url=snyk_url, get_link_info=get_link_info, check_link=is_commit))

    return results


def collect_fixes_from_snyk_url(url):
    commits, prs = _collect_links_from_snyk_url(
        url=url, link_checks=[
            (_is_commit_link, _get_href_from_a),
            (_is_pr_link, _get_href_from_a)
        ]
    )
    return commits or prs


def collect_others_from_snyk_url(url):
    non_commits, non_prs = _collect_links_from_snyk_url(
        url=url, link_checks=[
            (lambda a: not _is_commit_link(a), _get_text_from_a),
            (lambda a: not _is_pr_link(a), _get_text_from_a)
        ]
    )
    return [l for l in non_commits if l in non_prs]


def collect_cves_from_snyk_url(url):
    cves, = _collect_links_from_snyk_url(
        url=url, link_checks=[
            (_is_cve_link, lambda a: match_cve(_get_text_from_a(a))),
        ]
    )
    return cves


def collect_cwes_from_snyk_url(url):
    cwes, = _collect_links_from_snyk_url(
        url=url, link_checks=[
            (_is_cwe_link, lambda a: match_cwe(_get_text_from_a(a))),
        ]
    )
    return cwes


def _time_split(time) -> Date:
    import dateutil

    time_parts = str(dateutil.parser.parse(time)).split("-")
    return Date(int(time_parts[0]), int(time_parts[1]), int(time_parts[2][:2]))


def get_introduce_time(url) -> Date | None:
    results = []
    vuln_id = snyk_id_from_url(url)
    if vuln_id:
        snyk_url = f"https://security.snyk.io/vuln/{vuln_id}"
        results = _get_texts_from_url(
            url=snyk_url, get_text_info=_get_introduced_text, check_text=_is_introduced_text
        )

    if len(results) == 1:
        return _time_split(results[0])

    date_from_id = vuln_id.split(":")[-1]
    if len(date_from_id) == 8 and date_from_id.startswith("20"):
        return Date(int(date_from_id[:4]), int(date_from_id[4:6]), int(date_from_id[6:]))

    return None
