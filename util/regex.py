import re

diff_header_pattern = re.compile(r'^diff --git a/(.*?) b/(.*?)\s*$')

cve_pattern = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)
cwe_pattern = re.compile(r"CWE-(\d{1,4})", re.IGNORECASE)

url_part = r"[a-zA-Z0-9._-]+"
github_base = fr"(?:https?://)?github\.com/({url_part}/{url_part})"
github_commit_pattern = re.compile(
    fr"{github_base}(?:/pull/{url_part})?/(?:commits?|blob)/([0-9a-fA-F]{{4,40}})", re.IGNORECASE
)

gitlab_base = fr"(?:https?://)?gitlab\.com/({url_part}/{url_part})"
gitlab_commit_pattern = re.compile(fr"{gitlab_base}(?:/-)?/commits?/([0-9a-fA-F]{{4,40}})", re.IGNORECASE)

commit_patterns = [github_commit_pattern, gitlab_commit_pattern]

pr_pattern = re.compile(fr"{github_base}/pull/(\d+)", re.IGNORECASE)


def _match_pattern(pattern, text, result_length) -> list[str | None]:
    match = pattern.search(text)
    return match.groups() if match else [None] * result_length


def _find_all_pattern(pattern, text):
    matches = pattern.findall(text)
    return matches


def match_cwe(text):
    cwe_number, = _match_pattern(cwe_pattern, text, 1)
    return f"CWE-{str(int(cwe_number))}" if cwe_number else None


def match_cve(text):
    cve_id, = _match_pattern(cve_pattern, text, 1)
    return cve_id.upper() if cve_id else None


def match_commit(text):
    for pattern in commit_patterns:
        project, sha = _match_pattern(pattern, text, 2)
        if project and sha:
            return project.lower(), sha.lower()

    return None, None


def match_pr(text):
    project, pr_number = _match_pattern(pr_pattern, text, 2)
    return (project.lower(), str(int(pr_number))) if project and pr_number else (None, None)
