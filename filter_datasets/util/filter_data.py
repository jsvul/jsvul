import logging
from collections import defaultdict
from pathlib import Path

from tqdm import tqdm

from filter_datasets.js_vuln.utils import load_json_file
from util.advisory import ghsa_from_url
from util.filter import is_js_file
from util.snyk import snyk_id_from_url, collect_fixes_from_snyk_url
from filter_datasets.util.statistics import list_jsons
from util.common import FilteredData
from util.git import (
    resolve_repo, get_full_commit_sha, get_merge_commit_sha, get_commit_message, get_files, get_stats_and_files
)
from util.regex import match_cve, match_cwe, match_commit, match_pr

logger = logging.getLogger(__name__)

# key has been renamed to value
renamed_repos = {
    "otrs/otrs": "centuran/otrs-community-edition",
    "linxiaowu66/swagger-ui": "swagger-api/swagger-ui",
    "zhuangya/node-slug": "dodo/node-slug",
    "substack/minimist": "minimistjs/minimist",
}

removed_repos = {
    "mangoraft/git",
    "assfugil/nickchanbot",
    "finastra/ssr-pages",
    "andrepolischuk/servst",
    "sorellabs/xps",
    "calesanz/gibb-modul-151",
    "flitbit/json-ptr",
    "capnsquarepants/wordcraft",
    "jeff-kelley/opensim-utils",
    "mnbikeways/database",
    "harrystech/dynosaur-rails",
    "lunary-ai/lunary"
}

# new commit hashes are coming from ossf-cve-benchmark, which is handpicked, validated
moved_fix_sha = {
    "roest01/node-pdf-image": {
        "54679496a89738443917608c2bbe2f6e5dd20e83": "15c13846a966c8513e30aff58471163a872b3b6d"
    },
    "prismjs/prism": {
        "7bd7de05edf71112a3a77f87901a2409c9c5c20c": "8bba4880202ef6bd7a1e379fe9aebe69dd75f7be"
    },
    "juliangruber/brace-expansion": {
        "b13381281cead487cbdbfd6a69fb097ea5e456c3": "ed46e5ba619bd938e5b84835fca00eed0adc5585"
    },
    "scratchfoundation/scratch-svg-renderer": {
        "9ebf57588aa596c4fa3bb64209e10ade395aee90": "21d8f1668f6a8926280f9a9247b062c8ec6957fd"
    },
    "mostafa-samir/zip-local": {
        "9445f96223041abf2bf08daa56f8da50b674cbcd": "949446a95a660c0752b1db0c654f0fd619ae6085"
    },
    "apache/uima-ducc": {
        "113740c16f829c4a3e6bb3a6014c18b4b0c1fea8": "37d7b730908496b789b541603829bbb62e2ce94f"
    }
}

removed_fix_sha = {
    "awslabs/aws-js-s3-explorer": {
        "87efa7d6885c4a9d8473ec5893adf8e4922a8a89":
            "duplicate of https://github.com/awslabs/aws-js-s3-explorer/commit/7be671e858601455d6969e445d21a911632d6c94"
    },
    "ether/etherpad-lite": {
        "9d4e5f6":
            "fixed version still contains the same vulnerability. See: "
            "https://github.com/ether/etherpad-lite/commit/0fa7650df8f940ed6b577d79836a78eb09726c4b"
    },
    "misp/misp": {
        "3630a8b1e1cd99862867fe72ffa1ff51e4d9c09f": "not a fixing commit"
    },
    "roundcube/roundcubemail": {
        "699af1e5206ed9114322adaa3c25c1c969640a53":
            "not the real fixing commit, real fixing commit is: "
            "https://github.com/roundcube/roundcubemail/commit/4a408843b0ef816daf70a472a02b78cd6073a4d5"
    },
    "omrilotan/async-git": {
        "611823bd97dd41e9e8127c38066868ff9dcfa57a":
            "not the fixing commit, here is the fixing commit: "
            "https://github.com/omrilotan/async-git/commit/a5f45f58941006c4cc1699609383b533d9b92c6a"
    },
    "bcamarneiro/macfromip": {
        "1bbed8cd6f8299ad2e9d028e0ed0771340ab8391": "not a fixing commit"
    },
    "angular/angular.js": {
        "c8b7c16b78bc3ba7486ebf9c41f4603a9f429dd1": "not a fixing commit"
    },
    "d3/d3-color": {
        "4c2be7e59a317d0af7c3d66e44fa888f02163a59": "not a fixing commit (secbenchjs)"
    },
    "jonschlinkert/set-value": {
        "7cf8073bb06bf0c15e08475f9f952823b4576452": "not a fixing commit (secbenchjs)"
    },
    "facebook/hermes": {
        "fe52854cdf6725c2eaa9e125995da76e6ceb27da": "only .cpp files in commit (secbenchjs)"
    },
    "nim579/node-srv": {
        "15be996c0520ac6e4dee0cf0808fc7e72effd2a2": "only .coffee files in commit (secbenchjs)"
    },
    "milojs/proto": {
        "10adbec293e7dfdb2e9e565bfd77187cf0373cbe": "only .jst files in commit (secbenchjs)"
    },
    "flexsolution/alfrescoresetpassword": {
        "5927b9651356c4cd952cb9b485292583d305b47c": "not a js fix commit"
    },
    "mumble-voip/mumble": {
        "817d2c1a03cdeb0d951b0460c5c03c504fdeed40": "not a js fix commit"
    },
    "netdisco/netdisco": {
        "39562e0633a2472d50f7f33e69c36da4ad1fbfa3": "not a js fix commit",
        "deb9b62c7f839f5e41aa4d620bcdac5f9321a8a3": "not a js fix commit"
    },
    "pyload/pyload": {
        "46d75a3087f3237d06530d55998938e2e2bda6bd": "not a js fix commit"
    },
    "tiagorlampert/chaos": {
        "1b451cf62582295b7225caf5a7b506f0bad56f6b": "not a js fix commit",
        "b47438d36e3ad746de8c009e644f6e5396703f25": "not a js fix commit"
    },
    "tribalsystems/zenario": {
        "dfd0afacb26c3682a847bea7b49ea440b63f3baa": "not a js fix commit"
    },
    "wasp-lang/wasp": {
        "433b9b7f491c172db656fb94cc85e5bd7d614b74": "not a js fix commit"
    }
}

# project -> fixing commit hash -> correct vulnerable commit hash
moved_vuln_sha = {
    "apache/uima-ducc": {
        # fixing commit hash was updated, vulnerable commit hash needs to be updated as well
        "37d7b730908496b789b541603829bbb62e2ce94f": "c100eb0fadb04d6e209a714bf9f5cb7b602fd89a"
    },
    "totaljs/framework": {
        # original vuln commit is the wrong parent of the fixing commit (too many commits in between)
        "c812bbcab8981797d3a1b9993fc42dad3d246f04": "fcdf74ca6eee6b559502845944e66ada2f460eba"
    },
    "actions/http-client": {
        # original vuln commit is the wrong parent of the fixing commit (which is a merge commit of a PR)
        "f6aae3dda4f4c9dc0b49737b36007330f78fd53a": "ab10999b092a9629d71c76d2f248dee063e7ae93"
    }
}


def _update_list(list, items):
    if not items:
        return

    list.extend(item for item in items if item)
    list[:] = sorted(set(list))


def _process_fix_sha(project, sha):
    if not project or not sha:
        return None

    if project in removed_fix_sha and sha in removed_fix_sha[project]:
        return None

    if project in moved_fix_sha and sha in moved_fix_sha[project]:
        sha = moved_fix_sha[project][sha]

    return get_full_commit_sha(project, sha).lower()


def _process_vuln_sha(project, fix_sha, sha):
    if not project or not fix_sha or not sha:
        return None

    if project in moved_vuln_sha and fix_sha in moved_vuln_sha[project]:
        sha = moved_vuln_sha[project][fix_sha]

    return get_full_commit_sha(project, sha).lower()


def _process_project(project):
    if project in removed_repos:
        return None, None

    old_project = project
    if project in renamed_repos:
        project = renamed_repos[project]

    return old_project, resolve_repo(project).lower()


def _update_vuln_sha(project, fix_sha, vuln_sha, filtered_data):
    vuln_sha = _process_vuln_sha(project, fix_sha, vuln_sha)
    if vuln_sha:
        if not filtered_data.vuln_sha:
            filtered_data.vuln_sha = vuln_sha

        elif vuln_sha != filtered_data.vuln_sha:
            raise ValueError(
                f"Multiple vulnerable SHAs found for {project} - {fix_sha}: "
                f"{filtered_data.vuln_sha}, {vuln_sha}"
            )


def update_result(
        result: dict[str, dict[str, FilteredData]], project: str, fix_sha: str, caller: str,
        cves: list[str] = None, cwes: list[str] = None, github: list[str] = None, snyk: list[str] = None,
        others: list[str] = None, files: list[str] = None, vuln_sha: str = None
):
    old_project, project = _process_project(project)
    if not project:
        return

    fix_sha = _process_fix_sha(project, fix_sha)
    if not fix_sha:
        return

    cve_list = [match_cve(cve) for cve in (cves or [])]
    cwe_list = [match_cwe(cwe) for cwe in (cwes or [])]

    filtered_data = result[project][fix_sha]

    _update_list(filtered_data.cve, cve_list)
    _update_list(filtered_data.cwe, cwe_list)
    _update_list(filtered_data.github, github)
    _update_list(filtered_data.snyk, snyk)
    _update_list(filtered_data.others, others)
    _update_list(filtered_data.files, files)

    _update_vuln_sha(project, fix_sha, vuln_sha, filtered_data)

    if not filtered_data.dataset:
        filtered_data.dataset = Path(caller).parent.name

    if old_project != project:
        filtered_data.old_project = old_project


def _process_commit_url(url: str | None) -> tuple[str | None, str | None]:
    if not url:
        return None, None

    project, fix_sha = match_commit(url)
    if project in renamed_repos:
        project = renamed_repos[project]

    if (not project or not fix_sha) and not any(s in url for s in ["/commit/", "/commits/"]):
        project, pr = match_pr(url)
        if project in renamed_repos:
            project = renamed_repos[project]

        if project and pr:
            fix_sha = get_merge_commit_sha(project, pr)

    return project, fix_sha


def _snyk_id_has_js_prefix(url):
    snyk_id = snyk_id_from_url(url)
    return any(c in snyk_id for c in ["-JS-", "npm:"])


def _snyk_id_has_no_not_js_prefix(url):
    snyk_id = snyk_id_from_url(url)
    not_js_prefixes = [
        "-JAVA-", "-RUBY-", "-PYTHON-", "-LINUX-", "-DOTNET-", "-GOLANG-", "-PHP-", "-COCOAPODS-"
    ]
    return not any(c in snyk_id for c in not_js_prefixes)


def _get_js_files_from_commit(project, commit_sha):
    files = get_files(project, commit_sha)
    return [
        f["filename"]
        for f in files
        if is_js_file(f["filename"]) and f["changes"] > 0
    ]


def _is_stats_match_file_changes(project, fix_sha):
    stats, files = get_stats_and_files(project, fix_sha)
    return stats["total"] == sum(f["changes"] for f in files)


def _collect_fix_sha(project, fix_sha, data_id, collected_data, ok_commits, skip_commits):
    if project in skip_commits and fix_sha in skip_commits[project]:
        return

    if project in ok_commits and fix_sha in ok_commits[project]:
        collected_data[data_id]["fix_sha"].add((project, fix_sha))
        return

    js_files = _get_js_files_from_commit(project, fix_sha)
    if js_files:
        if _is_stats_match_file_changes(project, fix_sha):
            collected_data[data_id]["fix_sha"].add((project, fix_sha))
            ok_commits[project].add(fix_sha)
            return

        logger.debug(f"Commit https://github.com/{project}/commit/{fix_sha} is too big, skipping...")

    skip_commits[project].add(fix_sha)


def _collect_data_for_filtering(data_dir, is_reference_a_fix, check_for_skip=None):
    collected_data = defaultdict(lambda: defaultdict(set))
    ok_commits = defaultdict(set)
    skip_commits = defaultdict(set)
    json_list = list_jsons(dir_path=data_dir)
    with tqdm(total=len(json_list)) as pbar:
        for file_name in json_list:
            pbar.update(1)
            data = load_json_file(file_name)
            if check_for_skip and check_for_skip(data):
                continue

            data_id = data["id"]
            other_commits = set()
            data_references = {
                (is_reference_a_fix(ref), ref.get("url"))
                for ref in data.get("references", [])
                if ref.get("url")
            }
            patch_found = False
            commit_found = False
            for is_patch, url in data_references:
                if is_patch:
                    patch_found = True

                project, fix_sha = _process_commit_url(url=url)
                if project and fix_sha:
                    if project in removed_repos:
                        continue

                    commit_found = True
                    if is_patch:
                        _collect_fix_sha(project=project, fix_sha=fix_sha, data_id=data_id, collected_data=collected_data,
                                         ok_commits=ok_commits, skip_commits=skip_commits)

                    continue

                ghsa = ghsa_from_url(url)
                if ghsa:
                    collected_data[data_id]["github"].add(ghsa)
                    continue

                snyk_id = snyk_id_from_url(url)
                if snyk_id:
                    collected_data[data_id]["snyk"].add(snyk_id)
                    if not patch_found and _snyk_id_has_js_prefix(url) or _snyk_id_has_no_not_js_prefix(url):
                        for commit_from_snyk in collect_fixes_from_snyk_url(url):
                            if commit_from_snyk not in data_references:
                                other_commits.add(commit_from_snyk)

            if not patch_found and other_commits:
                for url in other_commits:
                    project, fix_sha = _process_commit_url(url=url)
                    if project and fix_sha:
                        _collect_fix_sha(project=project, fix_sha=fix_sha, data_id=data_id, collected_data=collected_data,
                                         ok_commits=ok_commits, skip_commits=skip_commits)

            if data_id in collected_data:
                cd = collected_data[data_id]
                if not commit_found and "snyk" in cd and "fix_sha" in cd:
                    logger.debug(f"  Collected data for ID: {data_id}: {collected_data[data_id]}")
                    logger.debug(f"  Original CVE https://nvd.nist.gov/vuln/detail/{data_id}")
                    logger.debug("  Fixing commit messages:")
                    for project, fix_sha in cd["fix_sha"]:
                        commit_msg = get_commit_message(project, fix_sha)
                        logger.debug(f"    https://github.com/{project}/commit/{fix_sha}: {commit_msg}")

                    logger.debug("")

    return collected_data


def filter_js_files_from_cve_data(caller, data_dir, is_reference_a_fix, check_for_skip=None):
    result = defaultdict(lambda: defaultdict(FilteredData))
    collected_data = _collect_data_for_filtering(
        data_dir=data_dir, is_reference_a_fix=is_reference_a_fix,
        check_for_skip=check_for_skip
    )
    for data_id, c_data in collected_data.items():
        for project, fix_sha in c_data["fix_sha"]:
            cves, github, others = [], [], []
            if cve := match_cve(data_id):
                cves = [cve]

            elif ghsa := ghsa_from_url(data_id):
                github = [ghsa]

            else:
                others = [data_id]

            update_result(
                result=result,
                project=project,
                fix_sha=fix_sha,
                cves=cves,
                github=github + list(c_data.get("github", set())),
                snyk=list(c_data.get("snyk", set())),
                cwes=list(c_data.get("cwe", set())),
                others=others,
                caller=caller
            )

    return result
