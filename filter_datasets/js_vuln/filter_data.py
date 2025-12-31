import logging
from collections import defaultdict
from pathlib import Path

from filter_datasets.js_vuln.utils import load_json_file
from util.cache import cache, write_cache
from util.common import get_data_dirs, FilteredData
from util.git import get_commit_url

logger = logging.getLogger(__name__)

# project: { vuln_sha: fix_sha }
real_fix_sha = {
    "sequelize/sequelize": {
        # https://github.com/sequelize/sequelize/commit/825eb75f31e71a242477a16e9a593ffc4519cd84 not a security fix
        "87358fae7abe6db82a1141b2d73d7f31b2726d87": "3f11bd97386f1cad4961d2cd054347508ef0aca5"
    },
    "facebook/react": {
        # https://github.com/facebook/react/commit/94a9a3e752fe089ab23f3a90c26d20d46d62ab10 is fix for another version
        "3e455a43975a34daac7dca978cbcc43c5a9d4ab1": "393a889aaceb761f058b09a701f889fa8f8b4e64"
    },
    "angular/angular.js": {
        "2df721965bccdfbbaeed5d5624892accf698e768": "48fa3aadd546036c7e69f71046f659ab1de244c6"
    }
}

# project: { fix_sha: vuln_sha }
real_vuln_sha = {
    "actionhero/actionhero": {
        "f9f5d92f7c50a6dad38f558bd0a207b18e3580c1": "57dd64aaf1bc53ece4b6ea63528109c2ab08583f"
    },
    "angular/angular.js": {
        "f33ce173c90736e349cf594df717ae3ee41e0f7a": "181fc567d873df065f1e84af7225deb70a8d2eb9",
        "77ada4c82d6b8fc6d977c26f3cdb48c2f5fbe5a5": "db713a1c1b2cf1a9f5f9b52a0e2481be3b0cf1be",
        "ab80cd90661396dbb1c94c5f4dd2d11ee8f6b6af": "8199f4dbde65b5a0db78fa48327129625363c2a6",
        "5a674f3bb9d1118d11b333e3b966c01a571c09e6": "e94b37e20e8e37abce0e7d13265298d86d4081fd",
        "f35f334bd3197585bdf034f4b6d9ffa3122dac62": "dd4ce50392e20b61199bcc66cf34c22efdf2e0f7",
        "0ff10e1b56c6b7c4ac465e35c96a5886e294bac5": "a7076dc0bb77ca1eff792c56394cc7c97a1a3b76",
        "667db466f959f8bbca1451d0f1c1a3db25d46a6c": "2c9c3a07845d9a0aae12fa3259983d37b68f918f"
    },
    "dcodeio/closurecompiler.js": {
        "c01efe9d86dc8d07e14c5a6ba1586244ce53a698": "e59848f5975e5b15279c044daf9cff8ff192bae6"
    },
    "dodo/node-slug": {
        "e82fccc6b3d850227560db659b17df0e242ae51b": "fcb67e2f63cf2f0e9e7eebd6eaf558cfa36ec2a0"
    },
    "electron/electron": {
        "a9d4d9ad85f8969dbc532dc9781645c01da4bdbc": "c27633dff4eec32030a9c4c887fd4808ecc2a7c6"
    },
    "facebook/react": {
        # 393a889aaceb761f058b09a701f889fa8f8b4e64 is vulnerable version of another commit
        "94a9a3e752fe089ab23f3a90c26d20d46d62ab10": "48af9c7bdad9c18f9349bcf3949b656da19ab56e"
    },
    "jquery/jquery": {
        "f60729f3903d17917dc351f3ac87794de379b0cc": "5da5035039c48fd00e3effa5135e257ccda79454"
    },
    "nodebb/nodebb": {
        "e028ac13639faf703922ce3ed728a85d2e27655e": "40d73e2a54427630531e584d8fb1157fd0d136f9"
    },
    "socketio/engine.io": {
        "27141f962d72e6e1b0940f0cca88265799966b39": "fba0495614cdcd1cf54e34b08f4ba99ffaf63483"
    },
    "tobli/alto-saxophone": {
        "8cb735e8194fa3aac47727cda5ba0a876adc4e45": "21d926cdc650692ea14fcf19275a04104ff9ac0b"
    },
    "tryghost/ghost": {
        "32b9fc71a7f1400acff1f2446167b6c852769843": "5a421af22b0513fcb58ce7e0c9507bdc33909f86"
    },
    "websockets/ws": {
        "7253f06f5432c76f3e82e2c055fcea08b612d8b2": "269dff8bfe99437c77f5ef558278acb120f929ec"
    }
}

skip_vuln_sha = {
    "jquery/jquery": {
        "250a1990baa571de60325ab2c52eabb399c4cf9e": "not a vulnerable version of a fixed code"
    },
    "electron/electron": {
        "851f490168747b450d16eb992a95095246853ef4": "not a vulnerable version of a fixed code",
        "1d32f300f3b5cd6b6dfb8b14a933a20d6260acaa": "not a vulnerable version of a fixed js code"
    },
    "angular/angular.js": {
        "e46ab434228c16a668937eb76215d371597f653b": "not a vulnerable version of a fixed code"
    },
}

skip_fix_sha = {
    "angular/angular.js": {
        "528be29d1662122a34e204dd607e1c0bd9c16bbc": "only partial fix"
    }
}

not_accessible_vuln_ids = {
    "npm:localhost-now:20180424", "npm:pdfinfojs:20180516", "npm:superstatic:20180516", "npm:reveal.js:20131024",
    "npm:inert:20141216", "npm:nes:20170414", "npm:mustache:20151214", "npm:glance:20180424", "npm:randomatic:20170414",
    "npm:mathjs:20171206", "npm:jquery:20170321", "npm:brace-expansion:20170425", "npm:mapbox.js:20151024",
    "npm:mqtt:20180115", "npm:mysql:20180425", "npm:crud-file-server:20180421", "npm:engine.io:20140212",
    "npm:engine.io-client:20160426", "npm:floody:20180425", "npm:serve-here:20180112", "npm:whereis:20180425"
}


def get_vuln_sha_entries(collected_info_dir: Path):
    vuln_sha_entries = defaultdict(list)

    merged_data = load_json_file(collected_info_dir / "merged_csv_and_vu_blob.json")
    for project, p_data in merged_data.items():
        for fix_sha, cve_info in p_data.items():
            if project in real_vuln_sha and fix_sha in real_vuln_sha[project]:
                vuln_sha = real_vuln_sha[project][fix_sha]

            else:
                vuln_sha = cve_info["vuln_sha"]
                if project in real_fix_sha and vuln_sha in real_fix_sha[project]:
                    fix_sha = real_fix_sha[project][vuln_sha]

            if project in skip_vuln_sha and vuln_sha in skip_vuln_sha[project]:
                continue

            if project in skip_fix_sha and fix_sha in skip_fix_sha[project]:
                continue

            new_entry = {
                "url": get_commit_url(project, fix_sha),
                "project": project,
                "fix_sha": fix_sha,
                "files": cve_info["files"],
                "cve": cve_info["cve"],
                "cwe": cve_info["cwe"],
                "vuln_id": cve_info["vuln_id"],
            }
            if "old_project" in cve_info:
                new_entry["old_project"] = cve_info["old_project"]

            if any(new_entry == e for e in vuln_sha_entries[vuln_sha]):
                continue

            vuln_sha_entries[vuln_sha].append(new_entry)

    return vuln_sha_entries


def find_duplicates(collected_info_dir: Path):
    vuln_sha_entries = get_vuln_sha_entries(collected_info_dir)
    return {k: v for k, v in vuln_sha_entries.items() if len(v) > 1}


def filter_js_files(_, collected_info_dir: Path):
    logger.info("Filtering js_vuln")
    result = defaultdict(lambda: defaultdict(FilteredData))
    for vuln_sha, v_data in get_vuln_sha_entries(collected_info_dir).items():
        for entry in v_data:
            files = entry["files"]
            cve = entry["cve"]
            cwe = entry["cwe"]
            vuln_id = entry["vuln_id"]
            project = entry["project"]
            fix_sha = entry["fix_sha"]
            if fix_sha in result[project]:
                raise ValueError(
                    f"Duplicate fixing commit sha found for {project} {fix_sha}. "
                    f"Vuln SHA: {vuln_sha}, Existing files: {result[project][fix_sha].files}, "
                    f"New files: {files}"
                )

            filtered_data = result[project][fix_sha]

            filtered_data.cve = sorted(set(cve))
            filtered_data.cwe = sorted(set(cwe))
            filtered_data.snyk = sorted(set(vuln_id))
            filtered_data.files = sorted(set(files))
            filtered_data.vuln_sha = vuln_sha
            filtered_data.dataset = "js_vuln"
            if "old_project" in entry:
                filtered_data.old_project = entry["old_project"]

    write_cache(collected_info_dir / "filtered_data.json", result)
    return result


if __name__ == "__main__":
    _, cid, _ = get_data_dirs(Path(__file__).parent.name)
    filter_js_files(_, collected_info_dir=cid)
