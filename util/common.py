import logging
import time
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Optional

import humps
from dotenv import load_dotenv

logger = logging.getLogger(__name__)


@dataclass
class StoredData:
    def to_dict(self):
        result = {}
        for k, v in self.__dict__.items():
            if v or v == 0:
                result[k] = v

        return order_dict(result)

    @classmethod
    def from_dict(cls, obj, force=False):
        if not isinstance(obj, dict):
            return obj

        snake_obj = humps.decamelize(obj)

        if force:
            own_keys = {f.name for f in fields(cls)}
            relevant_part = {k: v for k, v in snake_obj.items() if k in own_keys}
            return cls(**relevant_part)

        if snake_obj.keys() and set(snake_obj.keys()) <= {f.name for f in fields(cls)}:
            return cls(**snake_obj)

        return obj


@dataclass
class CVEData(StoredData):
    vuln_sha: Optional[str] = None
    old_project: str | None = None
    cve: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    github: list[str] = field(default_factory=list)
    others: list[str] = field(default_factory=list)
    snyk: list[str] = field(default_factory=list)

    def merge_data_from(self, other: "CVEData"):
        self.cwe = list(set(self.cwe) | set(other.cwe))
        self.cve = list(set(self.cve) | set(other.cve))
        self.github = list(set(self.github) | set(other.github))
        self.snyk = list(set(self.snyk) | set(other.snyk))
        self.others = list(set(self.others) | set(other.others))


@dataclass
class FilteredData(CVEData):
    dataset: str | None = None

    def to_cve_data(self) -> CVEData:
        return CVEData(**{f.name: getattr(self, f.name) for f in fields(CVEData)})


@dataclass
class GitHubFile(StoredData):
    filename: str
    status: str
    additions: int
    deletions: int
    changes: int
    previous_filename: str | None = None
    sha: str | None = None

    def file_without_sha(self):
        return self.filename, self.status, self.additions, self.deletions, self.changes


@dataclass
class Date(StoredData):
    year: int
    month: int | None = None
    day: int | None = None

    def __lt__(self, other):
        if self.year != other.year:
            return self.year < other.year

        if self.month != other.month:
            return (self.month or 13) < (other.month or 13)

        return (self.day or 13) < (other.day or 13)


@dataclass
class MergedCommitData(StoredData):
    vuln_sha: Optional[str] = None
    cwe: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    github: list[str] = field(default_factory=list)
    snyk: list[str] = field(default_factory=list)
    others: list[str] = field(default_factory=list)
    commit_msg: Optional[str] = None
    additions: int | None = None
    deletions: int | None = None
    changes: int | None = None
    files: list[GitHubFile] = field(default_factory=list)
    sources: dict[str, CVEData] = field(default_factory=dict)
    publish_time: Date | None = None

    def merge_data_from(self, other: "MergedCommitData"):
        self.cwe = list(set(self.cwe) | set(other.cwe))
        self.cve = list(set(self.cve) | set(other.cve))
        self.github = list(set(self.github) | set(other.github))
        self.snyk = list(set(self.snyk) | set(other.snyk))
        self.others = list(set(self.others) | set(other.others))
        self.publish_time = min(self.publish_time, other.publish_time)
        for src, src_data in other.sources.items():
            if src in self.sources:
                self.sources[src].merge_data_from(src_data)

            else:
                self.sources[src] = src_data


def get_data_dirs(tool_name: str):
    import os

    load_dotenv()
    root_dir = os.getenv("WORK_DIR")

    if root_dir:
        root_dir = Path(root_dir)

    else:
        root_dir = Path(__file__).parent.parent

    cache_dir = root_dir / "_cache" / tool_name
    collected_info_dir = root_dir / "_collected_info" / tool_name
    data_dir = root_dir / "_data" / tool_name
    return cache_dir, collected_info_dir, data_dir


def json_defaults(o):
    if isinstance(o, set):
        return list(o)

    elif hasattr(o, "to_dict"):
        return o.to_dict()

    raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")


def custom_order_dict(d, key, reverse=False):
    if isinstance(d, dict):
        if isinstance(next(iter(d.values())), dict):
            return {k: custom_order_dict(v, key, reverse) for k, v in sorted(d.items())}

        return {k: custom_order_dict(v, key, reverse) for k, v in sorted(d.items(), key=key, reverse=reverse)}

    else:
        return d


def order_dict_by_value(d):
    return custom_order_dict(d, key=lambda i: i[1], reverse=True)


def order_dict(d):
    if isinstance(d, dict):
        return {k: order_dict(v) for k, v in sorted(d.items())}

    elif isinstance(d, list):
        return sorted([order_dict(v) for v in d], key=lambda x: str(x))

    else:
        return d


def request_with_retries(max_retries, request_func, *args, **kwargs):
    for i in range(max_retries):
        try:
            resp = request_func(*args, **kwargs)
            if resp.status_code in [422, 404]:
                break

            resp.raise_for_status()
            return resp

        except:
            if i == max_retries - 1:
                logger.error(args[0])
                raise

            time.sleep(2 ** i)

    return None


def play_notification_sound(repeat=3):
    try:
        from playsound import playsound

        sound_file = Path(__file__).parent.parent / "notification.mp3"
        for i in range(repeat):
            playsound(sound_file.as_posix())

    except Exception as e:
        logger.debug(f"Could not play sound: {e}")
