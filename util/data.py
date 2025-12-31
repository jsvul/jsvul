from dataclasses import dataclass, field

from util.common import StoredData, Date


@dataclass
class FunctionLoc(StoredData):
    start_line: int
    start_column: int
    end_line: int
    end_column: int


@dataclass
class UnifiedFunctionData(StoredData):
    id: str
    project: str
    sha: str
    file: str
    loc: FunctionLoc
    label: int
    body: str
    name: str | None = None
    cwe: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    ghsa: list[str] = field(default_factory=list)
    snyk: list[str] = field(default_factory=list)
    other: list[str] = field(default_factory=list)
    publish_time: Date | None = None
