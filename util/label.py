from dataclasses import dataclass

from util.common import StoredData


@dataclass(frozen=True)
class Change:
    line: int


@dataclass(frozen=True)
class DirectChange(Change):
    pass


@dataclass(frozen=True)
class MappedChange(Change):
    pass


@dataclass(frozen=True)
class Loc:
    start_line: int
    end_line: int

    def match_changes(self, changes: list[Change]) -> bool:
        return any(self.match(change) for change in changes)

    def match(self, change: Change) -> bool:
        if isinstance(change, MappedChange):
            return self.mapped_match(change)

        if isinstance(change, DirectChange):
            return self.direct_match(change)

        return False

    def direct_match(self, change: Change) -> bool:
        return self.start_line <= change.line <= self.end_line

    def mapped_match(self, change: Change) -> bool:
        return self.start_line < change.line <= self.end_line


@dataclass
class ExtractedFunction(StoredData):
    function_body: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    node_type: str
    function_name: str | None = None
    affected: bool = False
    vuln: bool = False
