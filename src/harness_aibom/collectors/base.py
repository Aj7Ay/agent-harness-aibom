"""Collector base class shared by every runtime-specific collector."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from ..model import HarnessDocument


class Collector(ABC):
    """One collector = one runtime kind (hermes, openclaw, ...).

    A collector never raises just because the runtime isn't installed --
    it records that via `doc.warn()` and adds nothing. It should only raise
    for genuine programmer errors (e.g. a broken test fixture), not for
    "this piece is missing on this machine".
    """

    runtime_kind: str

    def __init__(self, home: Path | None = None):
        self.home = home or Path.home()

    @abstractmethod
    def is_present(self) -> bool:
        """Cheap, side-effect-free check: does this runtime look installed
        under self.home? Used by `scan --runtime auto`."""

    @abstractmethod
    def collect(self, doc: HarnessDocument) -> None:
        """Populate doc with every component/relationship this collector
        can find. Must not raise for missing-but-optional pieces."""
