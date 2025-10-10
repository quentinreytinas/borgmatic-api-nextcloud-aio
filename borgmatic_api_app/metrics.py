"""Lightweight metrics collection for the API."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock
from time import time
from typing import Dict


@dataclass
class Metrics:
    """Collects counters for the API."""

    _counters: Dict[str, int] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)
    start_time: float = field(default_factory=time)

    def inc(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + value

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._counters)
