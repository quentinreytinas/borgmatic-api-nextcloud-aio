"""Job log buffering utilities used for SSE and polling."""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, List


@dataclass(slots=True)
class BufferItem:
    id: int
    timestamp: float
    kind: str
    line: str


class StreamBuffer:
    """Thread-safe buffer keeping the last N log lines for a job."""

    def __init__(self, maxsize: int = 2000, ttl: int = 3600) -> None:
        self.items: Deque[BufferItem] = deque(maxlen=maxsize)
        self.lock = threading.Lock()
        self.next_id = 0
        self.last_push = time.time()
        self.ttl = ttl

    def push(self, kind: str, line: str) -> None:
        with self.lock:
            self.items.append(
                BufferItem(id=self.next_id, timestamp=time.time(), kind=kind, line=line)
            )
            self.next_id += 1
            self.last_push = time.time()

    def drain(self, cursor: int = 0, max_items: int = 200) -> List[dict]:
        with self.lock:
            out = [item for item in self.items if item.id >= cursor]
            return [
                {
                    "id": item.id,
                    "t": item.timestamp,
                    "kind": item.kind,
                    "line": item.line,
                }
                for item in out[:max_items]
            ]


class BufferStore:
    """Manage buffers for each job id with background garbage collection."""

    def __init__(self, maxsize: int = 2000, ttl: int = 3600) -> None:
        self._buffers: Dict[str, StreamBuffer] = {}
        self._lock = threading.Lock()
        self._maxsize = maxsize
        self._ttl = ttl
        self._start_gc()

    def _start_gc(self) -> None:
        thread = threading.Thread(target=self._gc_loop, daemon=True)
        thread.start()

    def _gc_loop(self) -> None:
        while True:
            time.sleep(60)
            now = time.time()
            with self._lock:
                stale = [
                    job_id
                    for job_id, buf in self._buffers.items()
                    if now - buf.last_push > buf.ttl
                ]
                for job_id in stale:
                    self._buffers.pop(job_id, None)

    def buffer_for(self, job_id: str) -> StreamBuffer:
        with self._lock:
            buffer = self._buffers.get(job_id)
            if buffer is None:
                buffer = StreamBuffer(maxsize=self._maxsize, ttl=self._ttl)
                self._buffers[job_id] = buffer
            return buffer

    def active_jobs(self) -> List[str]:
        with self._lock:
            return list(self._buffers.keys())

    def get(self, job_id: str) -> StreamBuffer | None:
        with self._lock:
            return self._buffers.get(job_id)
