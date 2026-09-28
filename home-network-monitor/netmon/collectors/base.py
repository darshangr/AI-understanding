from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from ..service import Monitor

log = logging.getLogger(__name__)


class PollingCollector(threading.Thread):
    """Runs ``poll()`` every ``interval`` seconds until the monitor stops."""

    name_prefix = "collector"

    def __init__(self, monitor: "Monitor", cfg: dict[str, Any], interval: float) -> None:
        super().__init__(name=self.name_prefix, daemon=True)
        self.monitor = monitor
        self.cfg = cfg
        self.interval = max(5.0, float(interval))

    def poll(self) -> str:
        raise NotImplementedError

    def run(self) -> None:
        stop = self.monitor.stop_event
        while not stop.is_set():
            try:
                message = self.poll()
                self.monitor.set_status(self.name, True, message)
            except (httpx.HTTPError, OSError) as exc:
                log.warning("%s: %s: %s", self.name, type(exc).__name__, exc)
                self.monitor.set_status(self.name, False, f"{type(exc).__name__} (unreachable?)")
            except Exception as exc:  # a failing collector must not kill the others
                log.exception("%s poll failed", self.name)
                self.monitor.set_status(self.name, False, type(exc).__name__)
            stop.wait(self.interval)
