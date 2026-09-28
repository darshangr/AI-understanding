import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netmon.config import DEFAULTS, Config, _deep_merge  # noqa: E402
from netmon.service import Monitor  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def cfg(tmp_path):
    return Config(_deep_merge(DEFAULTS, {"data_dir": str(tmp_path), "feeds": {"sources": []},
                                         "lan": {"cidr": "192.168.1.0/24"},
                                         "anomaly": {"learning_period_hours": 0}}))


@pytest.fixture
def monitor(cfg):
    m = Monitor(cfg)
    m.store.set_meta("installed_at", "0")
    yield m
    m.store.close()
