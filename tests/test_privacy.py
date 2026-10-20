from __future__ import annotations

import json
from pathlib import Path

from claude_sentinel.cli import _public_dict
from claude_sentinel.config import Settings
from claude_sentinel.models import (
    BrowserProbe,
    IpConsensus,
    IpIntel,
    Observation,
    RdapInfo,
    Source,
    Status,
)
from tests.conftest import make_report


def _report_with_ips():
    return make_report(
        observations={
            "net.edge": Observation(
                key="net.edge",
                label="edge",
                value={"ip": "203.0.113.9"},
                detail="203.0.113.9 · US",
                status=Status.ok,
                source=Source(name="edge", kind="edge"),
            )
        },
        ip=IpConsensus(
            ip="203.0.113.9",
            country_code="US",
            intel=[
                IpIntel(
                    provider="ip-api",
                    ip="203.0.113.9",
                    raw={"query": "203.0.113.9"},
                )
            ],
        ),
        browser=BrowserProbe(egress_ip="203.0.113.9", timezone="Asia/Shanghai"),
        rdap=RdapInfo(
            ip="203.0.113.9",
            ok=True,
            source_url="https://rdap.example/ip/203.0.113.9",
        ),
    )


def test_public_dict_redacts_ips_and_raw(tmp_path: Path):
    report = _report_with_ips()
    data = _public_dict(report, Settings(home=tmp_path, show_ip=False))
    text = json.dumps(data, ensure_ascii=False)
    assert "203.0.113.9" not in text
    assert "203.0.*.*" in text
    assert '"raw"' not in text
    assert "https://rdap.example/ip/203.0.*.*" in text


def test_public_dict_can_show_ip(tmp_path: Path):
    report = _report_with_ips()
    data = _public_dict(report, Settings(home=tmp_path, show_ip=True))
    text = json.dumps(data, ensure_ascii=False)
    assert "203.0.113.9" in text
