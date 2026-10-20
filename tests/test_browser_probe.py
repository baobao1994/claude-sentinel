from __future__ import annotations

from claude_sentinel.collectors.browser_probe import _build_probe, _parse_candidates


def test_parse_candidates():
    values = [
        "candidate:1 1 UDP 2122260223 192.0.2.10 54400 typ host",
        "candidate:2 1 UDP 2122260223 198.51.100.20 54401 typ srflx raddr 0.0.0.0 rport 0",
        "candidate:3 1 UDP 2122260223 0.0.0.0 54402 typ host",
    ]
    parsed = _parse_candidates(values)
    assert parsed[0].ip == "192.0.2.10"
    assert parsed[0].kind == "host"
    assert parsed[1].ip == "198.51.100.20"
    assert parsed[2].ip is None


def test_build_probe():
    probe = _build_probe(
        {
            "timezone": "Asia/Shanghai",
            "utc_offset_minutes": 480,
            "locale": "zh-CN",
            "languages": ["zh-CN", "zh"],
            "screen": "1440x900@2",
            "egress_ip": "203.0.113.9",
            "egress_country": "JP",
            "fonts": ["PingFang SC"],
            "webrtc": ["candidate:1 1 UDP 1 192.0.2.10 54400 typ host"],
        }
    )
    assert probe.timezone == "Asia/Shanghai"
    assert probe.egress_country == "JP"
    assert probe.fonts == ["PingFang SC"]
    assert probe.webrtc[0].ip == "192.0.2.10"
