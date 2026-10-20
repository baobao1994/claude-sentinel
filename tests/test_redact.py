from __future__ import annotations

from claude_sentinel.redact import mask_ip, redact_ips_in_obj, redact_text


def test_mask_ip():
    assert mask_ip("203.0.113.127") == "203.0.*.*"
    assert mask_ip("2001:db8::13") == "2001:db8:…"
    assert mask_ip(None) is None


def test_redact_text_keeps_time():
    text = "ip 203.0.113.127 v6 2001:db8::13 time 13:30:16"
    redacted = redact_text(text)
    assert "203.0.113.127" not in redacted
    assert "2001:db8::13" not in redacted
    assert "13:30:16" in redacted


def test_redact_object_drops_raw_and_masks_details():
    payload = {
        "environment": {"ip": "203.0.113.127", "ip_masked": "203.0.*.*"},
        "detail": "203.0.113.127 · CN",
        "raw": {"query": "203.0.113.127"},
        "ipv6": "2001:db8::13",
    }
    redacted = redact_ips_in_obj(payload)
    assert redacted["environment"]["ip"] == "203.0.*.*"
    assert redacted["ipv6"] == "2001:db8:…"
    assert "203.0.113.127" not in str(redacted)
    assert "raw" not in redacted
