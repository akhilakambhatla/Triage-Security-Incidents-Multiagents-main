"""Tests for threat intel IOC matching."""

from src.threat_intel import lookup_indicators


def test_lookup_known_ip_matches():
    results = lookup_indicators(["IP: 185.220.101.34"])
    assert len(results) == 1
    assert results[0]["matched"] is True
    assert results[0]["threat_type"] == "tor_exit_node"
    assert results[0]["source"] == "local_feed"


def test_lookup_pattern_hint_matches():
    results = lookup_indicators(["activity routed through a Tor exit node"])
    assert len(results) == 1
    assert results[0]["source"] == "pattern_heuristic"


def test_lookup_no_match_returns_empty():
    results = lookup_indicators(["totally-benign-value", "1.1.1.1-not-in-feed"])
    assert results == []


def test_lookup_multiple_indicators_mixed():
    results = lookup_indicators(
        ["185.220.101.34", "benign-thing", "traffic to evil-c2.example.net"]
    )
    matched_indicators = {r["indicator"] for r in results}
    assert "185.220.101.34" in matched_indicators
    assert len(results) >= 1
