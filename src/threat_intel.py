"""Local threat intelligence feed and IOC matching.

This simulates a threat intel source the way ``knowledge_base.py`` simulates
a playbook store: no external API key required, deterministic, and testable
offline. Swap ``KNOWN_INDICATORS`` for a real feed (VirusTotal, AbuseIPDB,
MISP, an internal TIP, etc.) in production without changing the agent code
that calls ``lookup_indicators``.
"""

from __future__ import annotations

import re

# --- Known-bad indicators (toy feed) ---
# In production this would be a query against a real threat intel platform.
KNOWN_INDICATORS: dict[str, dict] = {
    "185.220.101.34": {
        "type": "ip",
        "threat_type": "tor_exit_node",
        "confidence": 0.95,
        "description": "Known Tor exit node, frequently used to mask attacker origin.",
    },
    "45.155.205.0/24": {
        "type": "cidr",
        "threat_type": "bulletproof_hosting",
        "confidence": 0.85,
        "description": "Netblock associated with bulletproof hosting provider.",
    },
    "evil-c2.example.net": {
        "type": "domain",
        "threat_type": "c2_infrastructure",
        "confidence": 0.9,
        "description": "Domain observed in C2 beaconing for commodity malware.",
    },
}

# Free-text patterns that suggest a known technique even without an exact IOC match.
PATTERN_HINTS: list[tuple[re.Pattern, dict]] = [
    (
        re.compile(r"\btor exit node\b", re.IGNORECASE),
        {
            "threat_type": "anonymization_network",
            "confidence": 0.6,
            "description": "Activity attributed to Tor network in alert context.",
        },
    ),
    (
        re.compile(r"\b0\.0\.0\.0/0\b"),
        {
            "threat_type": "overly_permissive_exposure",
            "confidence": 0.5,
            "description": "Resource exposed to the entire internet.",
        },
    ),
    (
        re.compile(r"\bC2\b|\bcommand[- ]and[- ]control\b", re.IGNORECASE),
        {
            "threat_type": "c2_communication",
            "confidence": 0.7,
            "description": "Language suggesting command-and-control activity.",
        },
    ),
]


def _classify_indicator_type(indicator: str) -> str:
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", indicator):
        return "ip"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", indicator):
        return "cidr"
    if re.match(r"^[a-fA-F0-9]{32,64}$", indicator):
        return "hash"
    if "." in indicator and " " not in indicator:
        return "domain"
    return "text"


def lookup_indicators(indicators: list[str]) -> list[dict]:
    """Check a list of raw indicators against the local threat feed.

    Returns a list of match dicts (only for indicators that matched or
    contained a recognizable threat pattern) suitable for feeding to the
    threat intel agent's LLM summarization step.
    """
    results: list[dict] = []
    for indicator in indicators:
        cleaned = indicator.split(":", 1)[-1].strip() if ":" in indicator else indicator.strip()

        if cleaned in KNOWN_INDICATORS:
            info = KNOWN_INDICATORS[cleaned]
            results.append(
                {
                    "indicator": cleaned,
                    "indicator_type": info["type"],
                    "matched": True,
                    "threat_type": info["threat_type"],
                    "source": "local_feed",
                    "confidence": info["confidence"],
                    "description": info["description"],
                }
            )
            continue

        for pattern, info in PATTERN_HINTS:
            if pattern.search(indicator):
                results.append(
                    {
                        "indicator": indicator,
                        "indicator_type": _classify_indicator_type(cleaned),
                        "matched": True,
                        "threat_type": info["threat_type"],
                        "source": "pattern_heuristic",
                        "confidence": info["confidence"],
                        "description": info["description"],
                    }
                )
                break

    return results
