"""Tests for knowledge base / playbook retrieval."""

from src.knowledge_base import get_playbook, search_playbooks, PLAYBOOKS


def test_get_playbook_valid_category():
    playbook = get_playbook("unauthorized_access")
    assert playbook["title"] == "Unauthorized Access Response"
    assert len(playbook["immediate"]) > 0
    assert len(playbook["long_term"]) > 0


def test_get_playbook_all_categories():
    for category in PLAYBOOKS:
        playbook = get_playbook(category)
        assert "title" in playbook
        assert "immediate" in playbook
        assert "investigation" in playbook
        assert "long_term" in playbook


def test_get_playbook_unknown_category_returns_default():
    playbook = get_playbook("unknown_category")
    assert playbook["title"] == "Anomalous Behavior Response"


def test_search_playbooks_returns_results():
    results = search_playbooks("credential revoke IAM")
    assert len(results) > 0
    assert results[0]["score"] > 0


def test_search_playbooks_ranks_relevant_first():
    results = search_playbooks("malware C2 domain")
    assert results[0]["category"] == "malware"


def test_search_playbooks_max_three_results():
    results = search_playbooks("security incident breach access")
    assert len(results) <= 3


def test_search_playbooks_empty_query():
    results = search_playbooks("")
    assert len(results) == 0
