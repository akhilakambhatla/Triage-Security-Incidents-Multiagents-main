"""Tests for the playbook vector store / RAG retrieval.

These tests never call the real Vertex AI embeddings API: either they
exercise pure document-chunking logic, or they force the fallback path by
making ``_get_vector_store`` fail, matching the "no GCP auth needed" promise
the rest of the test suite makes.
"""

from src import vector_store
from src.knowledge_base import PLAYBOOKS


def setup_function():
    vector_store.reset_vector_store()


def test_build_documents_covers_every_playbook_step():
    docs = vector_store._build_documents()
    expected_count = sum(
        len(p["immediate"]) + len(p["investigation"]) + len(p["long_term"])
        for p in PLAYBOOKS.values()
    )
    assert len(docs) == expected_count


def test_build_documents_have_category_metadata():
    docs = vector_store._build_documents()
    categories = {d.metadata["category"] for d in docs}
    assert categories == set(PLAYBOOKS.keys())


def test_retrieve_semantic_context_empty_query_returns_empty():
    assert vector_store.retrieve_semantic_context("") == []


def test_retrieve_semantic_context_falls_back_without_credentials(monkeypatch):
    # Force the embedding-backed store to fail to build, simulating no
    # GCP credentials being configured in this environment.
    monkeypatch.setattr(vector_store, "_get_vector_store", lambda: None)

    docs = vector_store.retrieve_semantic_context("credential revoke IAM", k=3)

    assert len(docs) <= 3
    for d in docs:
        assert "category" in d.metadata


def test_get_vector_store_caches_failure(monkeypatch):
    calls = {"count": 0}

    def boom(*args, **kwargs):
        calls["count"] += 1
        raise RuntimeError("no credentials")

    monkeypatch.setattr(
        "src.vector_store.VertexAIEmbeddings", boom, raising=False
    )
    # Simulate the import failing inside _get_vector_store by patching the
    # lazy import target directly.
    import sys
    import types

    fake_module = types.ModuleType("langchain_google_vertexai")
    fake_module.VertexAIEmbeddings = boom
    monkeypatch.setitem(sys.modules, "langchain_google_vertexai", fake_module)

    result1 = vector_store._get_vector_store()
    result2 = vector_store._get_vector_store()

    assert result1 is None
    assert result2 is None
    # Second call should hit the cached failure, not retry the import.
    assert calls["count"] == 1
