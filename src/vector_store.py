"""Vector-store backed retrieval over the security playbook knowledge base.

This replaces ``knowledge_base.search_playbooks``'s keyword-overlap scoring
with real semantic retrieval: each playbook is chunked (one chunk per
immediate/investigation/long-term action, tagged with its category and
section) and embedded with Vertex AI's text-embedding model. Queries are
embedded the same way and matched by cosine similarity via LangChain's
``InMemoryVectorStore``.

The store is built lazily and cached at module scope, since embedding calls
require a network round trip and shouldn't happen at import time (or more
than once per process). If embeddings can't be produced -- no GCP
credentials configured, no network, etc. -- retrieval falls back to the
original keyword search from ``knowledge_base.py`` so the pipeline degrades
gracefully instead of hard failing. This mirrors how ``get_llm`` already
authenticates via ADC rather than an API key.
"""

from __future__ import annotations

import logging

from langchain_core.documents import Document
from langchain_core.vectorstores import InMemoryVectorStore

from .knowledge_base import PLAYBOOKS, search_playbooks

logger = logging.getLogger(__name__)

_VECTOR_STORE: InMemoryVectorStore | None = None
_BUILD_FAILED = False

EMBEDDING_MODEL = "text-embedding-005"


def _build_documents() -> list[Document]:
    """Chunk every playbook section into its own retrievable Document."""
    docs: list[Document] = []
    for category, playbook in PLAYBOOKS.items():
        for section in ("immediate", "investigation", "long_term"):
            for i, step in enumerate(playbook.get(section, [])):
                docs.append(
                    Document(
                        page_content=f"{playbook['title']} — {section}: {step}",
                        metadata={
                            "category": category,
                            "section": section,
                            "title": playbook["title"],
                            "step": step,
                            "index": i,
                        },
                    )
                )
    return docs


def _get_vector_store() -> InMemoryVectorStore | None:
    """Lazily build (and cache) the embedded vector store. Returns None on failure."""
    global _VECTOR_STORE, _BUILD_FAILED

    if _VECTOR_STORE is not None:
        return _VECTOR_STORE
    if _BUILD_FAILED:
        return None

    try:
        # Imported lazily so importing this module never requires
        # google-cloud credentials to be configured (e.g. during tests).
        from langchain_google_vertexai import VertexAIEmbeddings

        embeddings = VertexAIEmbeddings(model_name=EMBEDDING_MODEL)
        store = InMemoryVectorStore(embeddings)
        store.add_documents(_build_documents())
        _VECTOR_STORE = store
        return _VECTOR_STORE
    except Exception as exc:  # noqa: BLE001 - deliberately broad, see module docstring
        logger.warning(
            "Vertex AI embeddings unavailable (%s); falling back to keyword search "
            "for playbook retrieval. Run `gcloud auth application-default login` "
            "and set GOOGLE_CLOUD_PROJECT to enable semantic RAG.",
            exc,
        )
        _BUILD_FAILED = True
        return None


def reset_vector_store() -> None:
    """Clear the cached store (used by tests, or after PLAYBOOKS changes)."""
    global _VECTOR_STORE, _BUILD_FAILED
    _VECTOR_STORE = None
    _BUILD_FAILED = False


def retrieve_semantic_context(query: str, k: int = 4) -> list[Document]:
    """Retrieve the k most relevant playbook chunks for a free-text query.

    Falls back to the keyword-based ``search_playbooks`` (converted into
    Document form) if the embedding-backed vector store can't be built.
    """
    if not query.strip():
        return []

    store = _get_vector_store()
    if store is not None:
        return store.similarity_search(query, k=k)

    # Fallback path: reuse the original keyword search, flattened to
    # section-level "documents" so callers see a consistent return type.
    fallback_docs: list[Document] = []
    for result in search_playbooks(query):
        playbook = result["playbook"]
        for section in ("immediate", "long_term"):
            for step in playbook.get(section, [])[:2]:
                fallback_docs.append(
                    Document(
                        page_content=f"{playbook['title']} — {section}: {step}",
                        metadata={"category": result["category"], "section": section},
                    )
                )
    return fallback_docs[:k]
