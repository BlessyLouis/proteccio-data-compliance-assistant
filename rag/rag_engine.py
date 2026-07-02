"""
rag_engine.py
-------------
Retrieval-Augmented Generation pipeline for the Document Chat feature.

Pipeline:
1. Chunking      -> split document text into overlapping chunks
2. Embeddings    -> embed chunks using Google's text-embedding model
3. FAISS index   -> store embeddings for fast similarity search
4. Retrieval     -> fetch top-k relevant chunks for a user question
5. Generation    -> services.gemini_service produces the final answer

Falls back to a simple TF-IDF-like keyword retrieval if embeddings are
unavailable (e.g. no API key configured), so Document Chat still works
in a degraded mode rather than crashing.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

import numpy as np

from services import gemini_service
from utils.logger import get_logger

logger = get_logger(__name__)

try:
    import faiss
    _FAISS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _FAISS_AVAILABLE = False

try:
    import google.generativeai as genai
except ImportError:  # pragma: no cover
    genai = None

CHUNK_SIZE = 800
CHUNK_OVERLAP = 150
TOP_K = 4
EMBEDDING_MODEL = "models/text-embedding-004"


@dataclass
class RagIndex:
    chunks: list
    embeddings: "np.ndarray | None"
    faiss_index: "object | None"
    mode: str  # "embedding" | "keyword"


def chunk_text(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """Split text into overlapping chunks on whitespace boundaries."""
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return []

    chunks = []
    start = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        chunks.append(text[start:end])
        if end == len(text):
            break
        start = end - overlap
    return chunks


def _embed_texts(texts: list[str]) -> "np.ndarray | None":
    """Embed a list of texts using Gemini's embedding model. Returns None on failure."""
    if not gemini_service.is_configured() or genai is None:
        return None
    try:
        vectors = []
        for t in texts:
            result = genai.embed_content(model=EMBEDDING_MODEL, content=t, task_type="retrieval_document")
            vectors.append(result["embedding"])
        return np.array(vectors, dtype="float32")
    except Exception as exc:
        logger.warning(f"Embedding generation failed, falling back to keyword search: {exc}")
        return None


def build_index(document_text: str) -> RagIndex:
    """Chunk the document and build a FAISS index (or keyword fallback)."""
    chunks = chunk_text(document_text)
    if not chunks:
        return RagIndex(chunks=[], embeddings=None, faiss_index=None, mode="keyword")

    embeddings = _embed_texts(chunks)

    if embeddings is not None and _FAISS_AVAILABLE:
        dim = embeddings.shape[1]
        index = faiss.IndexFlatL2(dim)
        index.add(embeddings)
        logger.info(f"Built FAISS index with {len(chunks)} chunks (dim={dim}).")
        return RagIndex(chunks=chunks, embeddings=embeddings, faiss_index=index, mode="embedding")

    logger.info("Using keyword-based fallback retrieval (no embeddings/FAISS available).")
    return RagIndex(chunks=chunks, embeddings=None, faiss_index=None, mode="keyword")


def _keyword_retrieve_scored(query: str, chunks: list[str], top_k: int = TOP_K) -> list[tuple[str, float]]:
    """Overlap-based scoring fallback. Returns (chunk, confidence 0-1) pairs."""
    query_terms = set(re.findall(r"\w+", query.lower()))
    scored = []
    for chunk in chunks:
        chunk_terms = set(re.findall(r"\w+", chunk.lower()))
        overlap = len(query_terms & chunk_terms)
        confidence = overlap / max(1, len(query_terms))
        scored.append((chunk, min(1.0, confidence)))
    scored.sort(key=lambda x: x[1], reverse=True)
    top = [pair for pair in scored[:top_k] if pair[1] > 0]
    return top or [(c, 0.15) for c in chunks[:top_k]]


def _keyword_retrieve(query: str, chunks: list[str], top_k: int = TOP_K) -> list[str]:
    """Simple overlap-based scoring fallback when embeddings aren't available."""
    return [c for c, _ in _keyword_retrieve_scored(query, chunks, top_k)]


def retrieve_scored(index: RagIndex, query: str, top_k: int = TOP_K) -> list[tuple[str, float]]:
    """Retrieve top-k chunks with a 0-1 confidence score per chunk."""
    if not index.chunks:
        return []

    if index.mode == "embedding" and index.faiss_index is not None:
        try:
            query_vec = _embed_texts([query])
            if query_vec is None:
                return _keyword_retrieve_scored(query, index.chunks, top_k)
            k = min(top_k, len(index.chunks))
            distances, indices = index.faiss_index.search(query_vec, k)
            results = []
            for dist, idx in zip(distances[0], indices[0]):
                if idx >= len(index.chunks):
                    continue
                # Convert L2 distance to a 0-1 confidence heuristic.
                confidence = 1.0 / (1.0 + float(dist))
                results.append((index.chunks[idx], min(1.0, confidence)))
            return results
        except Exception as exc:
            logger.warning(f"FAISS retrieval failed, using keyword fallback: {exc}")
            return _keyword_retrieve_scored(query, index.chunks, top_k)

    return _keyword_retrieve_scored(query, index.chunks, top_k)


def retrieve(index: RagIndex, query: str, top_k: int = TOP_K) -> list[str]:
    """Retrieve the top-k most relevant chunks for a query (no scores)."""
    return [c for c, _ in retrieve_scored(index, query, top_k)]


def answer_question(index: RagIndex, question: str, chat_history: list | None = None) -> dict:
    """
    Full RAG pipeline: retrieve relevant chunks, generate an answer, and
    return a rich result for the chat UI.

    Returns:
        {
            "answer": str,
            "sources": [{"preview": str, "confidence": float}, ...],
            "confidence": float,           # overall (max of source confidences)
            "reasoning": str,               # one-line summary of retrieval strategy
            "mode": "embedding" | "keyword",
        }
    """
    scored_chunks = retrieve_scored(index, question)
    retrieved_texts = [c for c, _ in scored_chunks]
    answer = gemini_service.generate_chat_response(question, retrieved_texts, chat_history)

    overall_confidence = max((s for _, s in scored_chunks), default=0.0)
    sources = [
        {"preview": (c[:220] + "…") if len(c) > 220 else c, "confidence": round(s, 2)}
        for c, s in scored_chunks
    ]

    if index.mode == "embedding":
        reasoning = f"Retrieved {len(scored_chunks)} chunk(s) via semantic (FAISS) similarity search."
    else:
        reasoning = f"Retrieved {len(scored_chunks)} chunk(s) via keyword overlap (fallback mode — no embeddings configured)."

    return {
        "answer": answer,
        "sources": sources,
        "confidence": round(overall_confidence, 2),
        "reasoning": reasoning,
        "mode": index.mode,
    }
