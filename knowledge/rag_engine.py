"""
RAG Engine — Semantische Suche via ChromaDB + sentence-transformers
====================================================================
Optionale Komponente. Funktioniert auch OHNE Installation:
→ Automatischer Fallback auf Textsuche in knowledge_base.py

Aktivieren:
    pip install chromadb sentence-transformers

Externe RAG-Anbindung (eigenes System):
    Setze in .env:
        EXTERNAL_RAG_URL=http://localhost:11434/api/embeddings  (z.B. Ollama)
        EXTERNAL_RAG_MODEL=nomic-embed-text
    → Dann werden externe Embeddings statt sentence-transformers genutzt.
"""

import os
import json
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from knowledge.knowledge_base import KnowledgeBase, KnowledgeEntry

KB_DIR = Path(__file__).parent.parent / "knowledge_db"


class RAGEngine:
    """
    Semantische Suche für die Knowledge Base.

    Unterstützt:
    1. sentence-transformers (lokal, kein API-Key nötig) — Standard
    2. Ollama Embeddings (lokal, via EXTERNAL_RAG_URL in .env)
    3. OpenAI Embeddings (via OPENAI_API_KEY in .env)
    4. Fallback: ChromaDB ohne Embeddings (keyword-basiert)
    """

    def __init__(self, kb: "KnowledgeBase"):
        self.kb = kb
        self._collection = None
        self._embed_fn = None
        self._init()

    def _init(self):
        """Initialisiert ChromaDB und wählt Embedding-Strategie."""
        try:
            import chromadb
            from chromadb.config import Settings
            client = chromadb.PersistentClient(
                path=str(KB_DIR / "chroma"),
                settings=Settings(anonymized_telemetry=False)
            )
            self._collection = client.get_or_create_collection(
                name="redteam_knowledge",
                metadata={"hnsw:space": "cosine"}
            )
        except ImportError:
            self._collection = None
            return

        # Embedding-Strategie auswählen
        external_url = os.getenv("EXTERNAL_RAG_URL")
        if external_url:
            self._embed_fn = self._embed_external
        elif os.getenv("OPENAI_API_KEY"):
            self._embed_fn = self._embed_openai
        else:
            self._embed_fn = self._embed_local

    def _embed_local(self, text: str) -> Optional[List[float]]:
        """sentence-transformers (lokal, kein API-Key nötig)."""
        try:
            from sentence_transformers import SentenceTransformer
            if not hasattr(self, "_st_model"):
                self._st_model = SentenceTransformer("all-MiniLM-L6-v2")
            return self._st_model.encode(text).tolist()
        except ImportError:
            return None

    def _embed_external(self, text: str) -> Optional[List[float]]:
        """Externes Embedding-System (z.B. Ollama)."""
        try:
            import httpx
            url = os.getenv("EXTERNAL_RAG_URL")
            model = os.getenv("EXTERNAL_RAG_MODEL", "nomic-embed-text")
            resp = httpx.post(url, json={"model": model, "prompt": text}, timeout=10)
            return resp.json().get("embedding")
        except Exception:
            return self._embed_local(text)  # Fallback

    def _embed_openai(self, text: str) -> Optional[List[float]]:
        """OpenAI Embeddings (erfordert OPENAI_API_KEY in .env)."""
        try:
            import httpx
            resp = httpx.post(
                "https://api.openai.com/v1/embeddings",
                headers={"Authorization": f"Bearer {os.getenv('OPENAI_API_KEY')}"},
                json={"input": text, "model": "text-embedding-3-small"},
                timeout=15
            )
            return resp.json()["data"][0]["embedding"]
        except Exception:
            return self._embed_local(text)  # Fallback

    def _embed(self, text: str) -> Optional[List[float]]:
        if not self._embed_fn:
            return None
        return self._embed_fn(text)

    def index_entry(self, entry: "KnowledgeEntry"):
        """Fügt einen KB-Eintrag in den Vektorindex ein."""
        if not self._collection:
            return
        text = f"{entry.title} {entry.subcategory} {entry.content[:500]} {' '.join(entry.tags)}"
        embedding = self._embed(text)
        try:
            if embedding:
                self._collection.upsert(
                    ids=[entry.id],
                    embeddings=[embedding],
                    documents=[text],
                    metadatas=[{
                        "category": entry.category,
                        "subcategory": entry.subcategory,
                        "severity": entry.severity,
                    }]
                )
            else:
                # ChromaDB ohne Embeddings (keyword-only)
                self._collection.upsert(
                    ids=[entry.id],
                    documents=[text],
                    metadatas=[{
                        "category": entry.category,
                        "subcategory": entry.subcategory,
                        "severity": entry.severity,
                    }]
                )
        except Exception:
            pass

    def query(self, query_text: str, limit: int = 5) -> List["KnowledgeEntry"]:
        """Semantische Suche — gibt relevante KnowledgeEntries zurück."""
        if not self._collection:
            return self.kb.text_search(query_text, limit)

        try:
            import sqlite3
            n = min(limit, max(self._collection.count(), 1))
            embedding = self._embed(query_text)

            if embedding:
                results = self._collection.query(
                    query_embeddings=[embedding],
                    n_results=n
                )
            else:
                results = self._collection.query(
                    query_texts=[query_text],
                    n_results=n
                )

            ids = results.get("ids", [[]])[0]
            entries = []
            for entry_id in ids:
                with sqlite3.connect(self.kb.db_path) as conn:
                    row = conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
                    if row:
                        entries.append(self.kb._row_to_entry(row))
            return entries

        except Exception:
            return self.kb.text_search(query_text, limit)

    def rebuild_index(self) -> int:
        """Baut den gesamten Vektorindex aus der SQLite-DB neu auf."""
        if not self._collection:
            return 0
        import sqlite3
        with sqlite3.connect(self.kb.db_path) as conn:
            rows = conn.execute("SELECT * FROM entries").fetchall()
        count = 0
        for row in rows:
            entry = self.kb._row_to_entry(row)
            self.index_entry(entry)
            count += 1
        return count
