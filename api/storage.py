from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from detector.models import AnalysisResult


DB_PATH = Path(__file__).resolve().parent.parent / "phishing_history.db"


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = _get_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                created_at TEXT NOT NULL,
                details_json TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def save_analysis(result: AnalysisResult) -> int:
    conn = _get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO analyses (url, risk_score, risk_level, created_at, details_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(result.url),
                int(result.risk_score),
                result.risk_level.value,
                result.created_at.isoformat(),
                result.model_dump_json()
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)
    finally:
        conn.close()


def list_analyses(limit: int = 20, offset: int = 0) -> List[Dict[str, Any]]:
    conn = _get_connection()
    try:
        cursor = conn.execute(
            """
            SELECT id, url, risk_score, risk_level, created_at
            FROM analyses
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_analysis(analysis_id: int) -> Optional[AnalysisResult]:
    conn = _get_connection()
    try:
        cursor = conn.execute(
            """
            SELECT details_json
            FROM analyses
            WHERE id = ?
            """,
            (analysis_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        data = json.loads(row["details_json"])
        # created_at foi serializado como ISO string; Pydantic converte de volta
        return AnalysisResult(**data)
    finally:
        conn.close()

