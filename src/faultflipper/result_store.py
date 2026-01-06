from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pandas as pd

from faultflipper.cli_utils import BitFlipExperimentResult, NopExperimentResult


class _BaseResultStore:
    """
    Shared logic for persisting experiment results in SQLite. Subclasses only
    need to define the table schema and serialization logic.
    """

    TABLE_NAME = ""
    CREATE_TABLE_SQL = ""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        conn.execute(self.CREATE_TABLE_SQL.format(table=self.TABLE_NAME))
        conn.commit()
        conn.close()

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect()
            self._local.conn = conn
        return conn

    def _normalize_path(self, value: Path | str) -> str:
        return str(Path(value).resolve())

    def upsert_result(self, result) -> None:
        payload = self._serialize_result(result)
        columns = ", ".join(payload.keys())
        placeholders = ", ".join(["?"] * len(payload))
        sql = f"""
            INSERT OR IGNORE INTO {self.TABLE_NAME} ({columns})
            VALUES ({placeholders})
        """
        conn = self._get_conn()
        conn.execute(sql, tuple(payload.values()))
        conn.commit()

    def result_exists(self, binary_path: Path, program_input: Path) -> bool:
        conn = self._get_conn()
        cursor = conn.execute(
            f"""
            SELECT 1 FROM {self.TABLE_NAME}
            WHERE binary_path = ? AND program_input = ?
            LIMIT 1
            """,
            (
                self._normalize_path(binary_path),
                self._normalize_path(program_input),
            ),
        )
        return cursor.fetchone() is not None

    def load_dataframe(self) -> pd.DataFrame:
        conn = self._get_conn()
        df = pd.read_sql_query(
            f"SELECT * FROM {self.TABLE_NAME} ORDER BY id ASC",
            conn,
        )
        return df

    def _serialize_result(self, result) -> Mapping[str, Any]:
        raise NotImplementedError


class BitFlipResultStore(_BaseResultStore):
    """
    Thread-safe SQLite-backed store for bit flip experiment results.
    Each thread keeps its own SQLite connection so the ThreadPoolExecutor
    workers can insert concurrently without clobbering each other.
    """

    TABLE_NAME = "bit_flip_results"
    CREATE_TABLE_SQL = """
        CREATE TABLE IF NOT EXISTS {table} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_file TEXT,
            unmutated_binary TEXT,
            binary_path TEXT NOT NULL,
            return_code INTEGER,
            program_input TEXT NOT NULL,
            program_stdout TEXT,
            target TEXT,
            expected_stdout TEXT,
            expected_returncode INTEGER,
            custom_returncodes TEXT,
            flipped_addr INTEGER,
            flipped_index INTEGER,
            mutation TEXT,
            source_code TEXT,
            UNIQUE(binary_path, program_input)
        )
    """

    def _serialize_result(
        self, result: BitFlipExperimentResult
    ) -> Mapping[str, Any]:
        result_dict = result.to_dict()
        result_dict["custom_returncodes"] = json.dumps(
            result_dict["custom_returncodes"]
        )
        return result_dict


class NopResultStore(_BaseResultStore):
    """
    SQLite-backed store for nop experiment results.
    """

    TABLE_NAME = "nop_results"
    CREATE_TABLE_SQL = """
        CREATE TABLE IF NOT EXISTS {table} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_file TEXT,
            unmutated_binary TEXT,
            binary_path TEXT NOT NULL,
            return_code INTEGER,
            program_input TEXT NOT NULL,
            program_stdout TEXT,
            target TEXT,
            expected_stdout TEXT,
            expected_returncode INTEGER,
            custom_returncodes TEXT,
            nopped_addr INTEGER,
            mutation TEXT,
            source_code TEXT,
            UNIQUE(binary_path, program_input)
        )
    """

    def _serialize_result(
        self, result: NopExperimentResult
    ) -> Mapping[str, Any]:
        result_dict = result.to_dict()
        result_dict["custom_returncodes"] = json.dumps(
            result_dict["custom_returncodes"]
        )
        return result_dict
