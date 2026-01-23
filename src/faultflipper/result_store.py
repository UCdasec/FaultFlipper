from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pandas as pd

from cli_utils import BitFlipExperimentResult, NopExperimentResult


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

    def exit_code_histogram(
        self, unmutated_binary: Path
    ) -> list[tuple[int | None, int]]:
        """Return (return_code, count) aggregated for a binary."""
        conn = self._get_conn()
        cursor = conn.execute(
            f"""
            SELECT return_code, COUNT(*) AS total
            FROM {self.TABLE_NAME}
            WHERE unmutated_binary = ?
            GROUP BY return_code
            ORDER BY total DESC
            """,
            (self._normalize_path(unmutated_binary),),
        )
        return [(row["return_code"], row["total"]) for row in cursor]


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

    def _serialize_result(self, result: BitFlipExperimentResult) -> Mapping[str, Any]:
        result_dict = result.to_dict()
        result_dict["custom_returncodes"] = json.dumps(
            result_dict["custom_returncodes"]
        )
        return result_dict

    def load_completed_pairs(self, total_inputs: int) -> set[tuple[int, int]]:
        """Return (addr, bit) pairs that already have results for every input."""
        if total_inputs <= 0:
            return set()

        conn = self._get_conn()
        cursor = conn.execute(
            f"""
            SELECT flipped_addr, flipped_index
            FROM {self.TABLE_NAME}
            GROUP BY flipped_addr, flipped_index
            HAVING COUNT(*) >= ?
            """,
            (total_inputs,),
        )

        return {(row["flipped_addr"], row["flipped_index"]) for row in cursor}

    def summarize_bit_results(self, unmutated_binary: Path) -> list[dict[str, Any]]:
        """Aggregate per (addr, bit) stats for a given reference binary."""
        conn = self._get_conn()
        cursor = conn.execute(
            f"""
            SELECT
                flipped_addr,
                flipped_index,
                COUNT(*) AS total_runs,
                SUM(CASE WHEN return_code = -999 THEN 1 ELSE 0 END) AS total_failed,
                SUM(
                    CASE
                        WHEN expected_stdout IS NOT NULL
                             AND program_stdout LIKE '%' || expected_stdout || '%'
                        THEN 1 ELSE 0
                    END
                ) AS total_correct
            FROM {self.TABLE_NAME}
            WHERE unmutated_binary = ?
            GROUP BY flipped_addr, flipped_index
            ORDER BY flipped_addr, flipped_index
            """,
            (self._normalize_path(unmutated_binary),),
        )

        return [dict(row) for row in cursor]


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

    def _serialize_result(self, result: NopExperimentResult) -> Mapping[str, Any]:
        result_dict = result.to_dict()
        result_dict["custom_returncodes"] = json.dumps(
            result_dict["custom_returncodes"]
        )
        return result_dict

    def stdout_histogram(
        self, unmutated_binary: Path, addrs: Sequence[int]
    ) -> list[tuple[str, int]]:
        """Return (stdout, count) pairs for the given addresses."""
        if not addrs:
            return []

        placeholders = ",".join(["?"] * len(addrs))
        sql = f"""
            SELECT program_stdout, COUNT(*) AS total
            FROM {self.TABLE_NAME}
            WHERE unmutated_binary = ? AND nopped_addr IN ({placeholders})
            GROUP BY program_stdout
            ORDER BY total DESC
        """
        params = [self._normalize_path(unmutated_binary), *addrs]
        conn = self._get_conn()
        cursor = conn.execute(sql, params)
        return [(row["program_stdout"], row["total"]) for row in cursor]

    def load_completed_addrs(self, total_inputs: int) -> set[int]:
        """Return nopped addresses that already have results for every input."""
        if total_inputs <= 0:
            return set()

        conn = self._get_conn()
        cursor = conn.execute(
            f"""
            SELECT nopped_addr
            FROM {self.TABLE_NAME}
            GROUP BY nopped_addr
            HAVING COUNT(*) >= ?
            """,
            (total_inputs,),
        )

        return {row["nopped_addr"] for row in cursor}

    def summarize_nop_results(self, unmutated_binary: Path) -> list[dict[str, Any]]:
        """Aggregate per-address stats for a given reference binary."""
        conn = self._get_conn()
        cursor = conn.execute(
            f"""
            SELECT
                nopped_addr,
                COUNT(*) AS total_runs,
                SUM(CASE WHEN return_code = -999 THEN 1 ELSE 0 END) AS total_failed,
                SUM(
                    CASE
                        WHEN expected_stdout IS NOT NULL
                             AND program_stdout LIKE '%' || expected_stdout || '%'
                        THEN 1 ELSE 0
                    END
                ) AS total_correct
            FROM {self.TABLE_NAME}
            WHERE unmutated_binary = ?
            GROUP BY nopped_addr
            ORDER BY nopped_addr
            """,
            (self._normalize_path(unmutated_binary),),
        )

        return [dict(row) for row in cursor]
