from __future__ import annotations
import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "cloudsentinel.db"

def connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS scans (scan_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, risk_score INTEGER NOT NULL, risk_level TEXT NOT NULL, summary TEXT NOT NULL, findings TEXT NOT NULL, statement_count INTEGER NOT NULL, rules_triggered TEXT NOT NULL, policy_name TEXT)""")
    return conn

def save_scan(report: dict, scan_id: str, timestamp: str, policy_name: str | None = None) -> dict:
    with connection() as conn:
        conn.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (scan_id, timestamp, report["risk_score"], report["risk_level"], json.dumps(report["summary"]), json.dumps(report["findings"]), report["analysed_statement_count"], json.dumps(report["rules_triggered"]), policy_name))
    return get_scan(scan_id)

def _decode(row):
    if not row: return None
    value = dict(row)
    for key in ("summary", "findings", "rules_triggered"): value[key] = json.loads(value[key])
    return value

def get_scan(scan_id: str):
    with connection() as conn: return _decode(conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone())

def list_scans():
    with connection() as conn: return [_decode(row) for row in conn.execute("SELECT * FROM scans ORDER BY timestamp DESC").fetchall()]

def delete_scan(scan_id: str):
    with connection() as conn: return conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,)).rowcount > 0

def clear_scans():
    with connection() as conn: conn.execute("DELETE FROM scans")
