import sqlite3
import pytest
import os
from app.core.db import init_db, log_scan

def test_init_db(tmp_path):
    db_file = tmp_path / "test_init.db"
    db_path = str(db_file)
    init_db(db_path)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
    table = cursor.fetchone()
    assert table is not None
    conn.close()

def test_log_scan(tmp_path):
    # Use a temporary file for the database to ensure connection scope doesn't cause issues
    # with :memory: between calls.
    db_file = tmp_path / "test.db"
    db_path = str(db_file)
    
    init_db(db_path)
    log_scan(db_path, "http://example.com", 25, "safe")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT url, risk_score, prediction FROM scans")
    rows = cursor.fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "http://example.com"
    assert rows[0][1] == 25
    assert rows[0][2] == "safe"
    conn.close()
