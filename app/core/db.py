import sqlite3
import json

def init_db(db_path: str = "trustguard.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            prediction TEXT NOT NULL,
            ml_score REAL,
            ml_prediction TEXT,
            blacklisted BOOLEAN DEFAULT 0,
            reasons TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS model_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            trained_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            metrics TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            is_phishing BOOLEAN NOT NULL,
            comments TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def log_scan(db_path: str, url: str, risk_score: int, prediction: str, ml_score: float = None, ml_prediction: str = None, blacklisted: bool = False, reasons: list = None):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    reasons_str = json.dumps(reasons) if reasons else "[]"
    cursor.execute('''
        INSERT INTO scans (url, risk_score, prediction, ml_score, ml_prediction, blacklisted, reasons)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (url, risk_score, prediction, ml_score, ml_prediction, blacklisted, reasons_str))
    conn.commit()
    conn.close()

def log_model_version(db_path: str, name: str, version: str, metrics: dict):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO model_versions (name, version, metrics)
        VALUES (?, ?, ?)
    ''', (name, version, json.dumps(metrics)))
    conn.commit()
    conn.close()

def get_history(db_path: str = "trustguard.db", limit: int = 50):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, url, risk_score, prediction, ml_score, ml_prediction, blacklisted, timestamp
        FROM scans
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def log_report(db_path: str, url: str, is_phishing: bool, comments: str = None):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO reports (url, is_phishing, comments)
        VALUES (?, ?, ?)
    ''', (url, is_phishing, comments))
    conn.commit()
    conn.close()

def get_url_history(db_path: str, url: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, risk_score, prediction, timestamp 
        FROM scans 
        WHERE url = ? 
        ORDER BY timestamp DESC
    ''', (url,))
    scans = [dict(row) for row in cursor.fetchall()]
    
    cursor.execute('''
        SELECT id, is_phishing, comments, timestamp 
        FROM reports 
        WHERE url = ? 
        ORDER BY timestamp DESC
    ''', (url,))
    reports = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return {"scans": scans, "reports": reports}
