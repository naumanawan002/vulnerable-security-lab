import sqlite3
import os

DB_PATH = ":memory:"

def get_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        role TEXT
    )
    """)
    cursor.executemany("""
    INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)
    """, [
        ("alice", "AlicePass2026!", "alice@corp.internal", "admin"),
        ("bob", "BobSecret987", "bob@corp.internal", "user"),
        ("charlie", "CharliePass123", "charlie@corp.internal", "user"),
    ])

    # Invoices table (for IDOR demonstration)
    cursor.execute("""
    CREATE TABLE invoices (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        amount REAL,
        description TEXT
    )
    """)
    cursor.executemany("""
    INSERT INTO invoices (id, user_id, amount, description) VALUES (?, ?, ?, ?)
    """, [
        (101, 1, 15000.0, "Confidential Executive Bonus"),
        (102, 2, 250.0, "Office Supplies Requisition"),
        (103, 3, 120.0, "Travel Expenses"),
    ])

    conn.commit()
    return conn
