#!/usr/bin/env python3
"""Seed benign.db with ordinary application data (no injected content)."""
import argparse, sqlite3
ap = argparse.ArgumentParser(); ap.add_argument("--db-path", default="benign.db")
a = ap.parse_args()
c = sqlite3.connect(a.db_path)
c.executescript("""
DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS messages;
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT);
CREATE TABLE messages (id INTEGER PRIMARY KEY, author TEXT, body TEXT, created_at TEXT);
""")
c.executemany("INSERT INTO users (username,email,role) VALUES (?,?,?)",
              [("alice","alice@example.com","admin"),("bob","bob@example.com","member")])
c.executemany("INSERT INTO messages (author,body,created_at) VALUES (?,?,?)",
              [("alice","Welcome to the project.","2026-10-20T09:00:00Z"),
               ("bob","Pushed the parser draft.","2026-10-20T11:30:00Z")])
c.commit(); c.close()
print(f"seeded {a.db_path}")
