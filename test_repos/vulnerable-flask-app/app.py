"""
Deliberately vulnerable Flask application for ShieldClaw integration testing.

This code is unsafe by design: never deploy it outside an isolated lab.
"""

import os

import psycopg2
from flask import Flask, Response, jsonify, request
from psycopg2.extras import RealDictCursor

app = Flask(__name__)


def _connect() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.environ["POSTGRES_HOST"],
        dbname=os.environ["POSTGRES_DB"],
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        port=os.environ.get("POSTGRES_PORT", "5432"),
    )


@app.get("/user")
def user() -> Response:
    conn = _connect()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        # Intentionally unsafe string interpolation to demonstrate SQL injection.
        query = f"SELECT * FROM users WHERE id = {request.args['id']}"
        cur.execute(query)
        rows = cur.fetchall()
        return jsonify([dict(row) for row in rows])
    finally:
        conn.close()
