import json
import pdb
import sqlite3
import bleach
from datetime import datetime
from typing import Optional

from urllib.parse import urlparse

from fastapi import FastAPI, Request, Response
from fastapi.responses import PlainTextResponse

DB_PATH = "callbacks.db"
MAX_BODY_SIZE = 64 * 1024  # 64 KB hard limit

app = FastAPI(title="Headless XSS Callback Service")

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

@app.on_event("startup")
def startup():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS callbacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            ip_address TEXT,
            method TEXT,
            full_url TEXT,
            path TEXT,
            query_params TEXT,
            headers TEXT,
            cookies TEXT,
            body TEXT,
            user_agent TEXT,
            referer TEXT
        )
        """
    )
    conn.commit()
    conn.close()

@app.api_route("/c/{token}", methods=["GET", "POST", "PUT", "PATCH", "OPTIONS"])
async def collect(token: str, request: Request):
    client_ip = request.client.host if request.client else None

    headers = dict(request.headers)
    query_params = dict(request.query_params)
    cookies = request.cookies

    body: Optional[str] = None
    try:
        raw_body = await request.body()
        if raw_body:
            body = raw_body[:MAX_BODY_SIZE].decode(errors="replace")
    except Exception:
        body = None

# this is where you need to sanitize
    record = {
        "token": token,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ip_address": client_ip,
        "method": request.method,
        "full_url": str(request.url),
        "path": request.url.path,
        "query_params": json.dumps(query_params),
        "headers": json.dumps(headers),
        "cookies": json.dumps(cookies),
        "body": body,
        "user_agent": headers.get("user-agent"),
        "referer": headers.get("referer"),
    }

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO callbacks (
            token, timestamp, ip_address, method, full_url, path,
            query_params, headers, cookies, body, user_agent, referer
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record["token"],
            record["timestamp"],
            record["ip_address"],
            record["method"],
            record["full_url"],
            record["path"],
            record["query_params"],
            record["headers"],
            record["cookies"],
            record["body"],
            record["user_agent"],
            record["referer"],
        )
    )
    conn.commit()
    conn.close()

    # Small, browser-safe response
    return Response(status_code=204)

