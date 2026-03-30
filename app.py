import json
import sqlite3
import unicodedata
import re
import time
from datetime import datetime
from typing import Optional, Tuple
from collections import defaultdict, deque

from fastapi import FastAPI, Request, Response, HTTPException

DB_PATH = "callbacks.db"

# -------------------------
# Size & sanitation limits
# -------------------------
MAX_BODY_SIZE = 64 * 1024
MAX_STRING_LENGTH = 2048
MAX_HEADERS = 50
MAX_QUERY_PARAMS = 50
MAX_COOKIES = 20

CONTROL_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")

# -------------------------
# Rate limiting settings
# -------------------------
RATE_LIMIT_WINDOW = 60          # seconds
RATE_LIMIT_MAX = 60             # requests per window
MAX_RATE_KEYS = 10_000           # hard memory cap

rate_limit_store = defaultdict(deque)

app = FastAPI(title="Headless XSS Callback Service (Sanitized + Rate Limited)")


# -------------------------
# Database
# -------------------------
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


# -------------------------
# Sanitization helpers
# -------------------------
def sanitize_string(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = unicodedata.normalize("NFKC", value)
    value = CONTROL_CHARS.sub("", value)
    return value[:MAX_STRING_LENGTH]


def sanitize_dict(data: dict, max_items: int) -> dict:
    clean = {}
    for i, (k, v) in enumerate(data.items()):
        if i >= max_items:
            break
        clean[str(sanitize_string(str(k)))] = sanitize_string(str(v))
    return clean


# -------------------------
# Rate limiting
# -------------------------
def rate_limit(key: Tuple[str, str]):
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    q = rate_limit_store[key]

    # Remove expired timestamps
    while q and q[0] < window_start:
        q.popleft()

    if len(q) >= RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    q.append(now)

    # Global memory cap enforcement
    if len(rate_limit_store) > MAX_RATE_KEYS:
        # Drop oldest key aggressively
        oldest_key = min(rate_limit_store.items(), key=lambda i: i[1][0])[0]
        del rate_limit_store[oldest_key]


# -------------------------
# Callback endpoint
# -------------------------
@app.api_route("/c/{token}", methods=["GET", "POST", "PUT", "PATCH", "OPTIONS"])
async def collect(token: str, request: Request):
    token = sanitize_string(token)
    client_ip = sanitize_string(request.client.host if request.client else "unknown")

    # Apply rate limiting early
    rate_limit((client_ip, token))

    headers = sanitize_dict(dict(request.headers), MAX_HEADERS)
    query_params = sanitize_dict(dict(request.query_params), MAX_QUERY_PARAMS)
    cookies = sanitize_dict(request.cookies, MAX_COOKIES)

    body: Optional[str] = None
    try:
        raw_body = await request.body()
        if raw_body:
            body = sanitize_string(raw_body[:MAX_BODY_SIZE].decode(errors="replace"))
    except Exception:
        body = None

    record = (
        token,
        datetime.utcnow().isoformat() + "Z",
        client_ip,
        sanitize_string(request.method),
        sanitize_string(str(request.url)),
        sanitize_string(request.url.path),
        json.dumps(query_params, ensure_ascii=False),
        json.dumps(headers, ensure_ascii=False),
        json.dumps(cookies, ensure_ascii=False),
        body,
        headers.get("user-agent"),
        headers.get("referer"),
    )

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO callbacks (
            token, timestamp, ip_address, method, full_url, path,
            query_params, headers, cookies, body, user_agent, referer
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        record,
    )
    conn.commit()
    conn.close()

    return Response(status_code=204)
