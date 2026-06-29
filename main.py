import os
import time
import uuid
import base64
import math
from typing import List, Optional
from collections import deque
from datetime import datetime, timezone

import jwt
from fastapi import FastAPI, Request, Query, HTTPException, Header
from fastapi.responses import JSONResponse, Response, PlainTextResponse
from pydantic import BaseModel

app = FastAPI()

EMAIL = "23f2002594@ds.study.iitm.ac.in"

# ---------------- Common observability state for Q6 ----------------

START_TIME = time.perf_counter()
REQUEST_COUNT = 0
LOGS = deque(maxlen=1000)

# ---------------- Q1 ----------------

ALLOWED_ORIGIN = "https://dash-251w5p.example.com"

# ---------------- Q2 ----------------

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-y5cqp3p3.apps.exam.local"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

# ---------------- Q5 ----------------

API_KEY = "ak_e1elbl3a1vexap7iushfzygb"


class VerifyRequest(BaseModel):
    token: str


class Event(BaseModel):
    user: str
    amount: float
    ts: int


class AnalyticsRequest(BaseModel):
    events: List[Event]


@app.middleware("http")
async def add_required_headers_and_logs(request: Request, call_next):
    global REQUEST_COUNT

    start = time.perf_counter()

    # Q10 request context middleware
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id

    REQUEST_COUNT += 1

    response = await call_next(request)

    process_time = time.perf_counter() - start
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{process_time:.6f}"

    origin = request.headers.get("origin")

    # Strict CORS for Q1 /stats
    if origin == ALLOWED_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
        response.headers["Vary"] = "Origin"

    # Open CORS for browser-checked endpoints except /ping
    if (
        request.url.path.startswith("/effective-config")
        or request.url.path.startswith("/analytics")
        or request.url.path.startswith("/work")
        or request.url.path.startswith("/metrics")
        or request.url.path.startswith("/logs")
        or request.url.path.startswith("/healthz")
        or request.url.path.startswith("/orders")
    ):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, X-API-Key, X-Client-Id, Idempotency-Key, X-Request-ID"
        )
        response.headers["Access-Control-Expose-Headers"] = "Retry-After, X-Request-ID"
        response.headers["Vary"] = "Origin"

    # Q10 scoped CORS for /ping only: no wildcard
    if request.url.path.startswith("/ping"):
        ping_allowed_origins = {
            "https://app-lirvlb.example.com",
            "https://exam.sanand.workers.dev",
            "https://tds.s-anand.net",
        }

        if origin in ping_allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = (
                "Content-Type, X-Client-Id, X-Request-ID"
            )
            response.headers["Access-Control-Expose-Headers"] = "X-Request-ID"
            response.headers["Vary"] = "Origin"

    LOGS.append({
        "level": "info",
        "ts": datetime.now(timezone.utc).isoformat(),
        "path": request.url.path,
        "request_id": request_id,
        "method": request.method,
        "status_code": response.status_code,
        "process_time_s": process_time,
    })

    return response


@app.get("/")
async def root():
    return {"message": "API is running"}


# ---------------- Q1: Stats API ----------------

@app.options("/stats")
async def options_stats(request: Request):
    origin = request.headers.get("origin")

    if origin == ALLOWED_ORIGIN:
        return Response(
            status_code=204,
            headers={
                "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type",
                "Vary": "Origin",
            },
        )

    return Response(status_code=403)


@app.get("/stats")
async def stats(values: str = Query(...)):
    try:
        nums = [int(x.strip()) for x in values.split(",") if x.strip() != ""]
    except ValueError:
        raise HTTPException(status_code=400, detail="values must be comma-separated integers")

    if not nums:
        raise HTTPException(status_code=400, detail="values cannot be empty")

    total = sum(nums)

    return {
        "email": EMAIL,
        "count": len(nums),
        "sum": total,
        "min": min(nums),
        "max": max(nums),
        "mean": total / len(nums),
    }


# ---------------- Q2: JWT Verify API ----------------

@app.post("/verify")
async def verify_token(payload: VerifyRequest):
    try:
        claims = jwt.decode(
            payload.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
        )

        return {
            "valid": True,
            "email": claims.get("email"),
            "sub": claims.get("sub"),
            "aud": claims.get("aud"),
        }

    except Exception:
        return JSONResponse(status_code=401, content={"valid": False})


# ---------------- Q3: Effective Config API ----------------

def to_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes", "on")


def apply_layer(config, layer):
    for key, value in layer.items():
        normalized_key = key.lower()

        if normalized_key.startswith("app_"):
            normalized_key = normalized_key[4:]

        if normalized_key == "num_workers":
            normalized_key = "workers"

        config[normalized_key] = value


def coerce_config(config):
    return {
        "port": int(config["port"]),
        "workers": int(config["workers"]),
        "debug": to_bool(config["debug"]),
        "log_level": str(config["log_level"]),
        "api_key": "****",
    }


@app.options("/effective-config")
async def options_effective_config():
    return Response(
        status_code=204,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        },
    )


@app.get("/effective-config")
async def effective_config(set_: List[str] = Query(default=[], alias="set")):
    config = {}

    apply_layer(config, {
        "port": 8000,
        "workers": 1,
        "debug": False,
        "log_level": "info",
        "api_key": "default-secret-000",
    })

    apply_layer(config, {
        "workers": 12,
    })

    apply_layer(config, {
        "APP_API_KEY": "key-hfb5qw6oek",
    })

    apply_layer(config, {
        "APP_PORT": os.getenv("APP_PORT", "8097"),
        "APP_DEBUG": os.getenv("APP_DEBUG", "true"),
        "APP_API_KEY": os.getenv("APP_API_KEY", "key-jx8gfv8sqg"),
    })

    for key, value in os.environ.items():
        if key.startswith("APP_") or key == "NUM_WORKERS":
            apply_layer(config, {key: value})

    for item in set_:
        if "=" in item:
            key, value = item.split("=", 1)
            apply_layer(config, {key: value})

    return coerce_config(config)


# ---------------- Q5: Analytics API ----------------

@app.options("/analytics")
async def options_analytics():
    return Response(
        status_code=204,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
        },
    )


@app.post("/analytics")
async def analytics(
    payload: AnalyticsRequest,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
):
    if x_api_key != API_KEY:
        return JSONResponse(status_code=401, content={"error": "unauthorized"})

    events = payload.events

    total_events = len(events)
    unique_users = len(set(event.user for event in events))

    revenue = 0.0
    user_totals = {}

    for event in events:
        if event.amount > 0:
            revenue += event.amount
            user_totals[event.user] = user_totals.get(event.user, 0.0) + event.amount

    top_user = max(user_totals, key=user_totals.get) if user_totals else ""

    return {
        "email": EMAIL,
        "total_events": total_events,
        "unique_users": unique_users,
        "revenue": revenue,
        "top_user": top_user,
    }


# ---------------- Q6: Observability API ----------------

@app.options("/work")
async def options_work():
    return Response(
        status_code=204,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        },
    )


@app.get("/work")
async def work(n: int = Query(1)):
    if n < 0:
        raise HTTPException(status_code=400, detail="n must be non-negative")

    for _ in range(n):
        pass

    return {
        "email": EMAIL,
        "done": n,
    }


@app.get("/metrics")
async def metrics():
    body = (
        "# HELP http_requests_total Total number of HTTP requests\n"
        "# TYPE http_requests_total counter\n"
        f"http_requests_total {REQUEST_COUNT}\n"
    )
    return PlainTextResponse(body, media_type="text/plain")


@app.get("/healthz")
async def healthz():
    uptime = time.perf_counter() - START_TIME
    return {
        "status": "ok",
        "uptime_s": uptime,
    }


@app.get("/logs/tail")
async def logs_tail(limit: int = Query(10)):
    if limit < 0:
        limit = 0
    return list(LOGS)[-limit:]


# ---------------- Q9: Orders API ----------------

TOTAL_ORDERS = 58
RATE_LIMIT = 17
RATE_WINDOW_SECONDS = 10

IDEMPOTENCY_STORE = {}
NEXT_ORDER_ID = 1001
RATE_BUCKETS = {}


def encode_cursor(start_id: int) -> str:
    raw = str(start_id).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def decode_cursor(cursor: str) -> int:
    try:
        padding = "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode((cursor + padding).encode("utf-8"))
        return int(raw.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="invalid cursor")


def check_rate_limit(client_id: str):
    now = time.time()

    if not client_id:
        client_id = "anonymous"

    bucket = RATE_BUCKETS.get(client_id, [])

    bucket = [ts for ts in bucket if now - ts < RATE_WINDOW_SECONDS]

    if len(bucket) >= RATE_LIMIT:
        retry_after = max(1, math.ceil(RATE_WINDOW_SECONDS - (now - bucket[0])))
        RATE_BUCKETS[client_id] = bucket
        return retry_after

    bucket.append(now)
    RATE_BUCKETS[client_id] = bucket
    return None


def rate_limit_response(retry_after: int):
    return JSONResponse(
        status_code=429,
        content={"error": "rate limit exceeded"},
        headers={
            "Retry-After": str(retry_after),
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Expose-Headers": "Retry-After",
        },
    )


@app.options("/orders")
async def options_orders():
    return Response(
        status_code=204,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-Client-Id, Idempotency-Key",
            "Access-Control-Expose-Headers": "Retry-After",
        },
    )


@app.post("/orders")
async def create_order(
    request: Request,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    x_client_id: Optional[str] = Header(default="anonymous", alias="X-Client-Id"),
):
    retry_after = check_rate_limit(x_client_id or "anonymous")
    if retry_after is not None:
        return rate_limit_response(retry_after)

    if not idempotency_key:
        raise HTTPException(status_code=400, detail="Idempotency-Key header is required")

    if idempotency_key in IDEMPOTENCY_STORE:
        return JSONResponse(
            status_code=200,
            content=IDEMPOTENCY_STORE[idempotency_key],
        )

    try:
        payload = await request.json()
    except Exception:
        payload = {}

    global NEXT_ORDER_ID

    order = {
        "id": f"ord_{NEXT_ORDER_ID}",
        "email": EMAIL,
        "status": "created",
        "payload": payload,
    }

    NEXT_ORDER_ID += 1
    IDEMPOTENCY_STORE[idempotency_key] = order

    return JSONResponse(status_code=201, content=order)


@app.get("/orders")
async def list_orders(
    limit: int = Query(10),
    cursor: Optional[str] = Query(default=None),
    x_client_id: Optional[str] = Header(default="anonymous", alias="X-Client-Id"),
):
    retry_after = check_rate_limit(x_client_id or "anonymous")
    if retry_after is not None:
        return rate_limit_response(retry_after)

    if limit < 1:
        limit = 1

    limit = min(limit, 100)

    if cursor:
        start_id = decode_cursor(cursor)
    else:
        start_id = 1

    if start_id < 1:
        start_id = 1

    end_id = min(start_id + limit, TOTAL_ORDERS + 1)

    items = [
        {
            "id": order_id,
            "item": f"order-{order_id}",
            "amount": float(order_id * 10),
        }
        for order_id in range(start_id, end_id)
    ]

    if end_id <= TOTAL_ORDERS:
        next_cursor = encode_cursor(end_id)
    else:
        next_cursor = None

    return {
        "items": items,
        "next_cursor": next_cursor,
    }


# ---------------- Q10: Middleware Stack API ----------------

PING_RATE_LIMIT = 12
PING_RATE_WINDOW_SECONDS = 10
PING_RATE_BUCKETS = {}


def check_ping_rate_limit(client_id: str):
    now = time.time()

    if not client_id:
        client_id = "anonymous"

    bucket = PING_RATE_BUCKETS.get(client_id, [])
    bucket = [ts for ts in bucket if now - ts < PING_RATE_WINDOW_SECONDS]

    if len(bucket) >= PING_RATE_LIMIT:
        PING_RATE_BUCKETS[client_id] = bucket
        return True

    bucket.append(now)
    PING_RATE_BUCKETS[client_id] = bucket
    return False


@app.options("/ping")
async def options_ping():
    return Response(status_code=204)


@app.get("/ping")
async def ping(
    request: Request,
    x_client_id: Optional[str] = Header(default="anonymous", alias="X-Client-Id"),
):
    if check_ping_rate_limit(x_client_id or "anonymous"):
        return JSONResponse(
            status_code=429,
            content={"error": "rate limit exceeded"},
            headers={
                "X-Request-ID": request.state.request_id,
            },
        )

    return {
        "email": EMAIL,
        "request_id": request.state.request_id,
    }
