import os
import time
import uuid
from typing import List

import jwt
from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

app = FastAPI()

# Q1 values
ALLOWED_ORIGIN = "https://dash-251w5p.example.com"
EMAIL = "23f2002594@ds.study.iitm.ac.in"

# Q2 values
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


class VerifyRequest(BaseModel):
    token: str


@app.middleware("http")
async def add_required_headers(request: Request, call_next):
    start = time.perf_counter()
    request_id = str(uuid.uuid4())

    response = await call_next(request)

    process_time = time.perf_counter() - start
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{process_time:.6f}"

    origin = request.headers.get("origin")

    # Strict CORS for Q1 /stats
    if origin == ALLOWED_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
        response.headers["Vary"] = "Origin"

    # Open CORS for Q3 /effective-config so browser grader can check it
    if request.url.path.startswith("/effective-config"):
        response.headers["Access-Control-Allow-Origin"] = origin or "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "*"
        response.headers["Vary"] = "Origin"

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
async def options_effective_config(request: Request):
    origin = request.headers.get("origin")
    return Response(
        status_code=204,
        headers={
            "Access-Control-Allow-Origin": origin or "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Vary": "Origin",
        },
    )


@app.get("/effective-config")
async def effective_config(set_: List[str] = Query(default=[], alias="set")):
    config = {}

    # 1. defaults
    apply_layer(config, {
        "port": 8000,
        "workers": 1,
        "debug": False,
        "log_level": "info",
        "api_key": "default-secret-000",
    })

    # 2. config.development.yaml
    apply_layer(config, {
        "workers": 12,
    })

    # 3. .env file
    apply_layer(config, {
        "APP_API_KEY": "key-hfb5qw6oek",
    })

    # 4. OS environment variables
    apply_layer(config, {
        "APP_PORT": os.getenv("APP_PORT", "8097"),
        "APP_DEBUG": os.getenv("APP_DEBUG", "true"),
        "APP_API_KEY": os.getenv("APP_API_KEY", "key-jx8gfv8sqg"),
    })

    # Also support real APP_* variables if set in Render
    for key, value in os.environ.items():
        if key.startswith("APP_") or key == "NUM_WORKERS":
            apply_layer(config, {key: value})

    # 5. CLI-style overrides from query params
    # Example: ?set=port=9000&set=debug=false
    for item in set_:
        if "=" in item:
            key, value = item.split("=", 1)
            apply_layer(config, {key: value})

    return coerce_config(config)
