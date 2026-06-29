import time
import uuid
from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import JSONResponse, Response

app = FastAPI()

ALLOWED_ORIGIN = "https://dash-251w5p.example.com"
EMAIL = "23f2002594@ds.study.iitm.ac.in"


@app.middleware("http")
async def add_required_headers(request: Request, call_next):
    start = time.perf_counter()
    request_id = str(uuid.uuid4())

    response = await call_next(request)

    process_time = time.perf_counter() - start
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{process_time:.6f}"

    origin = request.headers.get("origin")
    if origin == ALLOWED_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
        response.headers["Vary"] = "Origin"

    return response


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


@app.get("/")
async def root():
    return {"message": "Stats API is running"}


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
