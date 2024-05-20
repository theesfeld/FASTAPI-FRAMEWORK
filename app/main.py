from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from dotenv import load_dotenv
from starlette.responses import JSONResponse
import aioredis
import os

load_dotenv(".env")
# sample .env file
# DATABASE_URL=postgresql://username:password@host/database
# REDIS_HOST=localhost
# REDIS_PORT=6379

from .api.v1.router import api_router
from .database import get_db, engine
from .models import RequestLog, APIKey, Base
from sqlalchemy.orm import Session

app = FastAPI(title="FASTAPI FRAMEWORK", version="0.1")


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": f"HTTP error occurred: {exc.detail}"},
    )


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.detail},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"message": "An unexpected error occurred"},
    )


@app.middleware("http")
async def log_requests(request: Request, call_next):
    response = await call_next(request)
    if "/api/" in request.url.path:
        db: Session = next(get_db())
        api_key_header = request.headers.get("x-api-key")
        api_key_id = None
        if api_key_header:
            hashed_key = APIKey.hash_api_key(api_key_header)
            api_key = (
                db.query(APIKey).filter(APIKey.hashed_api_key == hashed_key).first()
            )
            if api_key and api_key.verify_api_key(api_key_header):
                api_key_id = api_key.id
            else:
                # put invalid API key stuff [TODO]
                pass
        client_ip = request.client.host
        log_entry = RequestLog(
            api_key_id=api_key_id,
            endpoint=request.url.path,
            method=request.method,
            status_code=response.status_code,
            ip_address=client_ip,
        )
        db.add(log_entry)
        db.commit()
    return response


@app.on_event("startup")
async def startup():
    Base.metadata.create_all(bind=engine)
    app.state.redis = aioredis.from_url(
        f"redis://{os.getenv('REDIS_HOST')}:{os.getenv('REDIS_PORT')}",
        encoding="utf-8",
        decode_responses=True,
    )


@app.on_event("shutdown")
async def shutdown():
    await app.state.redis.close()


app.include_router(api_router, prefix="/api/v1")
