from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import config
from database import Base, engine
import models  # noqa: F401  (registers tables on Base.metadata)
from auth_router import router as auth_router
from auth_router import router as auth_router
from papers_router import router as papers_router

from auth_router import router as auth_router
from papers_router import router as papers_router
from admin_router import router as admin_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=engine)
    print(f"[QPMS] DB ready -> {config.DATABASE_URL}")
    yield


app = FastAPI(title="QPMS", lifespan=lifespan)

app.include_router(auth_router)
app.include_router(papers_router)
app.include_router(admin_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request, call_next):
    """Standard defensive headers on every response."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    # Swagger UI (/docs) and ReDoc (/redoc) load their JS/CSS from a CDN and
    # run an inline bootstrap script -- a strict same-origin CSP blocks all
    # of that and the docs page never renders. CSP is meant to protect pages
    # THIS backend renders; the real frontend is served separately and sets
    # its own policy. So: apply the strict policy to the actual API surface,
    # skip it for the dev-only interactive docs.
    if not request.url.path.startswith(("/docs", "/redoc", "/openapi.json")):
        response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response


@app.get("/")
def root():
    return {"service": "QPMS backend", "status": "running"}