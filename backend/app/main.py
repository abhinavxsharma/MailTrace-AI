"""
MAILTRACE AI - FastAPI Main Application.
Provides core entrypoint, CORS configuration, database auto-initialization, and API routes.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException as FastHTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.db.session import init_db
from app.api.cases import router as cases_router

# Ensure tables are created upon module loading
init_db()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context for startup and shutdown tasks."""
    init_db()
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="MAILTRACE AI - AI-Powered Email Threat Detection & Forensic Intelligence Platform",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware for React / frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Simple and reliable structured error handler."""
    if isinstance(exc, FastHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "message": "An internal server error occurred.",
            "detail": str(exc),
        },
    )


@app.get("/api/health", tags=["Health"])
async def health_check():
    """Health check endpoint confirming service status."""
    return {
        "status": "ok",
        "service": "MAILTRACE AI",
    }


# Include API routers
app.include_router(cases_router, prefix="/api")


@app.get("/", include_in_schema=False)
async def root():
    """Root redirect / index info."""
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": "/docs",
        "health": "/api/health",
    }
