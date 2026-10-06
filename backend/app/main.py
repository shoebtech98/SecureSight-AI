import logging
import os
from pathlib import Path

from dotenv import load_dotenv

# Load environment variables from the project-root .env file
PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.database import engine, Base, ensure_schema
from backend.app import models
from backend.app.api import auth, logs, threats, dashboard, assistant, reports


# Configure Python logging so route-level logs appear in the uvicorn terminal
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)


# Create database tables
Base.metadata.create_all(bind=engine)
ensure_schema()


app = FastAPI(
    title="SecureSight AI API",
    description="AI Assisted Security Log Analysis and Threat Detection Platform API",
    version="1.0.0",
)


# CORS configuration for the React frontend
_default_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

_env_origins = os.getenv("CORS_ORIGINS")

origins = (
    [o.strip() for o in _env_origins.split(",") if o.strip()]
    if _env_origins
    else _default_origins
)


# Authentication uses a Bearer token in the Authorization header
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["X-Total-Count"],
)


# Include routers
app.include_router(auth.router)
app.include_router(logs.router)
app.include_router(threats.router)
app.include_router(dashboard.router)
app.include_router(assistant.router)
app.include_router(reports.router)


@app.get("/")
def read_root():
    return {"message": "SecureSight AI API is running successfully"}