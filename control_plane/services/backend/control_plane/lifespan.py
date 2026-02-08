import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from control_plane.config import logger, REDIS_URL
from control_plane.database import SessionLocal
from control_plane.seed import seed_bootstrap, seed_test_data


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting AI Devbox Control Plane")
    if REDIS_URL:
        logger.info(f"Rate limiting enabled with Redis: {REDIS_URL}")
    else:
        logger.info("Rate limiting enabled with in-memory storage (single instance only)")

    db = SessionLocal()
    try:
        seed_bootstrap(db)

        if os.environ.get("SEED_TOKENS", "false").lower() == "true":
            logger.info("SEED_TOKENS=true — seeding tenants and tokens")
            seed_test_data(db)
    finally:
        db.close()

    yield
    logger.info("Shutting down")
