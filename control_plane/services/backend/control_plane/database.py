from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

import os

from control_plane.config import DATABASE_URL

_connect_args = {"check_same_thread": False} if 'sqlite' in DATABASE_URL else {}
_pool_kwargs = (
    {}
    if "sqlite" in DATABASE_URL
    else {
        "pool_size": int(os.environ.get("DB_POOL_SIZE", "20")),
        "max_overflow": int(os.environ.get("DB_MAX_OVERFLOW", "40")),
        "pool_pre_ping": True,
        "pool_recycle": 1800,
    }
)

engine = create_engine(DATABASE_URL, connect_args=_connect_args, **_pool_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
