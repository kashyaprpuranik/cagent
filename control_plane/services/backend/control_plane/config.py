import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///./control_plane.db')

# OpenObserve settings
OPENOBSERVE_URL = os.environ.get('OPENOBSERVE_URL', 'http://log-store:5080')
OPENOBSERVE_USER = os.environ.get('OPENOBSERVE_USER', 'admin@cagent.local')
OPENOBSERVE_PASSWORD = os.environ.get('OPENOBSERVE_PASSWORD', 'admin')

# Root credentials — used ONLY for org/user provisioning
OPENOBSERVE_ROOT_USER = os.environ.get(
    'OPENOBSERVE_ROOT_USER',
    os.environ.get('OPENOBSERVE_USER', 'admin@cagent.local')
)
OPENOBSERVE_ROOT_PASSWORD = os.environ.get(
    'OPENOBSERVE_ROOT_PASSWORD',
    os.environ.get('OPENOBSERVE_PASSWORD', 'admin')
)

# Multi-tenancy toggle (default on)
OPENOBSERVE_MULTI_TENANT = os.environ.get('OPENOBSERVE_MULTI_TENANT', 'true').lower() == 'true'

# Ingestion hardening
LOG_INGEST_MAX_BATCH_SIZE = int(os.environ.get('LOG_INGEST_MAX_BATCH_SIZE', '500'))
LOG_INGEST_MAX_PAYLOAD_BYTES = int(os.environ.get('LOG_INGEST_MAX_PAYLOAD_BYTES', str(1024 * 1024)))
LOG_INGEST_MAX_AGE_HOURS = int(os.environ.get('LOG_INGEST_MAX_AGE_HOURS', '24'))
LOG_INGEST_TIMEOUT = float(os.environ.get('LOG_INGEST_TIMEOUT', '10.0'))

# Query hardening
LOG_QUERY_TIMEOUT = float(os.environ.get('LOG_QUERY_TIMEOUT', '15.0'))
LOG_QUERY_MAX_RESULTS = int(os.environ.get('LOG_QUERY_MAX_RESULTS', '1000'))
LOG_QUERY_MAX_TIME_RANGE_DAYS = int(os.environ.get('LOG_QUERY_MAX_TIME_RANGE_DAYS', '30'))

# Redis
REDIS_URL = os.environ.get('REDIS_URL', '')

# CORS: comma-separated list of allowed origins, or empty for same-origin only
CORS_ORIGINS = [
    o.strip() for o in os.environ.get('CORS_ORIGINS', '').split(',') if o.strip()
]

# Beta features: comma-separated list of enabled beta features (e.g. "email")
BETA_FEATURES = set(
    f.strip() for f in os.environ.get('BETA_FEATURES', '').split(',') if f.strip()
)

# Trusted proxy depth: number of reverse proxies in front of the backend.
# 0 = no proxy, use TCP peer address (default, safe).
# 1 = one proxy, use rightmost X-Forwarded-For entry.
# N = N proxies, use Nth-from-right X-Forwarded-For entry.
TRUSTED_PROXY_COUNT = int(os.environ.get('TRUSTED_PROXY_COUNT', '0'))
