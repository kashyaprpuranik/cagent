import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///./control_plane.db')

# OpenObserve settings
OPENOBSERVE_URL = os.environ.get('OPENOBSERVE_URL', 'http://openobserve:5080')
OPENOBSERVE_USER = os.environ.get('OPENOBSERVE_USER', 'admin@cagent.local')
OPENOBSERVE_PASSWORD = os.environ.get('OPENOBSERVE_PASSWORD', 'admin')

# Redis
REDIS_URL = os.environ.get('REDIS_URL', '')

# CORS: comma-separated list of allowed origins, or empty for same-origin only
CORS_ORIGINS = [
    o.strip() for o in os.environ.get('CORS_ORIGINS', '').split(',') if o.strip()
]
