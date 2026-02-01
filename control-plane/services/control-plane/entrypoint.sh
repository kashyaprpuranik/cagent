#!/bin/bash
set -e

# Generate ENCRYPTION_KEY if not provided
if [ -z "$ENCRYPTION_KEY" ]; then
    echo "ENCRYPTION_KEY not set, generating one for this session..."
    export ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    echo "WARNING: ENCRYPTION_KEY was auto-generated. Secrets will be lost on container restart!"
    echo "For production, set ENCRYPTION_KEY in your environment or .env file."
fi

# Seed database if empty (checks for any agents)
echo "Checking if database needs seeding..."
python -c "
import os
import sys
sys.path.insert(0, '/app')

from main import engine, SessionLocal, Base, AgentState

# Create tables if they don't exist
Base.metadata.create_all(bind=engine)

db = SessionLocal()
try:
    agent_count = db.query(AgentState).count()
    if agent_count == 0:
        print('Database is empty, seeding...')
        db.close()
        # Import and run seeder
        from seed import seed_database
        seed_database(reset=False, show_token=True)
    else:
        print(f'Database already has {agent_count} agent(s), skipping seed.')
finally:
    db.close()
"

# Start the application
echo "Starting control plane API..."
exec uvicorn main:app --host 0.0.0.0 --port 8000
