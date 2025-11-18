#!/bin/bash

# Docker entrypoint script for Storage Manager

set -e

echo "Starting Storage Manager..."

# Create necessary directories if they don't exist
mkdir -p instance flask_session emails

# Initialize database if it doesn't exist
if [ ! -f "instance/storage_manager.db" ]; then
    echo "Initializing database..."
    python3 -c "
from app_new import app
with app.app_context():
    from backend.app.models import db
    db.create_all()
    print('Database initialized successfully!')
"
fi

# Check if environment is properly configured
if [ -f ".env" ]; then
    echo "✅ .env file found and mounted successfully"
else
    echo "ℹ️  .env file loaded via docker-compose env_file"
fi

# Verify critical environment variables
if [ -z "$FLASK_SECRET_KEY" ] && [ -z "$AWS_ACCESS_KEY_ID" ]; then
    echo "⚠️  Warning: Key environment variables not detected."
    echo "   Make sure your .env file contains FLASK_SECRET_KEY and AWS credentials"
else
    echo "✅ Environment variables loaded successfully"
fi

# Start the application
echo "Starting Flask application on port 5001..."
exec python3 app_new.py