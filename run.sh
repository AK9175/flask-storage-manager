#!/bin/bash

# Load environment from .env file
export $(cat .env | grep -v '#' | xargs)

# Start the Flask app
PORT=${PORT:-5001}
python3 app_new.py
