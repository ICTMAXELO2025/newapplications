#!/usr/bin/env bash
# Exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

# Create necessary directories
mkdir -p static/uploads

# Initialize database
python -c "
from app import init_db
init_db()
print('Database initialized successfully!')
"

echo "Build completed successfully!"