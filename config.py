import os

class Config:
    # Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here-change-in-production')
    UPLOAD_FOLDER = 'static/uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    
    # Local PostgreSQL Configuration (for development)
    POSTGRES_CONFIG = {
        'user': 'postgres',
        'password': 'Maxelo@2023',
        'host': 'localhost',
        'port': '5432',
        'database': 'applications_db'
    }
    
    # Render will automatically provide DATABASE_URL