from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here-change-this-in-production')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Use PostgreSQL on Render, SQLite locally
if os.getenv('RENDER'):
    app.config['DATABASE'] = 'postgresql'  # Render provides DATABASE_URL
else:
    app.config['DATABASE'] = 'applications.db'

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database connection
def get_db_connection():
    if os.getenv('DATABASE_URL'):
        # Use PostgreSQL on Render
        import psycopg2
        from urllib.parse import urlparse
        
        result = urlparse(os.getenv('DATABASE_URL'))
        conn = psycopg2.connect(
            database=result.path[1:],
            user=result.username,
            password=result.password,
            host=result.hostname,
            port=result.port
        )
        return conn
    else:
        # Use SQLite locally
        conn = sqlite3.connect(app.config['DATABASE'])
        conn.row_factory = sqlite3.Row
        return conn

# Initialize database tables
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if os.getenv('DATABASE_URL'):
        # PostgreSQL syntax
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS students (
                id SERIAL PRIMARY KEY,
                email VARCHAR(100) UNIQUE NOT NULL,
                phone VARCHAR(20) NOT NULL,
                password VARCHAR(200) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(200) NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS applications (
                id SERIAL PRIMARY KEY,
                names VARCHAR(100) NOT NULL,
                surname VARCHAR(100) NOT NULL,
                course VARCHAR(100) NOT NULL,
                university VARCHAR(100) NOT NULL,
                cv_filename VARCHAR(200) NOT NULL,
                status VARCHAR(20) DEFAULT 'pending',
                date_applied TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                student_id INTEGER REFERENCES students(id)
            )
        ''')
    else:
        # SQLite syntax
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email VARCHAR(100) UNIQUE NOT NULL,
                phone VARCHAR(20) NOT NULL,
                password VARCHAR(200) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(200) NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                names VARCHAR(100) NOT NULL,
                surname VARCHAR(100) NOT NULL,
                course VARCHAR(100) NOT NULL,
                university VARCHAR(100) NOT NULL,
                cv_filename VARCHAR(200) NOT NULL,
                status VARCHAR(20) DEFAULT 'pending',
                date_applied TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                student_id INTEGER REFERENCES students(id)
            )
        ''')
    
    conn.commit()
    conn.close()

# Simple login required decorator
def student_login_required(f):
    def decorated_function(*args, **kwargs):
        if 'student_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('student_login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def admin_login_required(f):
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please log in as admin to access this page.', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# [Keep all your routes exactly the same as before - they should work with both databases]
# ... (Include all your route functions from the previous version)

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Get port from environment variable for Render
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)