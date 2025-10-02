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

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database connection - FIXED: Only one function
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
        conn = sqlite3.connect('applications.db')
        conn.row_factory = sqlite3.Row
        return conn

# Initialize database tables - NEEDS UPDATE for PostgreSQL
# Initialize database tables - FIXED: Remove duplicates
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if we're using PostgreSQL or SQLite
    is_postgres = hasattr(conn, 'cursor') and not hasattr(conn, 'row_factory')
    
    if is_postgres:
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
        
        # ADD THIS NEW TABLE FOR MESSAGES
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100) NOT NULL,
                subject VARCHAR(200) NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        
        # ADD THIS NEW TABLE FOR MESSAGES
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100) NOT NULL,
                subject VARCHAR(200) NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")

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

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/student/register', methods=['GET', 'POST'])
def student_register():
    if request.method == 'POST':
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        
        conn = get_db_connection()
        
        # Check if email already exists
        existing_user = conn.execute(
            'SELECT id FROM students WHERE email = ?', (email,)
        ).fetchone()
        
        if existing_user:
            flash('Email already registered!', 'error')
            conn.close()
            return redirect(url_for('student_register'))
        
        # Insert new student
        hashed_password = generate_password_hash(password)
        cursor = conn.execute(
            'INSERT INTO students (email, phone, password) VALUES (?, ?, ?)',
            (email, phone, hashed_password)
        )
        student_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('student_login'))
    
    return render_template('student_register.html')

@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        print(f"🔐 Login attempt for: {email}")  # Debug
        
        conn = get_db_connection()
        student = conn.execute(
            'SELECT * FROM students WHERE email = ?', (email,)
        ).fetchone()
        conn.close()
        
        if student and check_password_hash(student['password'], password):
            # Store student ID in session
            session['student_id'] = student['id']
            session['student_email'] = student['email']
            session['user_type'] = 'student'
            session.permanent = True  # Make session persistent
            print(f"✅ Login successful: {student['email']}")  # Debug
            flash('Login successful!', 'success')
            return redirect(url_for('student_dashboard'))
        else:
            print("❌ Login failed")  # Debug
            flash('Invalid email or password!', 'error')
    
    return render_template('student_login.html')

@app.route('/student/dashboard')
@student_login_required
def student_dashboard():
    student_id = session['student_id']
    
    conn = get_db_connection()
    applications = conn.execute('''
        SELECT * FROM applications 
        WHERE student_id = ? 
        ORDER BY id
    ''', (student_id,)).fetchall()
    conn.close()
    
    return render_template('student_dashboard.html', applications=applications)

@app.route('/apply', methods=['GET', 'POST'])
@student_login_required
def application():
    if request.method == 'POST':
        names = request.form['names']
        surname = request.form['surname']
        course = request.form['course']
        university = request.form['university']
        student_id = session['student_id']
        
        # Handle CV upload
        cv = request.files['cv']
        if cv and cv.filename.endswith('.pdf'):
            filename = secure_filename(f"{student_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{cv.filename}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            cv.save(filepath)
            
            conn = get_db_connection()
            conn.execute('''
                INSERT INTO applications (names, surname, course, university, cv_filename, student_id)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (names, surname, course, university, filename, student_id))
            conn.commit()
            conn.close()
            
            flash('Application submitted successfully!', 'success')
            return redirect(url_for('student_dashboard'))
        else:
            flash('Please upload a valid PDF file!', 'error')
    
    return render_template('application.html')

@app.route('/download_cv/<int:app_id>')
@student_login_required
def download_cv(app_id):
    student_id = session['student_id']
    
    conn = get_db_connection()
    application = conn.execute(
        'SELECT * FROM applications WHERE id = ?', (app_id,)
    ).fetchone()
    conn.close()
    
    if not application:
        flash('Application not found!', 'error')
        return redirect(url_for('index'))
    
    # Check if user has permission to download
    if application['student_id'] == student_id or session.get('user_type') == 'admin':
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], application['cv_filename'])
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True)
        else:
            flash('CV file not found!', 'error')
    else:
        flash('Access denied!', 'error')
    
    return redirect(url_for('index'))

# Admin Routes
@app.route('/admin-secret-login-123', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        if email == 'admin@maxelo.co.za' and password == 'admin123':
            conn = get_db_connection()
            
            # Check if admin exists, if not create one
            admin = conn.execute(
                'SELECT * FROM admins WHERE email = ?', (email,)
            ).fetchone()
            
            if not admin:
                hashed_password = generate_password_hash('admin123')
                cursor = conn.execute(
                    'INSERT INTO admins (email, password) VALUES (?, ?)',
                    (email, hashed_password)
                )
                admin_id = cursor.lastrowid
                conn.commit()
                admin = conn.execute(
                    'SELECT * FROM admins WHERE email = ?', (email,)
                ).fetchone()
            
            # Store admin ID in session
            session['admin_id'] = admin['id']
            session['admin_email'] = admin['email']
            session['user_type'] = 'admin'
            session.permanent = True  # Make session persistent
            conn.close()
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials!', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@admin_login_required
def admin_dashboard():
    search_query = request.args.get('search', '').strip()
    
    conn = get_db_connection()
    
    if search_query:
        # Search across multiple fields
        query = '''
            SELECT a.*, s.email as student_email 
            FROM applications a 
            JOIN students s ON a.student_id = s.id 
            WHERE a.names LIKE ? OR a.surname LIKE ? OR a.course LIKE ? 
            OR a.university LIKE ? OR s.email LIKE ?
            ORDER BY a.id
        '''
        search_term = f'%{search_query}%'
        applications = conn.execute(query, (
            search_term, search_term, search_term, 
            search_term, search_term
        )).fetchall()
    else:
        # Get all applications if no search
        applications = conn.execute('''
            SELECT a.*, s.email as student_email 
            FROM applications a 
            JOIN students s ON a.student_id = s.id 
            ORDER BY a.id
        ''').fetchall()
    
    conn.close()
    
    return render_template('admin_dashboard.html', applications=applications)

@app.route('/admin/update_status/<int:app_id>/<status>')
@admin_login_required
def update_status(app_id, status):
    if status not in ['approved', 'rejected', 'pending']:
        flash('Invalid status!', 'error')
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    conn.execute(
        'UPDATE applications SET status = ? WHERE id = ?', 
        (status, app_id)
    )
    conn.commit()
    conn.close()
    
    flash(f'Application {status}!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_application/<int:app_id>')
@admin_login_required
def delete_application(app_id):
    conn = get_db_connection()
    
    # Get filename to delete the file
    result = conn.execute(
        'SELECT cv_filename FROM applications WHERE id = ?', (app_id,)
    ).fetchone()
    
    if result:
        # Delete the file
        try:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], result['cv_filename'])
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception as e:
            print(f"Error deleting file: {e}")
        
        # Delete from database
        conn.execute('DELETE FROM applications WHERE id = ?', (app_id,))
        conn.commit()
    
    conn.close()
    
    flash('Application deleted!', 'success')
    return redirect(url_for('admin_dashboard'))

# Admin CV Download Route
@app.route('/admin/download_cv/<int:app_id>')
@admin_login_required
def admin_download_cv(app_id):
    conn = get_db_connection()
    application = conn.execute(
        'SELECT * FROM applications WHERE id = ?', (app_id,)
    ).fetchone()
    conn.close()
    
    if not application:
        flash('Application not found!', 'error')
        return redirect(url_for('admin_dashboard'))
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], application['cv_filename'])
    
    if not os.path.exists(filepath):
        flash('CV file not found!', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Create a nice filename for download
    download_name = f"CV_{application['surname']}_{application['names']}.pdf"
    
    # Send the file for download
    return send_file(
        filepath,
        as_attachment=True,
        download_name=download_name,
        mimetype='application/pdf'
    )

# Password Reset Routes
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user_type = request.form['user_type']
        
        conn = get_db_connection()
        
        # Check if email exists in the appropriate table
        if user_type == 'student':
            user = conn.execute('SELECT * FROM students WHERE email = ?', (email,)).fetchone()
        else:  # admin
            user = conn.execute('SELECT * FROM admins WHERE email = ?', (email,)).fetchone()
        
        conn.close()
        
        if user:
            # Store user info in session for reset password page
            session['reset_user_email'] = email
            session['reset_user_type'] = user_type
            
            # Redirect directly to reset password page
            return redirect(url_for('reset_password'))
        else:
            flash('Email address not found in our system! Please check your email and user type.', 'error')
    
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    # Check if user came from forgot password page
    if 'reset_user_email' not in session or 'reset_user_type' not in session:
        flash('Please request a password reset first.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('reset_password.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return render_template('reset_password.html')
        
        # Update password in database
        conn = get_db_connection()
        hashed_password = generate_password_hash(password)
        
        try:
            user_type = session['reset_user_type']
            user_email = session['reset_user_email']
            
            if user_type == 'student':
                conn.execute(
                    'UPDATE students SET password = ? WHERE email = ?',
                    (hashed_password, user_email)
                )
            else:  # admin
                conn.execute(
                    'UPDATE admins SET password = ? WHERE email = ?',
                    (hashed_password, user_email)
                )
            
            conn.commit()
            conn.close()
            
            # Clear reset session data
            session.pop('reset_user_email', None)
            session.pop('reset_user_type', None)
            
            flash('Password updated successfully! You can now login with your new password.', 'success')
            
            # Redirect to appropriate login page
            if user_type == 'student':
                return redirect(url_for('student_login'))
            else:
                return redirect(url_for('admin_login'))
                
        except Exception as e:
            conn.close()
            flash('Error updating password. Please try again.', 'error')
            print(f"Password reset error: {e}")
    
    return render_template('reset_password.html')

@app.route('/logout')
def logout():
    # Clear all session data
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/debug/session')
def debug_session():
    return f"""
    <h3>Session Debug</h3>
    <pre>
    Session data: {dict(session)}
    User Type: {session.get('user_type', 'Not set')}
    Student ID: {session.get('student_id', 'Not set')}
    Student Email: {session.get('student_email', 'Not set')}
    Admin ID: {session.get('admin_id', 'Not set')}
    Admin Email: {session.get('admin_email', 'Not set')}
    </pre>
    <a href="/" class="btn btn-primary">Home</a>
    <a href="/student/login" class="btn btn-secondary">Student Login</a>
    """

@app.route('/debug/database')
def debug_database():
    conn = get_db_connection()
    students = conn.execute('SELECT * FROM students').fetchall()
    admins = conn.execute('SELECT * FROM admins').fetchall()
    applications = conn.execute('SELECT * FROM applications').fetchall()
    conn.close()
    
    student_list = []
    for student in students:
        student_list.append(dict(student))
    
    return f"""
    <h3>Database Debug</h3>
    <pre>
    Students ({len(students)}): {student_list}
    Admins ({len(admins)}): {[dict(admin) for admin in admins]}
    Applications: {len(applications)}
    </pre>
    <a href="/" class="btn btn-primary">Home</a>
    """

    # Contact Message Routes
@app.route('/send-message', methods=['GET', 'POST'])
def send_message():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message_text = request.form['message']
        
        # Validate required fields
        if not all([name, email, subject, message_text]):
            flash('Please fill in all required fields.', 'error')
            return render_template('send_message.html')
        
        # Save message to database
        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO messages (name, email, subject, message) VALUES (?, ?, ?, ?)',
                (name, email, subject, message_text)
            )
            conn.commit()
            flash('Your message has been sent successfully! We will get back to you soon.', 'success')
        except Exception as e:
            flash('Error sending message. Please try again.', 'error')
            print(f"Message send error: {e}")
        finally:
            conn.close()
        
        return redirect(url_for('send_message'))
    
    return render_template('send_message.html')

@app.route('/admin/view-messages')
@admin_login_required
def view_messages():
    conn = get_db_connection()
    messages = conn.execute(
        'SELECT * FROM messages ORDER BY id'
    ).fetchall()
    conn.close()
    
    return render_template('view_messages.html', messages=messages)

@app.route('/admin/delete-message/<int:message_id>')
@admin_login_required
def delete_message(message_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM messages WHERE id = ?', (message_id,))
    conn.commit()
    conn.close()
    
    flash('Message deleted successfully!', 'success')
    return redirect(url_for('view_messages'))



if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Get port from environment variable for Render
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)