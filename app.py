import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import uuid
import logging
import datetime
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, abort
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__, static_folder='static')

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='app.log' if not app.debug else None
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# App configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(24)),
    UPLOAD_FOLDER='static/uploads/covers',
    ALLOWED_EXTENSIONS={'jpg', 'jpeg', 'png', 'webp'},
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,  # 5MB
    ADMIN_CREDENTIALS_FILE='data/admin_credentials.json',
    TEMPLATES_AUTO_RELOAD=True
)

# Create directories if they don't exist
required_dirs = [
    app.config['UPLOAD_FOLDER'],
    'data',
    'data/backups'
]

for directory in required_dirs:
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as e:
        logger.error(f"Failed to create directory {directory}: {str(e)}")
        raise

# Initialize extensions
csrf = CSRFProtect(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "100 per hour"],
    storage_uri="memory://"
)

# Constants
BRAND_NAME = "Cool Cat Productions-Druna C."
VAT_RATE = 0.20  # 20% VAT

# Helper functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def load_json_file(filepath, default=[]):
    try:
        if not os.path.exists(filepath):
            with open(filepath, 'w') as f:
                json.dump(default, f)
            return default
        
        with open(filepath, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON in {filepath}, resetting file")
                with open(filepath, 'w') as f:
                    json.dump(default, f)
                return default
    except Exception as e:
        logger.error(f"Error loading {filepath}: {str(e)}")
        return default

def save_json_file(filepath, data):
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving to {filepath}: {str(e)}")
        return False

# Admin credentials management
def load_admin_credentials():
    return load_json_file(app.config['ADMIN_CREDENTIALS_FILE'])

def save_admin_credentials(username, password):
    credentials = {
        'username': username,
        'password_hash': generate_password_hash(password),
        'created_at': datetime.datetime.now().isoformat()
    }
    return save_json_file(app.config['ADMIN_CREDENTIALS_FILE'], credentials)

def is_admin_registered():
    return os.path.exists(app.config['ADMIN_CREDENTIALS_FILE'])

def get_admin_credentials():
    credentials = load_admin_credentials()
    if credentials:
        return credentials.get('username'), credentials.get('password_hash')
    return None, None

# Initialize admin credentials
ADMIN_USER, ADMIN_PASS_HASH = get_admin_credentials()

# Authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Admin access required', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Security headers
@app.after_request
def add_security_headers(response):
    headers = {
        'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src 'self' fonts.gstatic.com; script-src 'self'",
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    }
    for key, value in headers.items():
        response.headers[key] = value
    return response

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Admin routes
@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if session.get('admin_logged_in'):
        return redirect(url_for('home'))
    if is_admin_registered():
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not password:
            flash('Username and password are required', 'error')
        elif password != confirm_password:
            flash('Passwords do not match', 'error')
        elif len(password) < 8:
            flash('Password must be at least 8 characters', 'error')
        elif save_admin_credentials(username, password):
            global ADMIN_USER, ADMIN_PASS_HASH
            ADMIN_USER, ADMIN_PASS_HASH = get_admin_credentials()
            flash('Admin account created successfully! Please log in.', 'success')
            return redirect(url_for('admin_login'))
        else:
            flash('Failed to create admin account', 'error')

    return render_template('admin/register.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if not is_admin_registered():
        return redirect(url_for('admin_register'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        stored_username, stored_password_hash = get_admin_credentials()
        
        if username == stored_username and check_password_hash(stored_password_hash, password):
            session['admin_logged_in'] = True
            flash('Admin login successful', 'success')
            return redirect(url_for('home'))
        flash('Invalid credentials', 'error')

    return render_template('admin/login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Admin logged out', 'info')
    return redirect(url_for('home'))

# [Rest of your existing routes...]

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
