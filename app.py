import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import uuid
import logging
import datetime
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__, static_folder='static')

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# App configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-fallback-key')
app.config['UPLOAD_FOLDER'] = 'static/uploads/covers'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png', 'webp'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB
app.config['ADMIN_CREDENTIALS_FILE'] = 'data/admin_credentials.json'

# Create directories if they don't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('data', exist_ok=True)
os.makedirs('data/backups', exist_ok=True)

# Initialize extensions
csrf = CSRFProtect(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "100 per hour"]
)

# Constants
BRAND_NAME = "Cool Cat Productions-Druna C."
VAT_RATE = 0.20  # 20% VAT

# Helper functions for admin credentials
def load_admin_credentials():
    try:
        if os.path.exists(app.config['ADMIN_CREDENTIALS_FILE']):
            with open(app.config['ADMIN_CREDENTIALS_FILE'], 'r') as f:
                return json.load(f)
        return None
    except Exception as e:
        logger.error(f"Error loading admin credentials: {str(e)}")
        return None

def save_admin_credentials(username, password):
    try:
        credentials = {
            'username': username,
            'password_hash': generate_password_hash(password)
        }
        with open(app.config['ADMIN_CREDENTIALS_FILE'], 'w') as f:
            json.dump(credentials, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving admin credentials: {str(e)}")
        return False

# Check if admin is registered
def is_admin_registered():
    return os.path.exists(app.config['ADMIN_CREDENTIALS_FILE'])

# Get current admin credentials
def get_admin_credentials():
    credentials = load_admin_credentials()
    if credentials:
        return credentials.get('username'), credentials.get('password_hash')
    return None, None

# Update the ADMIN_USER and ADMIN_PASS_HASH with loaded credentials
ADMIN_USER, ADMIN_PASS_HASH = get_admin_credentials()

# [Rest of your existing helper functions...]

# Admin registration route
@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    # If admin is already registered and logged in, redirect to home
    if session.get('admin_logged_in'):
        return redirect(url_for('home'))

    # If admin is already registered but not logged in, redirect to login
    if is_admin_registered():
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not password:
            flash('Username and password are required', 'error')
            return redirect(url_for('admin_register'))

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('admin_register'))

        if len(password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return redirect(url_for('admin_register'))

        if save_admin_credentials(username, password):
            # Update the in-memory credentials
            global ADMIN_USER, ADMIN_PASS_HASH
            ADMIN_USER, ADMIN_PASS_HASH = get_admin_credentials()
            
            flash('Admin account created successfully! Please log in.', 'success')
            return redirect(url_for('admin_login'))
        else:
            flash('Failed to create admin account', 'error')
            return redirect(url_for('admin_register'))

    return render_template('admin/register.html')

# Modified admin login to use stored credentials
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    # If no admin is registered, redirect to registration
    if not is_admin_registered():
        return redirect(url_for('admin_register'))

    try:
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            
            stored_username, stored_password_hash = get_admin_credentials()
            
            if username == stored_username and check_password_hash(stored_password_hash, password):
                session['admin_logged_in'] = True
                flash('Admin login successful', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid credentials', 'error')
        return render_template('admin/login.html')
    except Exception as e:
        logger.error(f"Admin login error: {str(e)}")
        return render_template('error.html', message='Admin login failed'), 500

# [Rest of your existing routes...]

# Run the app
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
