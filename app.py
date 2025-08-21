import os
import json
import logging
import time
import hashlib
import secrets
import string
import re
import mimetypes
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_file, Response, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from markupsafe import escape

# Import security modules
from security_config import SecurityConfig
from security_middleware import SecurityMiddleware
from auth_system import AuthSystem
from file_security import FileSecurity

# Initialize logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Apply security configuration
app.config.from_object(SecurityConfig)

# Initialize security systems
auth_system = AuthSystem()
file_security = FileSecurity(SecurityConfig.ALLOWED_EXTENSIONS, SecurityConfig.MAX_FILE_SIZES)

# Production Configuration
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY', secrets.token_hex(32)),
    USERS_FILE=os.path.join('data', 'users.json'),
    ALBUMS_FILE=os.path.join('data', 'albums.json'),
    PURCHASES_FILE=os.path.join('data', 'purchases.json'),
    COVERS_FOLDER=os.path.join('static', 'uploads', 'covers'),
    MUSIC_FOLDER=os.path.join('static', 'uploads', 'music'),
    VIDEOS_FOLDER=os.path.join('static', 'uploads', 'videos'),
    UPLOAD_FOLDER='static/uploads',
    ADMIN_USERNAME=os.getenv('ADMIN_USERNAME', 'admin'),
    ADMIN_PASSWORD_HASH=os.getenv('ADMIN_PASSWORD_HASH', ''),
    DOWNLOAD_TOKENS={},
    VIDEO_STREAM_CHUNK_SIZE=2048 * 1024,  # 2MB chunks for better streaming
)

# Apply security middleware
app.wsgi_app = SecurityMiddleware(app.wsgi_app)

# Security event logging
def log_security_event(event_type, details, user_id=None, ip=None):
    ip = ip or request.remote_addr
    user_id = user_id or session.get('user_id')
    event = {
        'timestamp': datetime.now().isoformat(),
        'event_type': event_type,
        'user_id': user_id,
        'ip': ip,
        'details': details
    }
    logger.warning(f"SECURITY: {event_type} - User: {user_id} - IP: {ip} - Details: {details}")

# Enhanced security headers
@app.after_request
def add_security_headers(response):
    for key, value in SecurityConfig.SECURITY_HEADERS.items():
        response.headers[key] = value
    
    # Build CSP header from directives
    csp_directives = []
    for directive, values in SecurityConfig.CSP_DIRECTIVES.items():
        if isinstance(values, list):
            csp_directives.append(f"{directive} {' '.join(values)}")
        else:
            csp_directives.append(f"{directive} {values}")
    
    response.headers['Content-Security-Policy'] = '; '.join(csp_directives)
    
    return response

# Security before request checks
@app.before_request
def security_checks():
    # Enforce HTTPS in production
    if not app.debug and not request.is_secure and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)
    
    # Check for suspicious patterns in request
    suspicious_patterns = ['../', '/etc/passwd', '/bin/', '/cmd', ';', '|', '`', '$(']
    if any(pattern in request.path for pattern in suspicious_patterns):
        log_security_event('SUSPICIOUS_REQUEST', f'Path: {request.path}')
        abort(400)

# ... (rest of your existing routes and functions with enhanced security)

# Enhanced admin login with 2FA
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        ip = request.remote_addr
        
        if auth_system.is_locked_out(ip, 'admin_login'):
            flash('Too many failed attempts. Please try again in 15 minutes.', 'warning')
            return render_template('admin/login.html', csrf_token=auth_system.generate_csrf_token())
        
        if not auth_system.validate_csrf_token():
            flash('Security token invalid. Please try again.', 'danger')
            log_security_event('CSRF_FAILURE', 'Admin login attempt', ip=ip)
            return render_template('admin/login.html', csrf_token=auth_system.generate_csrf_token())
        
        if not auth_system.check_rate_limit(ip, 'admin_login', SecurityConfig.MAX_LOGIN_ATTEMPTS, SecurityConfig.LOGIN_WINDOW):
            flash('Too many login attempts. Please try again in 5 minutes.', 'warning')
            return render_template('admin/login.html', csrf_token=auth_system.generate_csrf_token())
        
        try:
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            
            admin_password_hash = app.config['ADMIN_PASSWORD_HASH']
            
            if (username == app.config['ADMIN_USERNAME'] and 
                check_password_hash(admin_password_hash, password)):
                
                # Generate and require 2FA for admin login
                token = auth_system.generate_2fa_token('admin')
                # In a real implementation, you would send this via email or authenticator app
                # For now, we'll just store it in session for demonstration
                session['admin_pending_2fa'] = True
                session['admin_username'] = username
                session['admin_2fa_token'] = token  # In real app, don't store in session
                
                flash('Please check your authenticator app for the verification code', 'info')
                log_security_event('ADMIN_LOGIN_2FA', '2FA required for admin login', ip=ip)
                return render_template('admin/verify_2fa.html', csrf_token=auth_system.generate_csrf_token())
            
            log_security_event('ADMIN_LOGIN_FAILED', f'Username: {username}', ip=ip)
            flash('Invalid credentials', 'danger')
            
        except Exception as e:
            logger.error(f"Admin login error: {e}")
            log_security_event('ADMIN_LOGIN_ERROR', f'Error: {str(e)}', ip=ip)
            flash('Login failed. Please try again.', 'danger')
    
    return render_template('admin/login.html', csrf_token=auth_system.generate_csrf_token())

# 2FA verification endpoint
@app.route('/admin/verify-2fa', methods=['POST'])
def admin_verify_2fa():
    if not session.get('admin_pending_2fa'):
        return redirect(url_for('admin_login'))
    
    if not auth_system.validate_csrf_token():
        flash('Security token invalid. Please try again.', 'danger')
        return redirect(url_for('admin_login'))
    
    token = request.form.get('token', '')
    username = session.get('admin_username')
    
    # In a real app, you would verify against a stored token, not session
    if token and secrets.compare_digest(token, session.get('admin_2fa_token', '')):
        session['admin_logged_in'] = True
        session['admin_username'] = username
        session.permanent = True
        session.pop('admin_pending_2fa', None)
        session.pop('admin_2fa_token', None)
        
        # Regenerate session after login to prevent fixation
        session.regenerate()
        
        flash('Logged in successfully', 'success')
        log_security_event('ADMIN_LOGIN_SUCCESS', 'Admin logged in with 2FA')
        return redirect(url_for('admin_dashboard'))
    
    log_security_event('ADMIN_2FA_FAILED', 'Invalid 2FA token', username)
    flash('Invalid verification code', 'danger')
    return render_template('admin/verify_2fa.html', csrf_token=auth_system.generate_csrf_token())

# Enhanced file upload with additional security
@app.route('/admin/add-album', methods=['GET', 'POST'])
def add_album():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        try:
            if not auth_system.validate_csrf_token():
                flash('Security token invalid. Please try again.', 'danger')
                return render_template('admin/add_album.html', csrf_token=auth_system.generate_csrf_token())
            
            albums = load_data(app.config['ALBUMS_FILE'])
            cover = request.files.get('cover')
            music_files = request.files.getlist('music_files')
            video_file = request.files.get('video_file')
            video_category = request.form.get('video_category', 'music_videos')
            
            # Enhanced file validation
            if not cover or cover.filename == '':
                flash('No cover image selected', 'danger')
                return redirect(request.url)
            
            # Use our enhanced file security
            is_valid, message = file_security.allowed_file(cover.filename, 'image')
            if not is_valid:
                flash(message, 'danger')
                return redirect(request.url)
            
            is_valid_size, message = file_security.allowed_file_size(cover, 'image')
            if not is_valid_size:
                flash(message, 'danger')
                return redirect(request.url)
            
            # ... (rest of your existing code with enhanced security checks)

# ... (rest of your existing routes with enhanced security)

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    
    if not debug:
        # Production settings
        app.config['SESSION_COOKIE_SECURE'] = True
        app.config['PREFERRED_URL_SCHEME'] = 'https'
    
    app.run(host='0.0.0.0', port=port, debug=debug)
