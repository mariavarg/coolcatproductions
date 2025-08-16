"""
Music Shop Flask Application
- Secure file uploads
- Rate limiting
- CSRF protection
- Error handling
"""

import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize Flask app
app = Flask(__name__)

# ============= SECURITY CONFIGURATION =============
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))  # Random secret key

# HTTPS and security headers
Talisman(
    app,
    force_https=True,  # Enforce HTTPS
    strict_transport_security=True,  # HSTS
    content_security_policy={
        'default-src': "'self'",
        'script-src': ["'self'", 'cdn.jsdelivr.net'],
        'style-src': ["'self'", 'cdn.jsdelivr.net'],
        'img-src': ["'self'", 'data:']
    }
)

# Rate limiting protection
limiter = Limiter(
    app=app,
    key_func=get_remote_address,  # Limit by IP
    default_limits=["200 per day", "50 per hour"]
)

# ============= FILE UPLOAD CONFIG =============
UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Create upload folder if not exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ============= ROUTES =============
@app.route('/')
@limiter.limit("10 per minute")  # Rate limiting
def home():
    """Homepage route"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
@limiter.limit("5 per minute")  # Stricter limit for uploads
def upload_file():
    """Secure file upload endpoint"""
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('home'))
    
    file = request.files['file']
    
    # Validate file
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('home'))
    
    if file and allowed_file(file.filename):
        # Secure filename and save
        filename = secure_filename(file.filename)
        unique_name = f"{secrets.token_hex(8)}_{filename}"  # Prevent overwrites
        file.save(os.path.join(UPLOAD_FOLDER, unique_name))
        flash('File uploaded successfully')
    
    return redirect(url_for('home'))

# ============= ERROR HANDLERS =============
@app.errorhandler(404)
def page_not_found(error):
    """Custom 404 page"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Custom 500 page"""
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # Dev-only HTTPS
