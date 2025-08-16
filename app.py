import os
import secrets
import bleach
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# ===== Security Config =====
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024  # 8MB upload limit

# HTTPS enforcement & security headers
Talisman(app, 
    force_https=True,
    strict_transport_security=True,
    session_cookie_secure=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': ["'self'", 'cdn.jsdelivr.net'],
        'style-src': ["'self'", 'cdn.jsdelivr.net', "'unsafe-inline'"],
        'img-src': ["'self'", 'data:', 'cdn.jsdelivr.net']
    }
)

# Rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# ===== Secure File Upload =====
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ===== Routes with Security =====
@app.route('/')
@limiter.limit("10 per minute")
def home():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
@limiter.limit("5 per minute")
def upload():
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('home'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('home'))

    if file and allowed_file(file.filename):
        # Sanitize filename
        filename = secure_filename(file.filename)
        # Add random prefix to prevent overwrites
        unique_name = f"{secrets.token_hex(8)}_{filename}"
        filepath = os.path.join(UPLOAD_FOLDER, unique_name)
        
        try:
            file.save(filepath)
            flash('File uploaded securely', 'success')
        except Exception as e:
            app.logger.error(f"Upload failed: {str(e)}")
            flash('Upload failed', 'error')
    
    return redirect(url_for('home'))

# ===== Error Handlers =====
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # Dev-only HTTPS
