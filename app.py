# Enhanced Security with 2FA and Payment Processing

## 1. Update Your `.env` File

Add these new environment variables:

```bash
# 2FA Configuration
TOTP_SECRET=your_super_secure_totp_secret_here

# Stripe Payment Processing
STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key
STRIPE_PUBLISHABLE_KEY=pk_test_your_stripe_publishable_key
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret

# Backup codes for 2FA (comma-separated)
BACKUP_CODES=code1,code2,code3,code4,code5,code6,code7,code8,code9,code10
```

## 2. Install Required Dependencies

Add these to your `requirements.txt`:

```txt
stripe==7.0.0
pyotp==2.8.0
qrcode[pil]==7.4.2
```

## 3. Enhanced Security Implementation

#Here's the complete updated `app.py` with 2FA and Stripe integration:

```python
import os
import json
import logging
import time
import hashlib
import secrets
import string
import re
import mimetypes
import smtplib
import stripe
import pyotp
import qrcode
from io import BytesIO
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_file, Response, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from markupsafe import escape

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
    ALLOWED_EXTENSIONS={'png', 'jpg', 'jpeg', 'webp'},
    ALLOWED_MUSIC_EXTENSIONS={'mp3', 'wav', 'flac'},
    ALLOWED_VIDEO_EXTENSIONS={'mp4', 'mov', 'avi', 'webm', 'mkv'},
    ADMIN_USERNAME=os.getenv('ADMIN_USERNAME', 'admin'),
    ADMIN_PASSWORD_HASH=os.getenv('ADMIN_PASSWORD_HASH', ''),
    MAX_CONTENT_LENGTH=1024 * 1024 * 1024,
    MAX_VIDEO_SIZE=1024 * 1024 * 1024,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    DOWNLOAD_TOKENS={},
    VIDEO_STREAM_CHUNK_SIZE=2048 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    MAX_LOGIN_ATTEMPTS=5,
    LOCKOUT_TIME=900,
    # Email configuration
    SMTP_SERVER=os.getenv('SMTP_SERVER', ''),
    SMTP_PORT=int(os.getenv('SMTP_PORT', 587)),
    SMTP_USERNAME=os.getenv('SMTP_USERNAME', ''),
    SMTP_PASSWORD=os.getenv('SMTP_PASSWORD', ''),
    ADMIN_EMAIL=os.getenv('ADMIN_EMAIL', 'drunac192@gmail.com'),
    SECURITY_QUESTION_1=os.getenv('SECURITY_QUESTION_1', 'What was your first pet\'s name?'),
    SECURITY_QUESTION_2=os.getenv('SECURITY_QUESTION_2', 'What city were you born in?'),
    SECURITY_ANSWER_1_HASH=os.getenv('SECURITY_ANSWER_1_HASH', ''),
    SECURITY_ANSWER_2_HASH=os.getenv('SECURITY_ANSWER_2_HASH', ''),
    PASSWORD_RESET_TOKENS={},
    # 2FA Configuration
    TOTP_SECRET=os.getenv('TOTP_SECRET', pyotp.random_base32()),
    BACKUP_CODES=os.getenv('BACKUP_CODES', '').split(','),
    # Stripe Configuration
    STRIPE_SECRET_KEY=os.getenv('STRIPE_SECRET_KEY', ''),
    STRIPE_PUBLISHABLE_KEY=os.getenv('STRIPE_PUBLISHABLE_KEY', ''),
    STRIPE_WEBHOOK_SECRET=os.getenv('STRIPE_WEBHOOK_SECRET', ''),
)

# Initialize Stripe
stripe.api_key = app.config['STRIPE_SECRET_KEY']

# Security setup
login_attempts = {}
failed_login_lockout = {}
security_events = []

# Ensure required directories exist
required_dirs = [
    'data', 'data/backups',
    'static/uploads/covers', 'static/uploads/music',
    'static/uploads/videos/music_videos',
    'static/uploads/videos/interviews',
    'static/uploads/videos/live_performances', 
    'static/uploads/videos/behind_the_scenes'
]

for directory in required_dirs:
    os.makedirs(directory, exist_ok=True)
    logger.info(f"Ensured directory exists: {directory}")

# Security functions
def log_security_event(event_type, details, user_id=None, ip=None):
    """Log security events for monitoring and auditing"""
    ip = ip or request.remote_addr
    user_id = user_id or session.get('user_id')
    event = {
        'timestamp': datetime.now().isoformat(),
        'event_type': event_type,
        'user_id': user_id,
        'ip': ip,
        'details': details
    }
    security_events.append(event)
    logger.warning(f"SECURITY: {event_type} - User: {user_id} - IP: {ip} - Details: {details}")

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token():
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return True
    token = request.form.get('csrf_token')
    return token and secrets.compare_digest(token, session.get('csrf_token', ''))

def check_rate_limit(ip, endpoint, max_attempts=5, window=300):
    now = time.time()
    key = f"{ip}_{endpoint}"
    
    if key in login_attempts:
        login_attempts[key] = [t for t in login_attempts[key] if now - t < window]
    
    if key not in login_attempts:
        login_attempts[key] = []
    
    if len(login_attempts[key]) >= max_attempts:
        failed_login_lockout[key] = now + 900
        log_security_event('RATE_LIMIT_EXCEEDED', f'Endpoint: {endpoint}', ip=ip)
        return False
        
    login_attempts[key].append(now)
    return True

def is_locked_out(ip, endpoint):
    key = f"{ip}_{endpoint}"
    if key in failed_login_lockout:
        if time.time() < failed_login_lockout[key]:
            return True
        else:
            del failed_login_lockout[key]
    return False

def remove_auto_durations(albums):
    for album in albums:
        if 'tracks' in album:
            album['tracks'] = [track.split(' (')[0].strip() for track in album.get('tracks', [])]
    return albums

def generate_download_token(user_id, album_id):
    token = secrets.token_urlsafe(32)
    expiry = datetime.now() + timedelta(hours=24)
    
    app.config['DOWNLOAD_TOKENS'][token] = {
        'user_id': user_id,
        'album_id': album_id,
        'expiry': expiry.isoformat()
    }
    return token

def validate_download_token(token):
    if token not in app.config['DOWNLOAD_TOKENS']:
        return False
        
    token_data = app.config['DOWNLOAD_TOKENS'][token]
    expiry = datetime.fromisoformat(token_data['expiry'])
    
    if datetime.now() > expiry:
        app.config['DOWNLOAD_TOKENS'].pop(token)
        return False
        
    return token_data

def has_purchased(user_id, album_id):
    purchases = load_data(app.config['PURCHASES_FILE'])
    return any(p['user_id'] == user_id and p['album_id'] == album_id for p in purchases)

def record_purchase(user_id, album_id, amount, stripe_payment_intent=None):
    purchases = load_data(app.config['PURCHASES_FILE'])
    
    purchase = {
        'id': secrets.token_hex(8),
        'user_id': user_id,
        'album_id': album_id,
        'amount': amount,
        'purchase_date': datetime.now().isoformat(),
        'downloads': 0,
        'stripe_payment_intent': stripe_payment_intent,
        'status': 'completed'
    }
    
    purchases.append(purchase)
    save_data(purchases, app.config['PURCHASES_FILE'])
    return purchase

def get_track_filename(album_id, track_index, track_name):
    track_number = str(track_index + 1).zfill(2)
    safe_name = secure_filename(track_name.replace(' ', '_').lower())
    return f"{track_number}_{safe_name}.mp3"

def get_track_path(album_id, track_index, track_name):
    filename = get_track_filename(album_id, track_index, track_name)
    return os.path.join(app.config['MUSIC_FOLDER'], f"album_{album_id}", filename)

def ensure_music_dirs_exist(album_id):
    album_dir = os.path.join(app.config['MUSIC_FOLDER'], f"album_{album_id}")
    os.makedirs(album_dir, exist_ok=True)
    return album_dir

def is_password_complex(password):
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    
    checks = [
        (r'[A-Z]', "uppercase letter"),
        (r'[a-z]', "lowercase letter"),
        (r'[0-9]', "number"),
        (r'[!@#$%^&*(),.?":{}|<>]', "special character")
    ]
    
    for pattern, requirement in checks:
        if not re.search(pattern, password):
            return False, f"Password must contain at least one {requirement}"
    
    return True, "Password is strong"

def generate_strong_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def allowed_video_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_VIDEO_EXTENSIONS']

def get_video_url(album):
    if album.get('video_filename'):
        return url_for('stream_video', filename=album['video_filename'])
    return album.get('video_url', '')

def allowed_file(filename, file_type='image'):
    if '.' not in filename:
        return False
        
    ext = filename.rsplit('.', 1)[1].lower()
    
    extensions = {
        'image': app.config['ALLOWED_EXTENSIONS'],
        'music': app.config['ALLOWED_MUSIC_EXTENSIONS'],
        'video': app.config['ALLOWED_VIDEO_EXTENSIONS']
    }
    
    return ext in extensions.get(file_type, set())

def load_data(filename):
    try:
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []
    except Exception as e:
        logger.error(f"Error loading {filename}: {e}")
        backup_file = f"data/backups/{os.path.basename(filename)}.backup"
        if os.path.exists(backup_file):
            try:
                with open(backup_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
                return data
            except Exception as backup_error:
                logger.error(f"Backup restoration failed: {backup_error}")
        return []

def save_data(data, filename):
    try:
        backup_file = f"data/backups/{os.path.basename(filename)}.backup"
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as src, open(backup_file, 'w', encoding='utf-8') as dst:
                dst.write(src.read())
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving {filename}: {e}")
        return False

# Simplified image validation - just check if file exists
def is_valid_image(file_path):
    """Simplified image validation - just check if file exists"""
    return os.path.exists(file_path)

def allowed_file_size(file, max_size_mb=50):
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    return file_size <= max_size_mb * 1024 * 1024

def is_safe_path(basedir, path, follow_symlinks=True):
    """Prevent directory traversal attacks"""
    if follow_symlinks:
        real_path = os.path.realpath(path)
        real_basedir = os.path.realpath(basedir)
    else:
        real_path = os.path.abspath(path)
        real_basedir = os.path.abspath(basedir)
    
    return real_path.startswith(real_basedir)

# 2FA and Security functions
def generate_password_reset_token():
    """Generate a secure password reset token"""
    return secrets.token_urlsafe(32)

def store_password_reset_token(token, admin_data):
    """Store password reset token with expiration"""
    expiry = datetime.now() + timedelta(hours=1)
    app.config['PASSWORD_RESET_TOKENS'][token] = {
        'admin_data': admin_data,
        'expiry': expiry.isoformat()
    }

def validate_password_reset_token(token):
    """Validate password reset token"""
    if token not in app.config['PASSWORD_RESET_TOKENS']:
        return False
        
    token_data = app.config['PASSWORD_RESET_TOKENS'][token]
    expiry = datetime.fromisoformat(token_data['expiry'])
    
    if datetime.now() > expiry:
        app.config['PASSWORD_RESET_TOKENS'].pop(token)
        return False
        
    return token_data

def send_admin_notification(subject, message):
    """Send notification to admin email"""
    try:
        if not all([app.config['SMTP_SERVER'], app.config['SMTP_USERNAME'], app.config['SMTP_PASSWORD']]):
            logger.warning("Email not configured. Notification not sent.")
            return False
        
        msg = MIMEMultipart()
        msg['From'] = app.config['SMTP_USERNAME']
        msg['To'] = app.config['ADMIN_EMAIL']
        msg['Subject'] = f"CoolCat Productions: {subject}"
        
        msg.attach(MIMEText(message, 'plain'))
        
        server = smtplib.SMTP(app.config['SMTP_SERVER'], app.config['SMTP_PORT'])
        server.starttls()
        server.login(app.config['SMTP_USERNAME'], app.config['SMTP_PASSWORD'])
        server.send_message(msg)
        server.quit()
        
        logger.info(f"Admin notification sent: {subject}")
        return True
    except Exception as e:
        logger.error(f"Failed to send admin notification: {e}")
        return False

# 2FA Functions
def generate_2fa_secret():
    """Generate a new 2FA secret"""
    return pyotp.random_base32()

def generate_2fa_qr_code(secret, username):
    """Generate QR code for 2FA setup"""
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="CoolCat Productions")
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

def verify_2fa_token(secret, token):
    """Verify 2FA token"""
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def generate_backup_codes(count=10):
    """Generate backup codes for 2FA"""
    return [secrets.token_hex(4).upper() for _ in range(count)]

# Security middleware and headers
@app.before_request
def security_checks():
    """Perform security checks on each request"""
    # Enforce HTTPS in production
    if not app.debug and not request.is_secure and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)
    
    # Check for suspicious user agents
    user_agent = request.headers.get('User-Agent', '')
    suspicious_agents = ['bot', 'spider', 'crawl', 'scan', 'hack', 'sqlmap', 'nikto']
    if any(agent in user_agent.lower() for agent in suspicious_agents):
        log_security_event('SUSPICIOUS_USER_AGENT', f'User-Agent: {user_agent}')
    
    # Check for common attack patterns in request path
    suspicious_patterns = ['../', '/etc/passwd', '/bin/', '/cmd', ';', '|', '`', '$(']
    if any(pattern in request.path for pattern in suspicious_patterns):
        log_security_event('SUSPICIOUS_REQUEST', f'Path: {request.path}')
        abort(400)

@app.after_request
def add_security_headers(response):
    """Add comprehensive security headers to all responses"""
    security_headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        'Cross-Origin-Embedder-Policy': 'require-corp',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Resource-Policy': 'same-origin'
    }
    
    # Enhanced CSP
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://js.stripe.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob: https:; "
        "frame-src https://js.stripe.com; "
        "media-src 'self' blob:; "
        "frame-ancestors 'none'; "
        "form-action 'self';"
        "base-uri 'self';"
        "object-src 'none';"
    )
    security_headers['Content-Security-Policy'] = csp_policy
    
    for key, value in security_headers.items():
        response.headers[key] = value
    
    return response

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"500 Error: {e}")
    return render_template('500.html'), 500

@app.errorhandler(413)
def too_large(e):
    return render_template('413.html'), 413

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(400)
def bad_request(e):
    return render_template('400.html'), 400

# Routes
@app.route('/favicon.ico')
def favicon():
    try:
        return send_file('static/images/channel-logo.png', mimetype='image/png')
    except:
        return '', 204

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/uploads/<path:filename>')
def serve_uploaded_files(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        abort(404)

# Enhanced video streaming with anti-download measures
@app.route('/stream-video/<filename>')
def stream_video(filename):
    if not session.get('user_id'):
        abort(403)
    
    # Find which album contains this video and its category
    albums = load_data(app.config['ALBUMS_FILE'])
    album = next((a for a in albums if a.get('video_filename') == filename), None)
    
    if not album:
        abort(404)
    
    # Verify the user has access to this video
    if not has_purchased(session['user_id'], album['id']):
        abort(403)
    
    # Get the correct video path based on category
    video_category = album.get('video_category', 'music_videos')
    video_path = os.path.join(app.config['VIDEOS_FOLDER'], video_category, filename)
    
    if not os.path.exists(video_path) or not is_safe_path(app.config['VIDEOS_FOLDER'], video_path):
        abort(404)
    
    # Get file size for Content-Length header
    file_size = os.stat(video_path).st_size
    
    # Implement range requests for streaming
    range_header = request.headers.get('Range', None)
    
    if range_header:
        # Parse range header
        byte1, byte2 = 0, None
        match = re.search(r'(\d+)-(\d*)', range_header)
        if match:
            byte1 = int(match.group(1))
            if match.group(2):
                byte2 = int(match.group(2))
        
                byte1 = int(match.group(1))
        if match.group(2):
            byte2 = int(match.group(2))
    
    length = file_size - byte1
    if byte2 is not None:
        length = byte2 - byte1 + 1
    
    # Read file in chunks
    def generate():
        with open(video_path, 'rb') as f:
            f.seek(byte1)
            remaining = length
            while remaining > 0:
                chunk_size = min(app.config['VIDEO_STREAM_CHUNK_SIZE'], remaining)
                data = f.read(chunk_size)
                if not data:
                    break
                remaining -= len(data)
                yield data
    
    rv = Response(generate(), 
                206,
                mimetype=mimetypes.guess_type(video_path)[0], 
                direct_passthrough=True)
    rv.headers.add('Content-Range', f'bytes {byte1}-{byte1 + length - 1}/{file_size}')
    rv.headers.add('Accept-Ranges', 'bytes')
    rv.headers.add('Content-Length', str(length))
    
    # Anti-download measures
    rv.headers.add('Content-Disposition', 'inline')
    rv.headers.add('X-Content-Type-Options', 'nosniff')
    rv.headers.add('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
    
    return rv
else:
    # Regular request without range header
    def generate():
        with open(video_path, 'rb') as f:
            while True:
                data = f.read(app.config['VIDEO_STREAM_CHUNK_SIZE'])
                if not data:
                    break
                yield data
    
    rv = Response(generate(), mimetype=mimetypes.guess_type(video_path)[0])
    rv.headers.add('Content-Length', str(file_size))
    rv.headers.add('Accept-Ranges', 'bytes')
    
    # Anti-download measures
    rv.headers.add('Content-Disposition', 'inline')
    rv.headers.add('X-Content-Type-Options', 'nosniff')
    rv.headers.add('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
    
    return rv

# Main routes
@app.route('/')
def home():
    try:
        albums = load_data(app.config['ALBUMS_FILE'])
        albums = remove_auto_durations(albums)
        
        # Get albums with videos for featured section
        featured_albums = [a for a in albums if a.get('has_video', False) and a.get('video_filename')][:4]
        regular_albums = [a for a in albums if not a.get('has_video', False)][:8]
        
        return render_template('index.html', 
                             featured_albums=featured_albums,
                             regular_albums=regular_albums,
                             get_video_url=get_video_url,
                             stripe_publishable_key=app.config['STRIPE_PUBLISHABLE_KEY'])
    except Exception as e:
        logger.error(f"Home error: {e}")
        return render_template('index.html', featured_albums=[], regular_albums=[])

@app.route('/shop')
def shop():
    try:
        albums = load_data(app.config['ALBUMS_FILE'])
        albums = remove_auto_durations(albums)
        return render_template('shop.html', albums=albums if albums else [], get_video_url=get_video_url)
    except Exception as e:
        logger.error(f"Shop error: {e}")
        return render_template('shop.html', albums=[])

@app.route('/album/<album_id>')
def album(album_id):
    try:
        if not album_id.isdigit():
            abort(404)
            
        album_id = int(album_id)
        albums = load_data(app.config['ALBUMS_FILE'])
        album = next((a for a in albums if a['id'] == album_id), None)
        
        if not album:
            abort(404)
        
        album['tracks'] = [track.split(' (')[0].strip() for track in album.get('tracks', [])]
        
        owns_album = False
        video_accessible = False
        if session.get('user_id'):
            owns_album = has_purchased(session['user_id'], album_id)
            video_accessible = owns_album
        
        safe_album = {
            'id': album['id'],
            'title': escape(album['title']),
            'artist': escape(album['artist']),
            'year': escape(str(album.get('year', ''))),
            'cover': album['cover'],
            'tracks': [escape(track) for track in album.get('tracks', [])],
            'price': album.get('price', 0),
            'on_sale': album.get('on_sale', False),
            'sale_price': album.get('sale_price'),
            'video_url': get_video_url(album) if video_accessible else '',
            'has_video': album.get('has_video', False),
            'owns_album': owns_album,
            'video_accessible': video_accessible
        }
        return render_template('album.html', album=safe_album, 
                             stripe_publishable_key=app.config['STRIPE_PUBLISHABLE_KEY'])
    except Exception as e:
        logger.error(f"Album error: {e}")
        abort(500)

# USER AUTHENTICATION ROUTES
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            if not validate_csrf_token():
                flash('Security token invalid. Please try again.', 'danger')
                return render_template('register.html', csrf_token=generate_csrf_token())
            
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            
            # Validate input
            if not all([username, email, password]):
                flash('All fields are required', 'danger')
                return render_template('register.html', csrf_token=generate_csrf_token())
            
            # Check password complexity
            is_complex, message = is_password_complex(password)
            if not is_complex:
                flash(message, 'danger')
                return render_template('register.html', csrf_token=generate_csrf_token())
            
            users = load_data(app.config['USERS_FILE'])
            
            # Check if username or email already exists
            if any(u['username'].lower() == username.lower() for u in users):
                flash('Username already taken', 'danger')
                return render_template('register.html', csrf_token=generate_csrf_token())
                
            if any(u['email'].lower() == email.lower() for u in users):
                flash('Email already registered', 'danger')
                return render_template('register.html', csrf_token=generate_csrf_token())
            
            # Create new user
            new_user = {
                'id': len(users) + 1,
                'username': escape(username),
                'email': escape(email),
                'password_hash': generate_password_hash(password),
                'created_at': datetime.now().isoformat(),
                'is_active': True,
                '2fa_enabled': False,
                '2fa_secret': generate_2fa_secret(),
                'backup_codes': generate_backup_codes()
            }
            
            users.append(new_user)
            if save_data(users, app.config['USERS_FILE']):
                # Generate QR code for 2FA setup
                qr_code = generate_2fa_qr_code(new_user['2fa_secret'], new_user['username'])
                
                flash('Registration successful. Please set up 2FA.', 'success')
                return render_template('setup_2fa.html', 
                                     qr_code=qr_code, 
                                     backup_codes=new_user['backup_codes'],
                                     csrf_token=generate_csrf_token())
            else:
                flash('Registration failed. Please try again.', 'danger')
                
        except Exception as e:
            logger.error(f"Registration error: {e}")
            flash('Registration error. Please try again.', 'danger')
    
    return render_template('register.html', csrf_token=generate_csrf_token())

@app.route('/setup-2fa', methods=['POST'])
def setup_2fa():
    """Complete 2FA setup by verifying the first token"""
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    try:
        if not validate_csrf_token():
            flash('Security token invalid. Please try again.', 'danger')
            return redirect(url_for('profile'))
        
        token = request.form.get('token', '')
        
        users = load_data(app.config['USERS_FILE'])
        user = next((u for u in users if u['id'] == session['user_id']), None)
        
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('login'))
        
        if verify_2fa_token(user['2fa_secret'], token):
            # Enable 2FA for the user
            user_index = next((i for i, u in enumerate(users) if u['id'] == session['user_id']), -1)
            if user_index != -1:
                users[user_index]['2fa_enabled'] = True
                if save_data(users, app.config['USERS_FILE']):
                    flash('Two-factor authentication enabled successfully.', 'success')
                    log_security_event('2FA_ENABLED', 'User enabled 2FA', session['user_id'])
                else:
                    flash('Failed to enable 2FA. Please try again.', 'danger')
            else:
                flash('User not found in database.', 'danger')
        else:
            flash('Invalid authentication code. Please try again.', 'danger')
            
    except Exception as e:
        logger.error(f"2FA setup error: {e}")
        flash('Error setting up 2FA. Please try again.', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        ip = request.remote_addr
        
        if is_locked_out(ip, 'user_login'):
            flash('Too many failed attempts. Please try again in 15 minutes.', 'warning')
            return render_template('login.html', csrf_token=generate_csrf_token())
        
        if not validate_csrf_token():
            flash('Security token invalid. Please try again.', 'danger')
            return render_template('login.html', csrf_token=generate_csrf_token())
        
        if not check_rate_limit(ip, 'user_login', 5, 300):
            flash('Too many login attempts. Please try again in 5 minutes.', 'warning')
            return render_template('login.html', csrf_token=generate_csrf_token())
        
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            
            users = load_data(app.config['USERS_FILE'])
            user = next((u for u in users if u['username'].lower() == username.lower() and u['is_active']), None)
            
            if user and check_password_hash(user['password_hash'], password):
                # Check if 2FA is enabled
                if user.get('2fa_enabled', False):
                    # Store user ID in session for 2FA verification
                    session['pending_2fa_user'] = user['id']
                    return redirect(url_for('verify_2fa_login'))
                
                # Regular login without 2FA
                session['user_id'] = user['id']
                session['username'] = user['username']
                session.permanent = True
                flash('Logged in successfully', 'success')
                log_security_event('USER_LOGIN_SUCCESS', f'User: {username}', user['id'], ip)
                return redirect(url_for('home'))
            
            log_security_event('USER_LOGIN_FAILED', f'Username: {username}', ip=ip)
            flash('Invalid credentials', 'danger')
        except Exception as e:
            logger.error(f"Login error: {e}")
            log_security_event('LOGIN_ERROR', f'Error: {str(e)}', ip=ip)
            flash('Login failed. Please try again.', 'danger')
    
    return render_template('login.html', csrf_token=generate_csrf_token())

@app.route('/verify-2fa-login', methods=['GET', 'POST'])
def verify_2fa_login():
    """Verify 2FA code during login"""
    if 'pending_2fa_user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if not validate_csrf_token():
            flash('Security token invalid. Please try again.', 'danger')
            return render_template('verify_2fa.html', csrf_token=generate_csrf_token())
        
        token = request.form.get('token', '')
        backup_code = request.form.get('backup_code', '')
        
        users = load_data(app.config['USERS_FILE'])
        user = next((u for u in users if u['id'] == session['pending_2fa_user']), None)
        
        if not user:
            flash('User not found', 'danger')
            session.pop('pending_2fa_user', None)
            return redirect(url_for('login'))
        
        verified = False
        
        # Check backup code first
        if backup_code and backup_code in user.get('backup_codes', []):
            # Remove used backup code
            user_index = next((i for i, u in enumerate(users) if u['id'] == user['id']), -1)
            if user_index != -1:
                users[user_index]['backup_codes'] = [code for code in user['backup_codes'] if code != backup_code]
                if save_data(users, app.config['USERS_FILE']):
                    verified = True
                    log_security_event('BACKUP_CODE_USED', f'User used backup code: {backup_code}', user['id'])
        # Check regular 2FA token
        elif token and verify_2fa_token(user['2fa_secret'], token):
            verified = True
        
        if verified:
            # Complete login
            session['user_id'] = user['id']
            session['username'] = user['username']
            session.permanent = True
            session.pop('pending_2fa_user', None)
            
            flash('Logged in successfully', 'success')
            log_security_event('USER_LOGIN_SUCCESS', f'User: {user["username"]} (2FA verified)', user['id'])
            return redirect(url_for('home'))
        else:
            flash('Invalid authentication code or backup code', 'danger')
            log_security_event('2FA_FAILED', 'Invalid 2FA code during login', user['id'])
    
    return render_template('verify_2fa.html', csrf_token=generate_csrf_token())

@app.route('/profile')
def profile():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    try:
        users = load_data(app.config['USERS_FILE'])
        user = next((u for u in users if u['id'] == session['user_id']), None)
        
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('login'))
        
        # Get user's purchase history
        purchases = load_data(app.config['PURCHASES_FILE'])
        user_purchases = [p for p in purchases if p['user_id'] == session['user_id']]
        
        # Get album details for purchases
        albums = load_data(app.config['ALBUMS_FILE'])
        purchase_history = []
        
        for purchase in user_purchases:
            album = next((a for a in albums if a['id'] == purchase['album_id']), None)
            if album:
                purchase_history.append({
                    'album': album,
                    'purchase_date': purchase['purchase_date'],
                    'amount': purchase['amount'],
                    'downloads': purchase.get('downloads', 0)
                })
        
        # Generate new QR code if 2FA is not enabled
        qr_code = None
        if not user.get('2fa_enabled', False):
            qr_code = generate_2fa_qr_code(user['2fa_secret'], user['username'])
        
        return render_template('profile.html', 
                             user=user,
                             purchase_history=purchase_history,
                             qr_code=qr_code,
                             backup_codes=user.get('backup_codes', []))
    except Exception as e:
        logger.error(f"Profile error: {e}")
        flash('Error loading profile', 'danger')
        return redirect(url_for('home'))

@app.route('/generate-new-backup-codes', methods=['POST'])
def generate_new_backup_codes():
    """Generate new backup codes for 2FA"""
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    if not validate_csrf_token():
        flash('Security token invalid. Please try again.', 'danger')
        return redirect(url_for('profile'))
    
    try:
        users = load_data(app.config['USERS_FILE'])
        user_index = next((i for i, u in enumerate(users) if u['id'] == session['user_id']), -1)
        
        if user_index == -1:
            flash('User not found', 'danger')
            return redirect(url_for('login'))
        
        # Generate new backup codes
        new_backup_codes = generate_backup_codes()
        users[user_index]['backup_codes'] = new_backup_codes
        
        if save_data(users, app.config['USERS_FILE']):
            flash('New backup codes generated successfully. Please save them in a secure place.', 'success')
            log_security_event('BACKUP_CODES_REGENERATED', 'User generated new backup codes', session['user_id'])
        else:
            flash('Failed to generate new backup codes. Please try again.', 'danger')
            
    except Exception as e:
        logger.error(f"Backup code generation error: {e}")
        flash('Error generating backup codes. Please try again.', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/disable-2fa', methods=['POST'])
def disable_2fa():
    """Disable 2FA for user account"""
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    if not validate_csrf_token():
        flash('Security token invalid. Please try again.', 'danger')
        return redirect(url_for('profile'))
    
    try:
        users = load_data(app.config['USERS_FILE'])
        user_index = next((i for i, u in enumerate(users) if u['id'] == session['user_id']), -1)
        
        if user_index == -1:
            flash('User not found', 'danger')
            return redirect(url_for('login'))
        
        # Disable 2FA
        users[user_index]['2fa_enabled'] = False
        
        if save_data(users, app.config['USERS_FILE']):
            flash('Two-factor authentication disabled successfully.', 'success')
            log_security_event('2FA_DISABLED', 'User disabled 2FA', session['user_id'])
        else:
            flash('Failed to disable 2FA. Please try again.', 'danger')
            
    except Exception as e:
        logger.error(f"2FA disable error: {e}")
        flash('Error disabling 2FA. Please try again.', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/logout')
def user_logout():
    user_id = session.get('user_id')
    username = session.get('username')
    session.clear()
    flash('Logged out successfully', 'success')
    log_security_event('USER_LOGOUT', f'User: {username}', user_id)
    return redirect(url_for('home'))

# STRIPE PAYMENT PROCESSING
@app.route('/create-payment-intent/<int:album_id>', methods=['POST'])
def create_payment_intent(album_id):
    """Create a Stripe Payment Intent"""
    if not session.get('user_id'):
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        if not validate_csrf_token():
            return jsonify({'error': 'Invalid CSRF token'}), 400
        
        albums = load_data(app.config['ALBUMS_FILE'])
        album = next((a for a in albums if a['id'] == album_id), None)
        
        if not album:
            return jsonify({'error': 'Album not found'}), 404
        
        # Check if user already owns this album
        if has_purchased(session['user_id'], album_id):
            return jsonify({'error': 'You already own this album'}), 400
        
        # Get the price (use sale price if on sale)
        price = album.get('sale_price') if album.get('on_sale') else album.get('price', 0)
        amount = int(price * 100)  # Convert to cents
        
        # Create PaymentIntent
        intent = stripe.PaymentIntent.create(
            amount=amount,
            currency='usd',
            metadata={
                'user_id': session['user_id'],
                'album_id': album_id,
                'album_title': album['title'],
                'album_artist': album['artist']
            },
            automatic_payment_methods={
                'enabled': True,
            },
        )
        
        return jsonify({
            'clientSecret': intent['client_secret'],
            'amount': amount,
            'currency': 'usd'
        })
    except Exception as e:
        logger.error(f"Payment intent creation error: {e}")
        return jsonify({'error': 'Failed to create payment intent'}), 500

@app.route('/payment-success', methods=['GET', 'POST'])
def payment_success():
    """Handle successful payment"""
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    try:
        # Get payment intent ID from request
        payment_intent_id = request.args.get('payment_intent') or request.form.get('payment_intent')
        
        if not payment_intent_id:
            flash('Invalid payment information', 'danger')
            return redirect(url_for('shop'))
        
        # Retrieve payment intent from Stripe
        intent = stripe.PaymentIntent.retrieve(payment_intent_id)
        
        # Verify payment was successful
        if intent.status != 'succeeded':
            flash('Payment was not successful. Please try again.', 'danger')
            return redirect(url_for('shop'))
        
        # Get album ID from metadata
        album_id = int(intent.metadata.get('album_id'))
        
        # Record the purchase
        price = intent.amount / 100  # Convert from cents to dollars
        purchase = record_purchase(session['user_id'], album_id, price, intent.id)
        
        if purchase:
            flash(f'Purchase successful! You can now download the album.', 'success')
            log_security_event('PURCHASE_SUCCESS', f'Album: {album_id}, Amount: {price}, Stripe ID: {intent.id}', session['user_id'])
            
            # Send confirmation email
            users = load_data(app.config['USERS_FILE'])
            user = next((u for u in users if u['id'] == session['user_id']), None)
            albums = load_data(app.config['ALBUMS_FILE'])
            album = next((a for a in albums if a['id'] == album_id), None)
            
            if user and album:
                send_admin_notification(
                    "New Album Purchase",
                    f"New purchase completed:\n\n"
                    f"User: {user['username']} ({user['email']})\n"
                    f"Album: {album['title']} by {album['artist']}\n"
                    f"Amount: ${price}\n"
                    f"Stripe ID: {intent.id}"
                )
            
            return redirect(url_for('album', album_id=album_id))
        else:
            flash('Purchase recording failed. Please contact support.', 'danger')
            return redirect(url_for('shop'))
            
    except Exception as e:
        logger.error(f"Payment success handling error: {e}")
        flash('Error processing payment. Please contact support if the charge was made.', 'danger')
        return redirect(url_for('shop'))

@app.route('/payment-cancel')
def payment_cancel():
    """Handle canceled payment"""
    flash('Payment was canceled. You can try again anytime.', 'info')
    return redirect(url_for('shop'))

# Stripe webhook handler for payment events
@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    """Handle Stripe webhook events"""
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, app.config['STRIPE_WEBHOOK_SECRET']
        )
    except ValueError as e:
        # Invalid payload
        logger.error(f"Invalid webhook payload: {e}")
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        logger.error(f"Invalid webhook signature: {e}")
        return jsonify({'error': 'Invalid signature'}), 400
    
    # Handle the event
    if event['type'] == 'payment_intent.succeeded':
        payment_intent = event['data']['object']
        logger.info(f"Payment succeeded: {payment_intent['id']}")
        # Additional processing if needed
    elif event['type'] == 'payment_intent.payment_failed':
        payment_intent = event['data']['object']
        logger.warning(f"Payment failed: {payment_intent['id']}")
        # Handle failed payment
    # Add more event handlers as needed
    
    return jsonify({'success': True})

# ADMIN ROUTES
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        ip = request.remote_addr
        
        if is_locked_out(ip, 'admin_login'):
            flash('Too many failed attempts. Please try again in 15 minutes.', 'warning')
            return render_template('admin/login.html', csrf_token=generate_csrf_token())
        
        if not validate_csrf_token():
            flash('Security token invalid. Please try again.', 'danger')
            return render_template('admin/login.html', csrf_token=generate_csrf_token())
        
        if not check_rate_limit(ip, 'admin_login', 3, 300):
            flash('Too many login attempts. Please try again in 5 minutes.', 'warning')
            return render_template('admin/login.html', csrf_token=generate_csrf_token())
        
        try:
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            
            admin_password_hash = app.config['ADMIN_PASSWORD_HASH']
            
            if (username == app.config['ADMIN_USERNAME'] and 
                check_password_hash(admin_password_hash, password)):
                # Check if 2FA is required for admin
                session['pending_admin_2fa'] = True
                return redirect(url_for('admin_verify_2fa'))
            
            log_security_event('ADMIN_LOGIN_FAILED', f'Username: {username}', ip=ip)
            flash('Invalid credentials', 'danger')
        except Exception as e:
            logger.error(f"Admin login error: {e}")
            log_security_event('ADMIN_LOGIN_ERROR', f'Error: {str(e)}', ip=ip)
            flash('Login failed. Please try again.', 'danger')
    
    return render_template('admin/login.html', csrf_token=generate_csrf_token())

@app.route('/admin/verify-2fa', methods=['GET', 'POST'])
def admin_verify_2fa():
    """Verify 2FA for admin login"""
    if 'pending_admin_2fa' not in session:
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        if not validate_csrf_token():
            flash('Security token invalid. Please try again.', 'danger')
            return render_template('admin/verify_2fa.html', csrf_token=generate_csrf_token())
        
        token = request.form.get('token', '')
        
        # Verify admin 2FA token
        if verify_2fa_token(app.config['TOTP_SECRET'], token):
            session['admin_logged_in'] = True
            session.permanent = True
            session.pop('pending_admin_2fa', None)
            
            flash('Logged in successfully', 'success')
            log_security_event('ADMIN_LOGIN_SUCCESS', 'Admin logged in with 2FA')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid authentication code', 'danger')
            log_security_event('ADMIN_2FA_FAILED', 'Invalid 2FA code during admin login')
    
    return render_template('admin/verify_2fa.html', csrf_token=generate_csrf_token())

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    try:
        albums = load_data(app.config['ALBUMS_FILE'])
        users = load_data(app.config['USERS_FILE'])
        purchases = load_data(app.config['PURCHASES_FILE'])
        
        total_revenue = sum(p.get('amount', 0) for p in purchases if p.get('status') == 'completed')
        recent_purchases = sorted([p for p in purchases if p.get('status') == 'completed'], 
                                 key=lambda x: x['purchase_date'], reverse=True)[:10]
        
        # Get sales statistics
        sales_data = []
        for purchase in purchases:
            if purchase.get('status') == 'completed':
                album = next((a for a in albums if a['id'] == purchase['album_id']), None)
                if album:
                    sales_data.append({
                        'date': purchase['purchase_date'][:10],  # Just the date part
                        'amount': purchase['amount'],
                        'album': album['title']
                    })
        
        return render_template('admin/dashboard.html',
                               album_count=len(albums),
                               user_count=len(users),
                               purchase_count=len([p for p in purchases if p.get('status') == 'completed']),
                               total_revenue=total_revenue,
                               recent_purchases=recent_purchases,
                               sales_data=sales_data,
                               current_date=datetime.now().strftime("%Y-%m-%d"))
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('admin/dashboard.html', album_count=0, user_count=0, purchase_count=0, total_revenue=0)

# ... (rest of the admin routes remain the same as before)

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    
    if not debug:
        # Production settings
        app.config['SESSION_COOKIE_SECURE'] = True
        app.config['PREFERRED_URL_SCHEME'] = 'https'
    
    app.run(host='0.0.0.0', port=port, debug=debug)
