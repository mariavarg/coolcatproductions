python
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
)

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

def record_purchase(user_id, album_id, amount):
    purchases = load_data(app.config['PURCHASES_FILE'])
    
    purchase = {
        'id': secrets.token_hex(8),
        'user_id': user_id,
        'album_id': album_id,
        'amount': amount,
        'purchase_date': datetime.now().isoformat(),
        'downloads': 0
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
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob: https:; "
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
                             get_video_url=get_video_url)
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
        return render_template('album.html', album=safe_album)
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
                'is_active': True
            }
            
            users.append(new_user)
            if save_data(users, app.config['USERS_FILE']):
                flash('Registration successful. Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Registration failed. Please try again.', 'danger')
                
        except Exception as e:
            logger.error(f"Registration error: {e}")
            flash('Registration error. Please try again.', 'danger')
    
    return render_template('register.html', csrf_token=generate_csrf_token())

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

@app.route('/logout')
def user_logout():
    user_id = session.get('user_id')
    username = session.get('username')
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Logged out successfully', 'success')
    log_security_event('USER_LOGOUT', f'User: {username}', user_id)
    return redirect(url_for('home'))

@app.route('/purchase/<int:album_id>', methods=['POST'])
def purchase_album(album_id):
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    try:
        if not validate_csrf_token():
            flash('Security token invalid. Please try again.', 'danger')
            return redirect(url_for('album', album_id=album_id))
        
        albums = load_data(app.config['ALBUMS_FILE'])
        album = next((a for a in albums if a['id'] == album_id), None)
        
        if not album:
            flash('Album not found', 'danger')
            return redirect(url_for('shop'))
        
        # Check if user already owns this album
        if has_purchased(session['user_id'], album_id):
            flash('You already own this album', 'info')
            return redirect(url_for('album', album_id=album_id))
        
        # Get the price (use sale price if on sale)
        price = album.get('sale_price') if album.get('on_sale') else album.get('price', 0)
        
        # Record the purchase
        purchase = record_purchase(session['user_id'], album_id, price)
        
        if purchase:
            flash(f'Purchase successful! You can now download the album.', 'success')
            log_security_event('PURCHASE_SUCCESS', f'Album: {album_id}, Amount: {price}', session['user_id'])
            return redirect(url_for('album', album_id=album_id))
        else:
            flash('Purchase failed. Please try again.', 'danger')
            return redirect(url_for('album', album_id=album_id))
            
    except Exception as e:
        logger.error(f"Purchase error: {e}")  # Fixed the missing closing brace here
        log_security_event('PURCHASE_ERROR', f'Album: {album_id}, Error: {str(e)}', session.get('user_id'))
        flash('Purchase error. Please try again.', 'danger')
        return redirect(url_for('album', album_id=album_id))

@app.route('/download/<int:album_id>')
def download_album(album_id):
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    # Check if user owns this album
    if not has_purchased(session['user_id'], album_id):
        flash('You need to purchase this album before downloading', 'danger')
        return redirect(url_for('album', album_id=album_id))
    
    # Generate download token
    token = generate_download_token(session['user_id'], album_id)
    
    # Redirect to download with token
    return redirect(url_for('download_with_token', token=token))

@app.route('/download/token/<token>')
def download_with_token(token):
    # Validate token
    token_data = validate_download_token(token)
    if not token_data:
        flash('Invalid or expired download link', 'danger')
        return redirect(url_for('shop'))
    
    # Get album data
    albums = load_data(app.config['ALBUMS_FILE'])
    album = next((a for a in albums if a['id'] == token_data['album_id']), None)
    
    if not album:
        flash('Album not found', 'danger')
        return redirect(url_for('shop'))
    
    # Update download count
    purchases = load_data(app.config['PURCHASES_FILE'])
    for purchase in purchases:
        if purchase['user_id'] == token_data['user_id'] and purchase['album_id'] == token_data['album_id']:
            purchase['downloads'] = purchase.get('downloads', 0) + 1
            break
    
    save_data(purchases, app.config['PURCHASES_FILE'])
    
    # Create zip file with all tracks
    # This is a simplified version - you might want to use a proper zip library
    try:
        album_dir = os.path.join(app.config['MUSIC_FOLDER'], f"album_{album['id']}")
        
        # For now, we'll just redirect to the first track
        # In a real implementation, you would create a zip file with all tracks
        if album.get('tracks'):
            first_track = get_track_filename(album['id'], 0, album['tracks'][0])
            track_path = os.path.join(album_dir, first_track)
            
            if os.path.exists(track_path) and is_safe_path(app.config['MUSIC_FOLDER'], track_path):
                log_security_event('DOWNLOAD_SUCCESS', f'Album: {album["id"]}, Track: {first_track}', token_data['user_id'])
                return send_file(track_path, as_attachment=True)
        
        flash('Download failed: files not found', 'danger')
        return redirect(url_for('album', album_id=album['id']))
    except Exception as e:
        logger.error(f"Download error: {e}")
        log_security_event('DOWNLOAD_ERROR', f'Album: {album["id"]}, Error: {str(e)}', token_data['user_id'])
        flash('Download error. Please try again.', 'danger')
        return redirect(url_for('album', album_id=album['id']))

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
                session['admin_logged_in'] = True
                session.permanent = True
                flash('Logged in successfully', 'success')
                log_security_event('ADMIN_LOGIN_SUCCESS', 'Admin logged in', ip=ip)
                return redirect(url_for('admin_dashboard'))
            
            log_security_event('ADMIN_LOGIN_FAILED', f'Username: {username}', ip=ip)
            flash('Invalid credentials', 'danger')
        except Exception as e:
            logger.error(f"Admin login error: {e}")
            log_security_event('ADMIN_LOGIN_ERROR', f'Error: {str(e)}', ip=ip)
            flash('Login failed. Please try again.', 'danger')
    
    return render_template('admin/login.html', csrf_token=generate_csrf_token())

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('csrf_token', None)
    flash('Logged out successfully', 'success')
    log_security_event('ADMIN_LOGOUT', 'Admin logged out')
    return redirect(url_for('home'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    try:
        albums = load_data(app.config['ALBUMS_FILE'])
        users = load_data(app.config['USERS_FILE'])
        purchases = load_data(app.config['PURCHASES_FILE'])
        
        total_revenue = sum(p.get('amount', 0) for p in purchases)
        recent_purchases = sorted(purchases, key=lambda x: x['purchase_date'], reverse=True)[:10]
        
        return render_template('admin/dashboard.html',
                               album_count=len(albums),
                               user_count=len(users),
                               purchase_count=len(purchases),
                               total_revenue=total_revenue,
                               recent_purchases=recent_purchases,
                               current_date=datetime.now().strftime("%Y-%m-%d"))
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('admin/dashboard.html', album_count=0, user_count=0, purchase_count=0, total_revenue=0)

# Enhanced album management with better video handling
@app.route('/admin/add-album', methods=['GET', 'POST'])
def add_album():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        try:
            if not validate_csrf_token():
                flash('Security token invalid. Please try again.', 'danger')
                return render_template('admin/add_album.html', csrf_token=generate_csrf_token())
            
            albums = load_data(app.config['ALBUMS_FILE'])
            cover = request.files.get('cover')
            music_files = request.files.getlist('music_files')
            video_file = request.files.get('video_file')
            video_category = request.form.get('video_category', 'music_videos')
            
            if not cover or cover.filename == '':
                flash('No cover image selected', 'danger')
                return redirect(request.url)
                
            if not allowed_file(cover.filename, 'image'):
                flash('Invalid cover image type', 'danger')
                return redirect(request.url)
                
            if not allowed_file_size(cover):
                flash('Cover image is too large (max 50MB)', 'danger')
                return redirect(request.url)
            
            # Handle video upload
            video_filename = None
            if video_file and video_file.filename:
                if allowed_video_file(video_file.filename) and allowed_file_size(video_file, app.config['MAX_VIDEO_SIZE']):
                    # Create category directory if it doesn't exist
                    category_dir = os.path.join(app.config['VIDEOS_FOLDER'], video_category)
                    os.makedirs(category_dir, exist_ok=True)
                    
                    video_filename = secure_filename(f"{int(time.time())}_{video_file.filename}")
                    video_path = os.path.join(category_dir, video_filename)
                    video_file.save(video_path)
                    
                    # Verify it's actually a video file
                    if not is_safe_path(app.config['VIDEOS_FOLDER'], video_path):
                        os.remove(video_path)
                        flash('Invalid video file path', 'danger')
                        return redirect(request.url)
                else:
                    flash(f'Invalid video file type or file too large (max {app.config["MAX_VIDEO_SIZE"] // (1024*1024)}MB)', 'danger')
                    return redirect(request.url)
            
            if not music_files or all(f.filename == '' for f in music_files):
                flash('No music files selected', 'danger')
                return redirect(request.url)
                
            track_list = [t.strip() for t in request.form.get('tracks', '').split('\n') if t.strip()]
            mp3_files = [f for f in music_files if f.filename]
            
                       if len(track_list) != len(mp3_files):
                flash(f'Error: You listed {len(track_list)} tracks but uploaded {len(mp3_files)} MP3 files. They must match!', 'danger')
                return redirect(request.url)
                
            for music_file in mp3_files:
                if not allowed_file(music_file.filename, 'music'):
                    flash('Invalid music file type. Use MP3, WAV, or FLAC.', 'danger')
                    return redirect(request.url)
                if not allowed_file_size(music_file, 100):
                    flash(f'Music file {music_file.filename} is too large (max 100MB)', 'danger')
                    return redirect(request.url)
            
            filename = secure_filename(cover.filename)
            cover_path = os.path.join(app.config['COVERS_FOLDER'], filename)
            cover.save(cover_path)
            
            # Simplified image validation - just check if file exists
            if not os.path.exists(cover_path) or not is_safe_path(app.config['COVERS_FOLDER'], cover_path):
                if os.path.exists(cover_path):
                    os.remove(cover_path)
                flash('Invalid image file', 'danger')
                return redirect(request.url)
            
            new_album = {
                'id': len(albums) + 1,
                'title': escape(request.form.get('title', '').strip()),
                'artist': escape(request.form.get('artist', '').strip()),
                'year': escape(request.form.get('year', '').strip()),
                'cover': os.path.join('uploads', 'covers', filename).replace('\\', '/'),
                'tracks': track_list,
                'added': datetime.now().strftime("%Y-%m-%d"),
                'price': round(float(request.form.get('price', 0)), 2),
                'on_sale': 'on_sale' in request.form,
                'sale_price': round(float(request.form.get('sale_price', 0)), 2) if request.form.get('sale_price') else None,
                'video_filename': video_filename,
                'video_category': video_category if video_filename else None,
                'has_video': bool(video_filename)
            }
            
            album_dir = ensure_music_dirs_exist(new_album['id'])
            
            track_paths = []
            for i, music_file in enumerate(mp3_files):
                track_name = new_album['tracks'][i]
                mp3_filename = get_track_filename(new_album['id'], i, track_name)
                music_path = os.path.join(album_dir, mp3_filename)
                music_file.save(music_path)
                track_paths.append(music_path)
                
                # Verify the file path is safe
                if not is_safe_path(app.config['MUSIC_FOLDER'], music_path):
                    os.remove(music_path)
                    flash(f'Invalid file path for track: {track_name}', 'danger')
                    # Clean up all uploaded tracks
                    for track_path in track_paths:
                        if os.path.exists(track_path):
                            os.remove(track_path)
                    return redirect(request.url)
                
                logger.info(f"Saved track {i+1}: {mp3_filename} → {track_name}")
            
            albums.append(new_album)
            if save_data(albums, app.config['ALBUMS_FILE']):
                flash('Album and music files added successfully! Tracks are in correct order.', 'success')
                log_security_event('ALBUM_ADDED', f'Album: {new_album["title"]}, ID: {new_album["id"]}')
                return redirect(url_for('shop'))
            else:
                for track_path in track_paths:
                    if os.path.exists(track_path):
                        os.remove(track_path)
                flash('Failed to save album', 'danger')
                
        except ValueError:
            flash('Invalid price format', 'danger')
        except Exception as e:
            logger.error(f"Add album error: {e}")
            log_security_event('ALBUM_ADD_ERROR', f'Error: {str(e)}')
            flash('Error adding album. Please try again.', 'danger')
    
    return render_template('admin/add_album.html', csrf_token=generate_csrf_token())

@app.route('/admin/manage-albums')
def manage_albums():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    try:
        albums = load_data(app.config['ALBUMS_FILE'])
        return render_template('admin/manage_albums.html', albums=albums)
    except Exception as e:
        logger.error(f"Manage albums error: {e}")
        return render_template('admin/manage_albums.html', albums=[])

@app.route('/admin/delete-album/<int:album_id>')
def delete_album(album_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    try:
        albums = load_data(app.config['ALBUMS_FILE'])
        album = next((a for a in albums if a['id'] == album_id), None)
        
        if not album:
            flash('Album not found', 'danger')
            return redirect(url_for('manage_albums'))
        
        # Remove album cover
        cover_path = os.path.join('static', album['cover'])
        if os.path.exists(cover_path) and is_safe_path('static/uploads', cover_path):
            os.remove(cover_path)
        
        # Remove music files
        music_dir = os.path.join(app.config['MUSIC_FOLDER'], f"album_{album_id}")
        if os.path.exists(music_dir) and is_safe_path(app.config['MUSIC_FOLDER'], music_dir):
            import shutil
            shutil.rmtree(music_dir)
        
        # Remove video file if exists
        if album.get('video_filename'):
            video_category = album.get('video_category', 'music_videos')
            video_path = os.path.join(app.config['VIDEOS_FOLDER'], video_category, album['video_filename'])
            if os.path.exists(video_path) and is_safe_path(app.config['VIDEOS_FOLDER'], video_path):
                os.remove(video_path)
        
        # Remove from albums list
        albums = [a for a in albums if a['id'] != album_id]
        
        if save_data(albums, app.config['ALBUMS_FILE']):
            flash('Album deleted successfully', 'success')
            log_security_event('ALBUM_DELETED', f'Album ID: {album_id}')
        else:
            flash('Failed to delete album', 'danger')
            
    except Exception as e:
        logger.error(f"Delete album error: {e}")
        log_security_event('ALBUM_DELETE_ERROR', f'Album ID: {album_id}, Error: {str(e)}')
        flash('Error deleting album', 'danger')
    
    return redirect(url_for('manage_albums'))

@app.route('/admin/edit-album/<int:album_id>', methods=['GET', 'POST'])
def edit_album(album_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    albums = load_data(app.config['ALBUMS_FILE'])
    album = next((a for a in albums if a['id'] == album_id), None)
    
    if not album:
        flash('Album not found', 'danger')
        return redirect(url_for('manage_albums'))
    
    if request.method == 'POST':
        try:
            if not validate_csrf_token():
                flash('Security token invalid. Please try again.', 'danger')
                return render_template('admin/edit_album.html', album=album, csrf_token=generate_csrf_token())
            
            # Update album data
            album_index = next((i for i, a in enumerate(albums) if a['id'] == album_id), -1)
            
            if album_index != -1:
                # Handle new cover upload if provided
                cover = request.files.get('cover')
                if cover and cover.filename:
                    if allowed_file(cover.filename, 'image') and allowed_file_size(cover):
                        # Remove old cover
                        old_cover_path = os.path.join('static', albums[album_index]['cover'])
                        if os.path.exists(old_cover_path) and is_safe_path('static/uploads', old_cover_path):
                            os.remove(old_cover_path)
                        
                        # Save new cover
                        filename = secure_filename(cover.filename)
                        cover_path = os.path.join(app.config['COVERS_FOLDER'], filename)
                        cover.save(cover_path)
                        
                        # Simplified image validation
                        if os.path.exists(cover_path) and is_safe_path(app.config['COVERS_FOLDER'], cover_path):
                            albums[album_index]['cover'] = os.path.join('uploads', 'covers', filename).replace('\\', '/')
                        else:
                            if os.path.exists(cover_path):
                                os.remove(cover_path)
                            flash('Invalid image file', 'danger')
                    else:
                        flash('Invalid cover image type or file too large', 'danger')
                
                # Handle new video upload if provided
                video_file = request.files.get('video_file')
                video_category = request.form.get('video_category', 'music_videos')
                if video_file and video_file.filename:
                    if allowed_video_file(video_file.filename) and allowed_file_size(video_file, app.config['MAX_VIDEO_SIZE']):
                        # Remove old video if exists
                        if albums[album_index].get('video_filename'):
                            old_video_category = albums[album_index].get('video_category', 'music_videos')
                            old_video_path = os.path.join(app.config['VIDEOS_FOLDER'], old_video_category, albums[album_index]['video_filename'])
                            if os.path.exists(old_video_path) and is_safe_path(app.config['VIDEOS_FOLDER'], old_video_path):
                                os.remove(old_video_path)
                        
                        # Create category directory if it doesn't exist
                        category_dir = os.path.join(app.config['VIDEOS_FOLDER'], video_category)
                        os.makedirs(category_dir, exist_ok=True)
                        
                        # Save new video
                        video_filename = secure_filename(f"{int(time.time())}_{video_file.filename}")
                        video_path = os.path.join(category_dir, video_filename)
                        video_file.save(video_path)
                        
                        if is_safe_path(app.config['VIDEOS_FOLDER'], video_path):
                            albums[album_index]['video_filename'] = video_filename
                            albums[album_index]['video_category'] = video_category
                            albums[album_index]['has_video'] = True
                        else:
                            os.remove(video_path)
                            flash('Invalid video file path', 'danger')
                    else:
                        flash(f'Invalid video file type or file too large (max {app.config["MAX_VIDEO_SIZE"] // (1024*1024)}MB)', 'danger')
                
                # Update other fields
                albums[album_index]['title'] = escape(request.form.get('title', '').strip())
                albums[album_index]['artist'] = escape(request.form.get('artist', '').strip())
                albums[album_index]['year'] = escape(request.form.get('year', '').strip())
                albums[album_index]['price'] = round(float(request.form.get('price', 0)), 2)
                albums[album_index]['on_sale'] = 'on_sale' in request.form
                albums[album_index]['sale_price'] = round(float(request.form.get('sale_price', 0)), 2) if request.form.get('sale_price') else None
                
                # Remove video if requested
                if 'remove_video' in request.form:
                    if albums[album_index].get('video_filename'):
                        video_category = albums[album_index].get('video_category', 'music_videos')
                        video_path = os.path.join(app.config['VIDEOS_FOLDER'], video_category, albums[album_index]['video_filename'])
                        if os.path.exists(video_path) and is_safe_path(app.config['VIDEOS_FOLDER'], video_path):
                            os.remove(video_path)
                    albums[album_index]['video_filename'] = None
                    albums[album_index]['video_category'] = None
                    albums[album_index]['has_video'] = False
                
                if save_data(albums, app.config['ALBUMS_FILE']):
                    flash('Album updated successfully', 'success')
                    log_security_event('ALBUM_UPDATED', f'Album ID: {album_id}')
                    return redirect(url_for('manage_albums'))
                else:
                    flash('Failed to update album', 'danger')
            else:
                flash('Album not found in database', 'danger')
            
        except ValueError:
            flash('Invalid price format', 'danger')
        except Exception as e:
            logger.error(f"Edit album error: {e}")
            log_security_event('ALBUM_UPDATE_ERROR', f'Album ID: {album_id}, Error: {str(e)}')
            flash('Error updating album', 'danger')
    
    return render_template('admin/edit_album.html', album=album, csrf_token=generate_csrf_token())

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    
    if not debug:
        # Production settings
        app.config['SESSION_COOKIE_SECURE'] = True
        app.config['PREFERRED_URL_SCHEME'] = 'https'
    
    app.run(host='0.0.0.0', port=port, debug=debug)
