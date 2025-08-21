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
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_file, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from markupsafe import escape

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY', 'dev-key-' + secrets.token_hex(16)),
    USERS_FILE=os.path.join('data', 'users.json'),
    ALBUMS_FILE=os.path.join('data', 'albums.json'),
    PURCHASES_FILE=os.path.join('data', 'purchases.json'),
    COVERS_FOLDER=os.path.join('static', 'uploads', 'covers'),
    MUSIC_FOLDER=os.path.join('static', 'uploads', 'music'),
    VIDEOS_FOLDER=os.path.join('static', 'uploads', 'videos'),
    UPLOAD_FOLDER='static/uploads',
    ALLOWED_EXTENSIONS={'png', 'jpg', 'jpeg', 'webp'},
    ALLOWED_MUSIC_EXTENSIONS={'mp3', 'wav', 'flac'},
    ALLOWED_VIDEO_EXTENSIONS={'mp4', 'mov', 'avi', 'webm'},
    ADMIN_USERNAME=os.getenv('ADMIN_USERNAME', 'admin'),
    ADMIN_PASSWORD_HASH=os.getenv('ADMIN_PASSWORD_HASH', ''),
    MAX_CONTENT_LENGTH=500 * 1024 * 1024,
    PERMANENT_SESSION_LIFETIME=3600,
    DOWNLOAD_TOKENS={},
    VIDEO_STREAM_CHUNK_SIZE=1024 * 1024
)

# Security setup
login_attempts = {}

def generate_csrf_token():
    token = hashlib.sha256(f"{time.time()}{app.secret_key}".encode()).hexdigest()
    session['csrf_token'] = token
    return token

def validate_csrf_token():
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return True
    token = request.form.get('csrf_token')
    return token and token == session.get('csrf_token')

def check_rate_limit(ip, endpoint, max_attempts=5, window=60):
    now = time.time()
    key = f"{ip}_{endpoint}"
    
    if key not in login_attempts:
        login_attempts[key] = []
    
    login_attempts[key] = [t for t in login_attempts[key] if now - t < window]
    
    if len(login_attempts[key]) >= max_attempts:
        return False
        
    login_attempts[key].append(now)
    return True

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
        'expiry': expiry.strftime("%Y-%m-%d %H:%M:%S")
    }
    return token

def validate_download_token(token):
    if token not in app.config['DOWNLOAD_TOKENS']:
        return False
        
    token_data = app.config['DOWNLOAD_TOKENS'][token]
    expiry = datetime.strptime(token_data['expiry'], "%Y-%m-%d %H:%M:%S")
    
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
        'id': len(purchases) + 1,
        'user_id': user_id,
        'album_id': album_id,
        'amount': amount,
        'purchase_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
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

# Password strength validation
def is_password_complex(password):
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is strong"

# Generate strong password
def generate_strong_password(length=16):
    """Generate a cryptographically secure random password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

# Video file validation
def allowed_video_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_VIDEO_EXTENSIONS']

# Get video URL for templates
def get_video_url(album):
    if album.get('video_filename'):
        return url_for('protected_video', filename=album['video_filename'])
    return album.get('video_url', '')

# Initialize app setup with backup system
def initialize_app():
    try:
        os.makedirs('data', exist_ok=True)
        os.makedirs(app.config['COVERS_FOLDER'], exist_ok=True)
        os.makedirs(app.config['MUSIC_FOLDER'], exist_ok=True)
        os.makedirs(app.config['VIDEOS_FOLDER'], exist_ok=True)
        
        # Create backup directory
        os.makedirs('data/backups', exist_ok=True)
        
        for data_file in [app.config['USERS_FILE'], app.config['ALBUMS_FILE'], app.config['PURCHASES_FILE']]:
            if not os.path.exists(data_file):
                with open(data_file, 'w') as f:
                    json.dump([], f)
            # Create backup
            backup_file = f"data/backups/{os.path.basename(data_file)}.backup"
            if os.path.exists(data_file) and not os.path.exists(backup_file):
                with open(data_file, 'r') as src, open(backup_file, 'w') as dst:
                    dst.write(src.read())
                
    except Exception as e:
        logger.error(f"Initialization error: {str(e)}")

initialize_app()

# Helper functions with enhanced error handling
def allowed_file(filename, file_type='image'):
    if file_type == 'image':
        extensions = app.config['ALLOWED_EXTENSIONS']
    elif file_type == 'music':
        extensions = app.config['ALLOWED_MUSIC_EXTENSIONS']
    elif file_type == 'video':
        extensions = app.config['ALLOWED_VIDEO_EXTENSIONS']
    else:
        return False
        
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in extensions

def load_data(filename):
    try:
        if os.path.exists(filename):
            with open(filename) as f:
                return json.load(f)
        return []
    except Exception as e:
        logger.error(f"Error loading {filename}: {e}")
        # Try to restore from backup
        backup_file = f"data/backups/{os.path.basename(filename)}.backup"
        if os.path.exists(backup_file):
            try:
                with open(backup_file) as f:
                    data = json.load(f)
                # Save back to main file
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
                return data
            except Exception as backup_error:
                logger.error(f"Backup restoration also failed: {backup_error}")
        return []

def save_data(data, filename):
    try:
        # Create backup before saving
        backup_file = f"data/backups/{os.path.basename(filename)}.backup"
        if os.path.exists(filename):
            with open(filename, 'r') as src, open(backup_file, 'w') as dst:
                dst.write(src.read())
        
        # Save new data
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving {filename}: {e}")
        return False

def is_valid_image(file_path):
    try:
        with open(file_path, 'rb') as f:
            header = f.read(12)
        
        if (header.startswith(b'\xFF\xD8\xFF') or
            header.startswith(b'\x89PNG\r\n\x1a\n') or
            (header[:4] == b'RIFF' and header[8:12] == b'WEBP')):
            return True
            
        return False
    except:
        return False

def allowed_file_size(file, max_size_mb=50):
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    return file_size <= max_size_mb * 1024 * 1024

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Add CSP to prevent various attacks
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "media-src 'self' blob:; "
        "frame-ancestors 'none'; "
        "form-action 'self';"
    )
    
    if not app.debug:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# HTTPS enforcement in production
@app.before_request
def enforce_https_in_production():
    if not app.debug and not request.is_secure and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
        url = request.url.replace('http://', 'https://', 1)
        code = 301
        return redirect(url, code=code)

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500

@app.errorhandler(413)
def too_large(e):
    return render_template('413.html'), 413

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

# Favicon route
@app.route('/favicon.ico')
def favicon():
    try:
        return send_file('static/images/channel-logo.png', mimetype='image/png')
    except:
        return '', 204

# Protected video streaming route
@app.route('/protected-video/<filename>')
def protected_video(filename):
    if not session.get('user_id'):
        abort(403)
    
    # Verify the user has access to this video
    albums = load_data(app.config['ALBUMS_FILE'])
    user_has_access = any(
        album.get('video_filename') == filename and 
        has_purchased(session['user_id'], album['id']) 
        for album in albums
    )
    
    if not user_has_access:
        abort(403)
    
    video_path = os.path.join(app.config['VIDEOS_FOLDER'], filename)
    
    if not os.path.exists(video_path):
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
                    206,  # Partial Content
                    mimetype=mimetypes.guess_type(video_path)[0], 
                    direct_passthrough=True)
        rv.headers.add('Content-Range', f'bytes {byte1}-{byte1 + length - 1}/{file_size}')
        rv.headers.add('Accept-Ranges', 'bytes')
        rv.headers.add('Content-Length', str(length))
        
        # Add security headers to prevent download
        rv.headers.add('Content-Disposition', 'inline')
        rv.headers.add('X-Content-Type-Options', 'nosniff')
        
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
        
        # Add security headers to prevent download
        rv.headers.add('Content-Disposition', 'inline')
        rv.headers.add('X-Content-Type-Options', 'nosniff')
        
        return rv

# Routes
@app.route('/')
def home():
    try:
        albums = load_data(app.config['ALBUMS_FILE'])
        albums = remove_auto_durations(albums)
        
        # Get albums with videos for featured section (only uploaded videos, not YouTube)
        featured_albums = [a for a in albums if a.get('has_video', False) and a.get('video_filename')][:3]
        regular_albums = [a for a in albums if not a.get('has_video', False)][:6]
        
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

@app.route('/album/<int:album_id>')
def album(album_id):
    try:
        albums = load_data(app.config['ALBUMS_FILE'])
        album = next((a for a in albums if a['id'] == album_id), None)
        if not album:
            abort(404)
        
        album['tracks'] = [track.split(' (')[0].strip() for track in album.get('tracks', [])]
        
        owns_album = False
        video_accessible = False
        if session.get('user_id'):
            owns_album = has_purchased(session['user_id'], album_id)
            video_accessible = owns_album  # Only owners can access videos
        
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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            if not validate_csrf_token():
                flash('Security token invalid. Please try again.', 'danger')
                return render_template('register.html', csrf_token=generate_csrf_token())
            
            users = load_data(app.config['USERS_FILE'])
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            if not username or not email or not password:
                flash('All fields are required', 'danger')
            elif len(username) < 4:
                flash('Username must be at least 4 characters', 'danger')
            elif not re.match(r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                flash('Please enter a valid email address', 'danger')
            else:
                # Check password complexity
                is_complex, complexity_msg = is_password_complex(password)
                if not is_complex:
                    flash(complexity_msg, 'danger')
                elif password != confirm_password:
                    flash('Passwords do not match', 'danger')
                elif any(u['username'] == username for u in users):
                    flash('Username already exists', 'danger')
                elif any(u['email'] == email for u in users):
                    flash('Email already registered', 'danger')
                else:
                    new_user = {
                        'id': len(users) + 1,
                        'username': escape(username),
                        'email': escape(email),
                        'password': generate_password_hash(password),
                        'joined': datetime.now().strftime("%Y-%m-%d")
                    }
                    users.append(new_user)
                    if save_data(users, app.config['USERS_FILE']):
                        session['user_id'] = new_user['id']
                        session['username'] = new_user['username']
                        flash('Registration successful! You are now logged in.', 'success')
                        return redirect(url_for('home'))
                    else:
                        flash('Registration failed. Please try again.', 'danger')
                    
        except Exception as e:
            logger.error(f"Registration error: {e}")
            flash('Registration error occurred', 'danger')
    
    return render_template('register.html', csrf_token=generate_csrf_token())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            if not validate_csrf_token():
                flash('Security token invalid. Please try again.', 'danger')
                return render_template('login.html', csrf_token=generate_csrf_token())
            
            users = load_data(app.config['USERS_FILE'])
            username = request.form.get('username', '').strip())
            password = request.form.get('password', '')
            
            user = next((u for u in users if u['username'] == username), None)
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid username or password', 'danger')
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('Login error occurred', 'danger')
    
    return render_template('login.html', csrf_token=generate_csrf_token())

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# Music Purchase & Download System
@app.route('/purchase/<int:album_id>')
def purchase_album(album_id):
    if not session.get('user_id'):
        flash('Please login to purchase music', 'danger')
        return redirect(url_for('login'))
    
    albums = load_data(app.config['ALBUMS_FILE'])
    album = next((a for a in albums if a['id'] == album_id), None)
    
    if not album:
        flash('Album not found', 'danger')
        return redirect(url_for('shop'))
    
    if has_purchased(session['user_id'], album_id):
        flash('You already own this album!', 'info')
        return redirect(url_for('my_music'))
    
    purchase = record_purchase(session['user_id'], album_id, album.get('price', 0))
    token = generate_download_token(session['user_id'], album_id)
    
    flash(f'Purchase successful! ${album.get("price", 0):.2f} paid. You can now download the music.', 'success')
    return redirect(url_for('download_album', token=token))

@app.route('/my-music')
def my_music():
    if not session.get('user_id'):
        flash('Please login to view your music', 'danger')
        return redirect(url_for('login'))
    
    purchases = load_data(app.config['PURCHASES_FILE'])
    user_purchases = [p for p in purchases if p['user_id'] == session['user_id']]
    
    albums = load_data(app.config['ALBUMS_FILE'])
    user_albums = []
    
    for purchase in user_purchases:
        album = next((a for a in albums if a['id'] == purchase['album_id']), None)
        if album:
            album['purchase_date'] = purchase['purchase_date']
            album['downloads'] = purchase['downloads']
            user_albums.append(album)
    
    return render_template('my_music.html', albums=user_albums, get_video_url=get_video_url)

@app.route('/download/<token>')
def download_album(token):
    token_data = validate_download_token(token)
    
    if not token_data:
        flash('Invalid or expired download link', 'danger')
        return redirect(url_for('shop'))
    
    if session.get('user_id') != token_data['user_id']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('shop'))
    
    albums = load_data(app.config['ALBUMS_FILE'])
    album = next((a for a in albums if a['id'] == token_data['album_id']), None)
    
    if not album:
        flash('Album not found', 'danger')
        return redirect(url_for('shop'))
    
    album['tracks'] = [track.split(' (')[0].strip() for track in album.get('tracks', [])]
    
    return render_template('download.html', album=album, token=token, get_video_url=get_video_url)

@app.route('/download-track/<token>/<int:track_index>')
def download_track(token, track_index):
    token_data = validate_download_token(token)
    
    if not token_data:
        flash('Invalid or expired download link', 'danger')
        return redirect(url_for('shop'))
    
    if session.get('user_id') != token_data['user_id']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('shop'))
    
    albums = load_data(app.config['ALBUMS_FILE'])
    album = next((a for a in albums if a['id'] == token_data['album_id']), None)
    
    if not album or track_index >= len(album.get('tracks', [])):
        flash('Track not found', 'danger')
        return redirect(url_for('shop'))
    
    track_name = album['tracks'][track_index].split(' (')[0].strip()
    mp3_path = get_track_path(album['id'], track_index, track_name)
    
    if not os.path.exists(mp3_path):
        flash('Music file not available yet', 'danger')
        return redirect(url_for('download_album', token=token))
    
    purchases = load_data(app.config['PURCHASES_FILE'])
    for purchase in purchases:
        if purchase['user_id'] == session['user_id'] and purchase['album_id'] == album['id']:
            purchase['downloads'] += 1
            break
    save_data(purchases, app.config['PURCHASES_FILE'])
    
    return send_file(
        mp3_path,
        as_attachment=True,
        download_name=f"{track_name}.mp3",
        mimetype='audio/mpeg'
    )

# ADMIN ROUTES
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        if not check_rate_limit(request.remote_addr, 'login'):
            flash('Too many login attempts. Please wait 1 minute.', 'warning')
            return render_template('admin/login.html', csrf_token=generate_csrf_token())
        
        if not validate_csrf_token():
            flash('Security token invalid. Please try again.', 'danger')
            return render_template('admin/login.html', csrf_token=generate_csrf_token())
        
        try:
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            
            # Check if we're using hashed password from env or need to hash
            admin_password_hash = app.config['ADMIN_PASSWORD_HASH']
            
            if (username == app.config['ADMIN_USERNAME'] and 
                (check_password_hash(admin_password_hash, password) or 
                 (not admin_password_hash and password == os.getenv('ADMIN_PASSWORD', '')))):
                session['admin_logged_in'] = True
                session.permanent = True
                flash('Logged in successfully', 'success')
                return redirect(url_for('admin_dashboard'))
            
            flash('Invalid credentials', 'danger')
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('Login failed. Please try again.', 'danger')
    
    return render_template('admin/login.html', csrf_token=generate_csrf_token())

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('csrf_token', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('home'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    try:
        albums = load_data(app.config['ALBUMS_FILE'])
        users = load_data(app.config['USERS_FILE'])
        purchases = load_data(app.config['PURCHASES_FILE'])
        
        # Calculate total revenue
        total_revenue = sum(p.get('amount', 0) for p in purchases)
        
        return render_template('admin/dashboard.html',
                               album_count=len(albums),
                               user_count=len(users),
                               purchase_count=len(purchases),
                               total_revenue=total_revenue,
                               current_date=datetime.now().strftime("%Y-%m-%d"))
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('admin/dashboard.html', album_count=0, user_count=0, purchase_count=0, total_revenue=0)

@app.route('/admin/add-album', methods=['GET', 'POST'])
def add_album():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        if not validate_csrf_token():
            flash('Security token invalid. Please try again.', 'danger')
            return render_template('admin/add_album.html', csrf_token=generate_csrf_token())
        
        try:
            albums = load_data(app.config['ALBUMS_FILE'])
            cover = request.files.get('cover')
            music_files = request.files.getlist('music_files')
            video_file = request.files.get('video_file')  # New: video upload
            
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
                if allowed_video_file(video_file.filename) and allowed_file_size(video_file, 500):  # 500MB max for videos
                    video_filename = secure_filename(f"album_{len(albums) + 1}_{video_file.filename}")
                    video_path = os.path.join(app.config['VIDEOS_FOLDER'], video_filename)
                    video_file.save(video_path)
                else:
                    flash('Invalid video file type or file too large (max 500MB)', 'danger')
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
                if not allowed_file_size(music_file, 100):  # 100MB max for music files
                    flash(f'Music file {music_file.filename} is too large (max 100MB)', 'danger')
                    return redirect(request.url)
            
            filename = secure_filename(cover.filename)
            cover_path = os.path.join(app.config['COVERS_FOLDER'], filename)
            cover.save(cover_path)
            
            if not is_valid_image(cover_path):
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
                
                logger.info(f"Saved track {i+1}: {mp3_filename} → {track_name}")
            
            albums.append(new_album)
            if save_data(albums, app.config['ALBUMS_FILE']):
                flash('Album and music files added successfully! Tracks are in correct order.', 'success')
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
        if os.path.exists(cover_path):
            os.remove(cover_path)
        
        # Remove music files
        music_dir = os.path.join(app.config['MUSIC_FOLDER'], f"album_{album_id}")
        if os.path.exists(music_dir):
            import shutil
            shutil.rmtree(music_dir)
        
        # Remove video file if exists
        if album.get('video_filename'):
            video_path = os.path.join(app.config['VIDEOS_FOLDER'], album['video_filename'])
            if os.path.exists(video_path):
                os.remove(video_path)
        
        # Remove from albums list
        albums = [a for a in albums if a['id'] != album_id]
        
        if save_data(albums, app.config['ALBUMS_FILE']):
            flash('Album deleted successfully', 'success')
        else:
            flash('Failed to delete album', 'danger')
            
    except Exception as e:
        logger.error(f"Delete album error: {e}")
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
                        if os.path.exists(old_cover_path):
                            os.remove(old_cover_path)
                        
                        # Save new cover
                        filename = secure_filename(cover.filename)
                        cover_path = os.path.join(app.config['COVERS_FOLDER'], filename)
                        cover.save(cover_path)
                        
                        if is_valid_image(cover_path):
                            albums[album_index]['cover'] = os.path.join('uploads', 'covers', filename).replace('\\', '/')
                        else:
                            os.remove(cover_path)
                            flash('Invalid image file', 'danger')
                    else:
                        flash('Invalid cover image type or file too large', 'danger')
                
                # Handle new video upload if provided
                video_file = request.files.get('video_file')
                if video_file and video_file.filename:
                    if allowed_video_file(video_file.filename) and allowed_file_size(video_file, 500):
                        # Remove old video if exists
                        if albums[album_index].get('video_filename'):
                            old_video_path = os.path.join(app.config['VIDEOS_FOLDER'], albums[album_index]['video_filename'])
                            if os.path.exists(old_video_path):
                                os.remove(old_video_path)
                        
                        # Save new video
                        video_filename = secure_filename(f"album_{album_id}_{video_file.filename}")
                        video_path = os.path.join(app.config['VIDEOS_FOLDER'], video_filename)
                        video_file.save(video_path)
                        albums[album_index]['video_filename'] = video_filename
                        albums[album_index]['has_video'] = True
                    else:
                        flash('Invalid video file type or file too large (max 500MB)', 'danger')
                
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
                        video_path = os.path.join(app.config['VIDEOS_FOLDER'], albums[album_index]['video_filename'])
                        if os.path.exists(video_path):
                            os.remove(video_path)
                    albums[album_index]['video_filename'] = None
                    albums[album_index]['has_video'] = False
                
                if save_data(albums, app.config['ALBUMS_FILE']):
                    flash('Album updated successfully', 'success')
                    return redirect(url_for('manage_albums'))
                else:
                    flash('Failed to update album', 'danger')
            else:
                flash('Album not found in database', 'danger')
            
        except ValueError:
            flash('Invalid price format', 'danger')
        except Exception as e:
            logger.error(f"Edit album error: {e}")
            flash('Error updating album', 'danger')
    
    return render_template('admin/edit_album.html', album=album, csrf_token=generate_csrf_token())

# Password generation utility route (for admin use)
@app.route('/admin/generate-password')
def generate_password():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    password = generate_strong_password()
    hashed = generate_password_hash(password)
    
    return render_template('admin/generate_password.html', 
                          password=password, 
                          hashed_password=hashed,
                          csrf_token=generate_csrf_token())

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
