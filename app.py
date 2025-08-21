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
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
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
    ALLOWED_VIDEO_EXTENSIONS={'mp4', 'mov', 'avi', 'webm'},
    ADMIN_USERNAME=os.getenv('ADMIN_USERNAME', 'admin'),
    ADMIN_PASSWORD_HASH=os.getenv('ADMIN_PASSWORD_HASH', ''),
    MAX_CONTENT_LENGTH=500 * 1024 * 1024,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    DOWNLOAD_TOKENS={},
    VIDEO_STREAM_CHUNK_SIZE=1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# Security setup
login_attempts = {}
failed_login_lockout = {}

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
    
    # Clear old attempts
    if key in login_attempts:
        login_attempts[key] = [t for t in login_attempts[key] if now - t < window]
    
    if key not in login_attempts:
        login_attempts[key] = []
    
    if len(login_attempts[key]) >= max_attempts:
        # Lockout for 15 minutes after too many attempts
        failed_login_lockout[key] = now + 900
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
        return url_for('protected_video', filename=album['video_filename'])
    return album.get('video_url', '')

def initialize_app():
    try:
        os.makedirs('data', exist_ok=True)
        os.makedirs(app.config['COVERS_FOLDER'], exist_ok=True)
        os.makedirs(app.config['MUSIC_FOLDER'], exist_ok=True)
        os.makedirs(app.config['VIDEOS_FOLDER'], exist_ok=True)
        
        os.makedirs('data/backups', exist_ok=True)
        
        for data_file in [app.config['USERS_FILE'], app.config['ALBUMS_FILE'], app.config['PURCHASES_FILE']]:
            if not os.path.exists(data_file):
                with open(data_file, 'w', encoding='utf-8') as f:
                    json.dump([], f, indent=2)
            
            backup_file = f"data/backups/{os.path.basename(data_file)}.backup"
            if os.path.exists(data_file) and not os.path.exists(backup_file):
                with open(data_file, 'r', encoding='utf-8') as src, open(backup_file, 'w', encoding='utf-8') as dst:
                    dst.write(src.read())
                
    except Exception as e:
        logger.error(f"Initialization error: {str(e)}")

initialize_app()

def allowed_file(filename, file_type='image'):
    extensions = {
        'image': app.config['ALLOWED_EXTENSIONS'],
        'music': app.config['ALLOWED_MUSIC_EXTENSIONS'],
        'video': app.config['ALLOWED_VIDEO_EXTENSIONS']
    }.get(file_type, set())
        
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in extensions

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

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob: https:; "
        "media-src 'self' blob:; "
        "frame-ancestors 'none'; "
        "form-action 'self';"
    )
    
    return response

@app.before_request
def enforce_https_in_production():
    if not app.debug and not request.is_secure and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

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

@app.route('/protected-video/<filename>')
def protected_video(filename):
    if not session.get('user_id'):
        abort(403)
    
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
    
    file_size = os.stat(video_path).st_size
    range_header = request.headers.get('Range', None)
    
    if range_header:
        byte1, byte2 = 0, None
        match = re.search(r'(\d+)-(\d*)', range_header)
        if match:
            byte1 = int(match.group(1))
            if match.group(2):
                byte2 = int(match.group(2))
        
        length = file_size - byte1
        if byte2 is not None:
            length = byte2 - byte1 + 1
        
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
        
        rv = Response(generate(), 206, mimetype=mimetypes.guess_type(video_path)[0], direct_passthrough=True)
        rv.headers.add('Content-Range', f'bytes {byte1}-{byte1 + length - 1}/{file_size}')
        rv.headers.add('Accept-Ranges', 'bytes')
        rv.headers.add('Content-Length', str(length))
        rv.headers.add('Content-Disposition', 'inline')
        return rv
    else:
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
        rv.headers.add('Content-Disposition', 'inline')
        return rv

@app.route('/')
def home():
    try:
        albums = load_data(app.config['ALBUMS_FILE'])
        albums = remove_auto_durations(albums)
        
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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            if not validate_csrf_token():
                flash('Security token invalid. Please try again.', 'danger')
                return render_template('register.html', csrf_token=generate_csrf_token())
            
            users = load_data(app.config['USERS_FILE'])
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            if not all([username, email, password]):
                flash('All fields are required', 'danger')
            elif len(username) < 4:
                flash('Username must be at least 4 characters', 'danger')
            elif not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                flash('Please enter a valid email address', 'danger')
            else:
                is_complex, complexity_msg = is_password_complex(password)
                if not is_complex:
                    flash(complexity_msg, 'danger')
                elif password != confirm_password:
                    flash('Passwords do not match', 'danger')
                elif any(u['username'].lower() == username.lower() for u in users):
                    flash('Username already exists', 'danger')
                elif any(u['email'].lower() == email.lower() for u in users):
                    flash('Email already registered', 'danger')
                else:
                    new_user = {
                        'id': secrets.token_hex(8),
                        'username': escape(username),
                        'email': escape(email),
                        'password': generate_password_hash(password),
                        'joined': datetime.now().isoformat(),
                        'last_login': None
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
            ip = request.remote_addr
            
            if is_locked_out(ip, 'login'):
                flash('Too many failed attempts. Please try again in 15 minutes.', 'warning')
                return render_template('login.html', csrf_token=generate_csrf_token())
            
            if not validate_csrf_token():
                flash('Security token invalid. Please try again.', 'danger')
                return render_template('login.html', csrf_token=generate_csrf_token())
            
            if not check_rate_limit(ip, 'login'):
                flash('Too many login attempts. Please wait 5 minutes.', 'warning')
                return render_template('login.html', csrf_token=generate_csrf_token())
            
            users = load_data(app.config['USERS_FILE'])
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            
            user = next((u for u in users if u['username'].lower() == username.lower()), None)
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                user['last_login'] = datetime.now().isoformat()
                save_data(users, app.config['USERS_FILE'])
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
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/purchase/<album_id>')
def purchase_album(album_id):
    if not session.get('user_id'):
        flash('Please login to purchase music', 'danger')
        return redirect(url_for('login'))
    
    if not album_id.isdigit():
        abort(404)
    
    album_id = int(album_id)
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
        download_name=f"{secure_filename(track_name)}.mp3",
        mimetype='audio/mpeg'
    )
# ... (other routes above)

# ⭐ TEMPORARY ROUTE - PUT THIS RIGHT HERE ⭐
@app.route('/generate-admin-hash')
def generate_admin_hash():
    """TEMPORARY: Generate admin password hash - REMOVE AFTER USE"""
    password = "YourChosenPassword123!"  # ← CHANGE THIS
    hashed = generate_password_hash(password)
    return f'<h1>Hash: {hashed}</h1>'

# ... (other routes above)

# ⭐ TEMPORARY ROUTE - PUT THIS RIGHT HERE ⭐
@app.route('/generate-admin-hash')
def generate_admin_hash():
    """TEMPORARY: Generate admin password hash - REMOVE AFTER USE"""
    password = "YourChosenPassword123!"  # ← CHANGE THIS
    hashed = generate_password_hash(password)
    return f'''
    <h1>Admin Password Hash</h1>
    <p>Add this to Render Environment Variables:</p>
    <code>ADMIN_PASSWORD_HASH={hashed}</code>
    <p>⚠️ Remove this route after setup!</p>
    '''
#ADMIN_ROUTES        
@app.route('/admin/dashboard')  
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    # ... your dashboard code here
    # MAKE SURE THIS IS ALL INDENTED TOO!
    return render_template('admin/dashboard.html')

# ... rest of your admin routes
# ADMIN ROUTES
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST'
        ip = request.remote_addr
        
        if is_locked_out(ip, 'admin_login'):
            flash('Too many failed attempts. Please try again in 15 minutes.', 'warning')
            return render_template('admin/login.html', csrf_token=generate_csrf_token())
        
        if not validate_csrf_token():
            flash('Security token invalid. Please try again.', 'danger')
            return render_template('admin/login.html', csrf_token=generate_csrf_token())
        
        if not check_rate_limit(ip, 'admin_login', 3, 300):
            flash('Too many login attempts. Please wait 5 minutes.', 'warning')
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
                return redirect(url_for('admin_dashboard'))
            
            flash('Invalid credentials', 'danger')
        except Exception as e:
            logger.error(f"Admin login error: {e}")
            flash('Login failed. Please try again.', 'danger')
    pass
    
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

# ... [Rest of admin routes remain similar but with enhanced security] ...

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    
    if not debug:
        # Production settings
        app.config['SESSION_COOKIE_SECURE'] = True
        app.config['PREFERRED_URL_SCHEME'] = 'https'
    
    app.run(host='0.0.0.0', port=port, debug=debug)
