import os
import json
import logging
import time
import hashlib
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_file
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
    SECRET_KEY=os.getenv('SECRET_KEY', 'dev-key-' + os.urandom(16).hex()),
    USERS_FILE=os.path.join('data', 'users.json'),
    ALBUMS_FILE=os.path.join('data', 'albums.json'),
    PURCHASES_FILE=os.path.join('data', 'purchases.json'),  # NEW: Track purchases
    COVERS_FOLDER=os.path.join('static', 'uploads', 'covers'),
    MUSIC_FOLDER=os.path.join('static', 'uploads', 'music'),  # Where MP3s are stored
    UPLOAD_FOLDER='static/uploads',
    ALLOWED_EXTENSIONS={'png', 'jpg', 'jpeg', 'webp'},
    ALLOWED_MUSIC_EXTENSIONS={'mp3', 'wav'},  # Music file types
    ADMIN_USERNAME=os.getenv('ADMIN_USERNAME', 'admin'),
    ADMIN_PASSWORD_HASH=generate_password_hash(os.getenv('ADMIN_PASSWORD', 'admin123')),
    MAX_CONTENT_LENGTH=50 * 1024 * 1024,  # 50MB for music files
    PERMANENT_SESSION_LIFETIME=3600,
    DOWNLOAD_TOKENS={}
)

# Security setup
login_attempts = {}

def generate_csrf_token():
    """Generate a simple CSRF token"""
    token = hashlib.sha256(f"{time.time()}{app.secret_key}".encode()).hexdigest()
    session['csrf_token'] = token
    return token

def validate_csrf_token():
    """Validate CSRF token for POST requests"""
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return True
    token = request.form.get('csrf_token')
    return token and token == session.get('csrf_token')

def check_rate_limit(ip, endpoint, max_attempts=5, window=60):
    """Simple rate limiting"""
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
    """Remove auto-generated durations from albums"""
    for album in albums:
        if 'tracks' in album:
            album['tracks'] = [track.split(' (')[0].strip() for track in album.get('tracks', [])]
    return albums

def generate_download_token(user_id, album_id):
    """Generate a secure download token"""
    token = secrets.token_urlsafe(32)
    expiry = datetime.now() + timedelta(hours=24)
    
    app.config['DOWNLOAD_TOKENS'][token] = {
        'user_id': user_id,
        'album_id': album_id,
        'expiry': expiry.strftime("%Y-%m-%d %H:%M:%S")
    }
    return token

def validate_download_token(token):
    """Validate download token"""
    if token not in app.config['DOWNLOAD_TOKENS']:
        return False
        
    token_data = app.config['DOWNLOAD_TOKENS'][token]
    expiry = datetime.strptime(token_data['expiry'], "%Y-%m-%d %H:%M:%S")
    
    if datetime.now() > expiry:
        app.config['DOWNLOAD_TOKENS'].pop(token)
        return False
        
    return token_data

def has_purchased(user_id, album_id):
    """Check if user has purchased this album"""
    purchases = load_data(app.config['PURCHASES_FILE'])
    return any(p['user_id'] == user_id and p['album_id'] == album_id for p in purchases)

def record_purchase(user_id, album_id, amount):
    """Record a purchase in JSON file"""
    purchases = load_data(app.config['PURCHASES_FILE'])
    
    purchase = {
        'id': len(purchases) + 1,
        'user_id': user_id,
        'album_id': album_id,
        'amount': amount,
        'purchase_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'downloads': 0  # Track download count
    }
    
    purchases.append(purchase)
    save_data(purchases, app.config['PURCHASES_FILE'])
    return purchase

# Initialize app setup
def initialize_app():
    """Ensure required directories and files exist"""
    try:
        os.makedirs('data', exist_ok=True)
        os.makedirs(app.config['COVERS_FOLDER'], exist_ok=True)
        os.makedirs(app.config['MUSIC_FOLDER'], exist_ok=True)
        
        for data_file in [app.config['USERS_FILE'], app.config['ALBUMS_FILE'], app.config['PURCHASES_FILE']]:
            if not os.path.exists(data_file):
                with open(data_file, 'w') as f:
                    json.dump([], f)
                
    except Exception as e:
        logger.error(f"Initialization error: {str(e)}")

initialize_app()

# Helper functions
def allowed_file(filename, file_type='image'):
    """Check if file extension is allowed"""
    extensions = app.config['ALLOWED_EXTENSIONS'] if file_type == 'image' else app.config['ALLOWED_MUSIC_EXTENSIONS']
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in extensions

def load_data(filename):
    try:
        if os.path.exists(filename):
            with open(filename) as f:
                return json.load(f)
        return []
    except Exception as e:
        logger.error(f"Error loading {filename}: {e}")
        return []

def save_data(data, filename):
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving {filename}: {e}")
        return False

def is_valid_image(file_path):
    """Check if file is a valid image"""
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

# Security headers
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    if not app.debug:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return response

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500

# Routes
@app.route('/')
def home():
    try:
        albums = load_data(app.config['ALBUMS_FILE'])
        albums = remove_auto_durations(albums)
        return render_template('index.html', albums=albums[:4] if albums else [])
    except Exception as e:
        logger.error(f"Home error: {e}")
        return render_template('index.html', albums=[])

@app.route('/shop')
def shop():
    try:
        albums = load_data(app.config['ALBUMS_FILE'])
        albums = remove_auto_durations(albums)
        return render_template('shop.html', albums=albums if albums else [])
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
        
        # Check if user owns this album
        owns_album = False
        if session.get('user_id'):
            owns_album = has_purchased(session['user_id'], album_id)
        
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
            'owns_album': owns_album
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
            elif len(password) < 8:
                flash('Password must be at least 8 characters', 'danger')
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

# Music Purchase & Download System
@app.route('/purchase/<int:album_id>')
def purchase_album(album_id):
    """Purchase an album"""
    if not session.get('user_id'):
        flash('Please login to purchase music', 'danger')
        return redirect(url_for('register'))
    
    albums = load_data(app.config['ALBUMS_FILE'])
    album = next((a for a in albums if a['id'] == album_id), None)
    
    if not album:
        flash('Album not found', 'danger')
        return redirect(url_for('shop'))
    
    # Check if already purchased
    if has_purchased(session['user_id'], album_id):
        flash('You already own this album!', 'info')
        return redirect(url_for('my_music'))
    
    # Record purchase
    purchase = record_purchase(session['user_id'], album_id, album.get('price', 0))
    
    # Generate download token
    token = generate_download_token(session['user_id'], album_id)
    
    flash(f'Purchase successful! ${album.get("price", 0):.2f} paid. You can now download the music.', 'success')
    return redirect(url_for('download_album', token=token))

@app.route('/my-music')
def my_music():
    """Show user's purchased music"""
    if not session.get('user_id'):
        flash('Please login to view your music', 'danger')
        return redirect(url_for('register'))
    
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
    
    return render_template('my_music.html', albums=user_albums)

@app.route('/download/<token>')
def download_album(token):
    """Download album page"""
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
    
    return render_template('download.html', album=album, token=token)

@app.route('/download-track/<token>/<int:track_index>')
def download_track(token, track_index):
    """Download individual track"""
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
    
    # Update download count
    purchases = load_data(app.config['PURCHASES_FILE'])
    for purchase in purchases:
        if purchase['user_id'] == session['user_id'] and purchase['album_id'] == album['id']:
            purchase['downloads'] += 1
            break
    save_data(purchases, app.config['PURCHASES_FILE'])
    
    # In a real app, serve actual MP3 file:
    # mp3_filename = f"album_{album['id']}_track_{track_index}.mp3"
    # mp3_path = os.path.join(app.config['MUSIC_FOLDER'], mp3_filename)
    # 
    # if os.path.exists(mp3_path):
    #     return send_file(mp3_path, as_attachment=True, download_name=f"{track_name}.mp3")
    # else:
    #     flash('Music file not found', 'danger')
    #     return redirect(url_for('download_album', token=token))
    
    # For demo purposes - show success message
    flash(f'Download started: {track_name}.mp3', 'success')
    return redirect(url_for('download_album', token=token))

# Admin routes (continued in next message due to length)
