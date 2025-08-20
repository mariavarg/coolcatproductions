import os
import json
import logging
import time
import hashlib
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
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

# Configuration - KEEP YOUR EXISTING SETTINGS
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY', os.urandom(24).hex()),
    USERS_FILE=os.path.join('data', 'users.json'),
    ALBUMS_FILE=os.path.join('data', 'albums.json'),
    COVERS_FOLDER=os.path.join('static', 'uploads', 'covers'),
    UPLOAD_FOLDER='static/uploads',
    ALLOWED_EXTENSIONS=set(os.getenv('ALLOWED_EXTENSIONS', 'png,jpg,jpeg,webp').split(',')),
    ADMIN_USERNAME=os.getenv('ADMIN_USERNAME', 'admin'),
    ADMIN_PASSWORD_HASH=generate_password_hash(os.getenv('ADMIN_PASSWORD', 'admin123')),
    MAX_CONTENT_LENGTH=int(os.getenv('MAX_CONTENT_LENGTH', 16 * 1024 * 1024)),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

# Simple rate limiting storage
login_attempts = {}

# Initialize app setup at startup
def initialize_app():
    """Ensure required directories and files exist"""
    try:
        os.makedirs('templates/admin', exist_ok=True)
        os.makedirs('data', exist_ok=True)
        os.makedirs(app.config['COVERS_FOLDER'], exist_ok=True)
        
        for data_file in [app.config['USERS_FILE'], app.config['ALBUMS_FILE']]:
            if not os.path.exists(data_file):
                with open(data_file, 'w') as f:
                    json.dump([], f)
                logger.info(f"Created new data file: {data_file}")
                
    except Exception as e:
        logger.error(f"Initialization error: {str(e)}")
        raise

initialize_app()

# Security helper functions
def generate_csrf_token():
    """Generate a simple CSRF token"""
    if 'csrf_token' not in session:
        token = hashlib.sha256(f"{time.time()}{app.secret_key}".encode()).hexdigest()
        session['csrf_token'] = token
    return session['csrf_token']

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
    
    # Clean old attempts
    login_attempts[key] = [t for t in login_attempts[key] if now - t < window]
    
    if len(login_attempts[key]) >= max_attempts:
        return False
        
    login_attempts[key].append(now)
    return True

def is_valid_image(file_path):
    """Check if file is a valid image using magic numbers"""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(12)
        
        # JPEG: FF D8 FF
        if header.startswith(b'\xFF\xD8\xFF'):
            return True
        # PNG: \x89PNG\r\n\x1a\n
        if header.startswith(b'\x89PNG\r\n\x1a\n'):
            return True
        # WEBP: RIFF....WEBP
        if header[:4] == b'RIFF' and header[8:12] == b'WEBP':
            return True
            
        return False
    except:
        return False

# Helper functions (keep your existing ones)
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def load_data(filename):
    try:
        with open(filename) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"Error loading {filename}: {str(e)}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error loading {filename}: {str(e)}")
        return []

def save_data(data, filename):
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving to {filename}: {str(e)}")
        return False

# Security middleware
@app.before_request
def security_setup():
    """Set up security features before each request"""
    # Generate CSRF token if not exists
    if 'csrf_token' not in session:
        generate_csrf_token()
    
    # Security headers
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        if not app.debug:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

# Error handlers (keep your existing ones)
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(413)
def too_large(e):
    flash('File too large - maximum size is 16MB', 'danger')
    return redirect(request.url)

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"500 Error: {str(e)}")
    return render_template('500.html'), 500

# Routes - UPDATED FOR SECURITY
@app.route('/')
def home():
    try:
        albums = load_data(app.config['ALBUMS_FILE'])
        return render_template('index.html', albums=albums[:4] if albums else [])
    except Exception as e:
        logger.error(f"Home route error: {str(e)}")
        return render_template('index.html', albums=[])

@app.route('/cart')
def cart():
    flash('Shopping cart functionality is coming soon!', 'info')
    return redirect(url_for('shop'))

@app.route('/shop')
def shop():
    try:
        albums = load_data(app.config['ALBUMS_FILE'])
        return render_template('shop.html', albums=albums if albums else [])
    except Exception as e:
        logger.error(f"Shop route error: {str(e)}")
        return render_template('shop.html', albums=[])

@app.route('/album/<int:album_id>')
def album(album_id):
    try:
        albums = load_data(app.config['ALBUMS_FILE'])
        album = next((a for a in albums if a['id'] == album_id), None)
        if not album:
            abort(404)
        
        # Escape user content to prevent XSS
        safe_album = {
            'id': album['id'],
            'title': escape(album['title']),
            'artist': escape(album['artist']),
            'year': escape(str(album['year'])),
            'cover': album['cover'],
            'tracks': [escape(track) for track in album.get('tracks', [])],
            'added': album.get('added', ''),
            'price': album.get('price', 0),
            'on_sale': album.get('on_sale', False),
            'sale_price': album.get('sale_price')
        }
        return render_template('album.html', album=safe_album)
    except Exception as e:
        logger.error(f"Album route error: {str(e)}")
        abort(500)

# Admin routes - SECURED
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        # Rate limiting
        if not check_rate_limit(request.remote_addr, 'login'):
            flash('Too many login attempts. Please wait 1 minute.', 'warning')
            return render_template('admin/login.html', csrf_token=generate_csrf_token())
        
        # CSRF protection
        if not validate_csrf_token():
            flash('Security token invalid. Please try again.', 'danger')
            return render_template('admin/login.html', csrf_token=generate_csrf_token())
        
        try:
            if (request.form['username'] == app.config['ADMIN_USERNAME'] and 
                check_password_hash(app.config['ADMIN_PASSWORD_HASH'], request.form['password'])):
                session['admin_logged_in'] = True
                session.permanent = True
                flash('Logged in successfully', 'success')
                return redirect(url_for('admin_dashboard'))
            flash('Invalid credentials', 'danger')
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('Login failed. Please try again.', 'danger')
    
    return render_template('admin/login.html', csrf_token=generate_csrf_token())

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('home'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    try:
        albums = load_data(app.config['ALBUMS_FILE'])
        users = load_data(app.config['USERS_FILE'])
        return render_template('admin/dashboard.html',
                               album_count=len(albums),
                               user_count=len(users),
                               current_date=datetime.now().strftime("%Y-%m-%d"))
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        return render_template('admin/dashboard.html', album_count=0, user_count=0)

@app.route('/admin/add-album', methods=['GET', 'POST'])
def add_album():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        # CSRF protection
        if not validate_csrf_token():
            flash('Security token invalid. Please try again.', 'danger')
            return render_template('admin/add_album.html', csrf_token=generate_csrf_token())
        
        try:
            albums = load_data(app.config['ALBUMS_FILE'])
            cover = request.files['cover']
            
            if not cover or cover.filename == '':
                flash('No file selected', 'danger')
                return redirect(request.url)
                
            if not allowed_file(cover.filename):
                flash('Invalid file type', 'danger')
                return redirect(request.url)
            
            filename = secure_filename(cover.filename)
            cover_path = os.path.join(app.config['COVERS_FOLDER'], filename)
            cover.save(cover_path)
            
            # Validate image content
            if not is_valid_image(cover_path):
                os.remove(cover_path)
                flash('Invalid image file', 'danger')
                return redirect(request.url)
            
            # Escape user input
            new_album = {
                'id': len(albums) + 1,
                'title': escape(request.form['title'].strip()),
                'artist': escape(request.form['artist'].strip()),
                'year': escape(request.form['year'].strip()),
                'cover': os.path.join('uploads', 'covers', filename).replace('\\', '/'),
                'tracks': [escape(t.strip()) for t in request.form['tracks'].split('\n') if t.strip()],
                'added': datetime.now().strftime("%Y-%m-%d"),
                'price': round(float(request.form.get('price', 0)), 2),
                'on_sale': 'on_sale' in request.form,
                'sale_price': round(float(request.form.get('sale_price', 0)), 2) if request.form.get('sale_price') else None
            }
            
            albums.append(new_album)
            if save_data(albums, app.config['ALBUMS_FILE']):
                flash('Album added successfully', 'success')
                return redirect(url_for('shop'))
            else:
                flash('Failed to save album', 'danger')
                
        except ValueError:
            flash('Invalid price format', 'danger')
        except Exception as e:
            logger.error(f"Add album error: {str(e)}")
            flash('Error adding album. Please try again.', 'danger')
    
    return render_template('admin/add_album.html', csrf_token=generate_csrf_token())

# User registration - SECURED
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Rate limiting
        if not check_rate_limit(request.remote_addr, 'register', 3, 300):  # 3 attempts per 5 minutes
            flash('Too many registration attempts. Please wait 5 minutes.', 'warning')
            return render_template('register.html', csrf_token=generate_csrf_token())
        
        # CSRF protection
        if not validate_csrf_token():
            flash('Security token invalid. Please try again.', 'danger')
            return render_template('register.html', csrf_token=generate_csrf_token())
        
        try:
            users = load_data(app.config['USERS_FILE'])
            username = request.form['username'].strip()
            email = request.form['email'].strip()
            
            if any(u['username'] == username for u in users):
                flash('Username already exists', 'danger')
                return render_template('register.html', csrf_token=generate_csrf_token())
                
            if any(u['email'] == email for u in users):
                flash('Email already registered', 'danger')
                return render_template('register.html', csrf_token=generate_csrf_token())
            
            new_user = {
                'id': len(users) + 1,
                'username': escape(username),
                'email': escape(email),
                'password': generate_password_hash(request.form['password']),
                'joined': datetime.now().strftime("%Y-%m-%d")
            }
            
            users.append(new_user)
            if save_data(users, app.config['USERS_FILE']):
                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('home'))
            else:
                flash('Registration failed. Please try again.', 'danger')
                
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            flash('Registration error. Please try again.', 'danger')
            
    return render_template('register.html', csrf_token=generate_csrf_token())

if __name__ == '__main__':
    try:
        port = int(os.getenv('PORT', 5000))
        debug = os.getenv('DEBUG', 'False').lower() == 'true'
        app.run(host=os.getenv('HOST', '0.0.0.0'), port=port, debug=debug)
    except Exception as e:
        logger.critical(f"Failed to start server: {str(e)}")
