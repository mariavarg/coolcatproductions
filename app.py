import os
import json
import logging
import time
import hashlib
import hmac
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

# In-memory storage for rate limiting
rate_limit_store = {}

# Configuration
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY', os.urandom(24).hex()),
    USERS_FILE=os.path.join('data', 'users.json'),
    ALBUMS_FILE=os.path.join('data', 'albums.json'),
    COVERS_FOLDER=os.path.join('static', 'uploads', 'covers'),
    UPLOAD_FOLDER='static/uploads',
    ALLOWED_EXTENSIONS=set(os.getenv('ALLOWED_EXTENSIONS', 'png,jpg,jpeg,webp').split(',')),
    ADMIN_USERNAME=os.getenv('ADMIN_USERNAME', 'admin'),
    # Stronger password hashing with increased iterations
    ADMIN_PASSWORD_HASH=generate_password_hash(
        os.getenv('ADMIN_PASSWORD', 'admin123'),
        method='pbkdf2:sha256:600000'
    ),
    MAX_CONTENT_LENGTH=int(os.getenv('MAX_CONTENT_LENGTH', 16 * 1024 * 1024)),  # 16MB default
    # Enhanced session security
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    # Security settings
    CSRF_SECRET=os.getenv('CSRF_SECRET', os.urandom(24).hex()),
    RATE_LIMIT_WINDOW=60,  # 60 seconds
    RATE_LIMIT_COUNT=5,    # 5 requests per window
    REGISTER_RATE_LIMIT=3  # 3 registrations per window
)

# Initialize app setup at startup
def initialize_app():
    """Ensure required directories and files exist"""
    try:
        os.makedirs('templates/admin', exist_ok=True)
        os.makedirs('data', exist_ok=True)
        os.makedirs(app.config['COVERS_FOLDER'], exist_ok=True)
        
        # Initialize empty data files if they don't exist
        for data_file in [app.config['USERS_FILE'], app.config['ALBUMS_FILE']]:
            if not os.path.exists(data_file):
                with open(data_file, 'w') as f:
                    json.dump([], f)
                logger.info(f"Created new data file: {data_file}")
                
    except Exception as e:
        logger.error(f"Initialization error: {str(e)}")
        raise

# Run initialization when app starts
initialize_app()

# Helper functions
def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def load_data(filename):
    """Load JSON data from file with error handling"""
    try:
        with open(filename) as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"Data file not found: {filename}")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {filename}: {str(e)}")
        flash('Data loading error. Please contact admin.', 'danger')
        return []
    except Exception as e:
        logger.error(f"Unexpected error loading {filename}: {str(e)}")
        return []

def save_data(data, filename):
    """Save data to JSON file with error handling"""
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving to {filename}: {str(e)}")
        flash('Data saving failed. Please try again.', 'danger')
        return False

# Image validation using file signatures
def is_valid_image(file_path):
    """Check if file is a valid image by reading its signature"""
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
            
        # Add more formats if needed
        return False
    except Exception:
        return False

# Security functions
def generate_csrf_token():
    """Generate a CSRF token"""
    if 'csrf_token' not in session:
        # Create timestamped token
        timestamp = str(int(time.time()))
        token = hmac.new(
            app.config['CSRF_SECRET'].encode(),
            (session.sid + timestamp).encode(),
            hashlib.sha256
        ).hexdigest()
        session['csrf_token'] = f"{timestamp}:{token}"
    return session['csrf_token']

def validate_csrf_token():
    """Validate the CSRF token in the request"""
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return True
        
    token = request.form.get('csrf_token')
    if not token:
        logger.warning("Missing CSRF token")
        return False
        
    if token != session.get('csrf_token'):
        logger.warning("Invalid CSRF token")
        return False
        
    # Check token expiration (1 hour)
    try:
        timestamp, _ = token.split(':', 1)
        if int(timestamp) < time.time() - 3600:
            logger.warning("Expired CSRF token")
            return False
    except:
        return False
        
    return True

def check_rate_limit(identifier, limit, window):
    """Simple rate limiting implementation"""
    current_time = time.time()
    key = f"{identifier}_{request.endpoint}"
    
    # Initialize or clean up old entries
    if key not in rate_limit_store:
        rate_limit_store[key] = []
    
    # Remove old entries
    rate_limit_store[key] = [
        t for t in rate_limit_store[key] 
        if t > current_time - window
    ]
    
    # Check if under limit
    if len(rate_limit_store[key]) < limit:
        rate_limit_store[key].append(current_time)
        return True
    
    return False

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    # Basic CSP - adjust as needed for your site
    csp = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'"
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Add session cookie security
    if request.url.startswith('https://') or not app.debug:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Set secure cookies in production
    if not app.debug:
        response.headers.add('Set-Cookie', 'session={}; Secure; HttpOnly; SameSite=Lax'.format(
            session.sid if session.sid else ''
        ))
    
    return response

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(413)
def too_large(e):
    flash('File too large - maximum size is 16MB', 'danger')
    return redirect(request.url)

@app.errorhandler(429)
def ratelimit_handler(e):
    flash('Too many requests. Please try again later.', 'warning')
    return redirect(url_for('home'))

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"500 Error: {str(e)}")
    return render_template('500.html'), 500

# Routes
@app.route('/')
def home():
    try:
        albums = load_data(app.config['ALBUMS_FILE'])
        if albums is None:  # Handle case where load_data fails
            albums = []
        return render_template('index.html', albums=albums[:4])
    except Exception as e:
        logger.error(f"Home route error: {str(e)}", exc_info=True)
        flash('Failed to load content. Please try again later.', 'danger')
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
        flash('Failed to load shop content.', 'danger')
        return render_template('shop.html', albums=[])

@app.route('/album/<int:album_id>')
def album(album_id):
    try:
        albums = load_data(app.config['ALBUMS_FILE'])
        album = next((a for a in albums if a['id'] == album_id), None)
        if not album:
            logger.warning(f"Album not found: {album_id}")
            abort(404)
        
        # Escape user-generated content to prevent XSS
        album['title'] = escape(album['title'])
        album['artist'] = escape(album['artist'])
        
        return render_template('album.html', album=album)
    except Exception as e:
        logger.error(f"Album route error: {str(e)}")
        abort(500)

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    
    # Rate limiting check for login attempts
    if request.method == 'POST':
        ip = request.remote_addr
        if not check_rate_limit(ip, app.config['RATE_LIMIT_COUNT'], app.config['RATE_LIMIT_WINDOW']):
            flash('Too many login attempts. Please try again later.', 'warning')
            return redirect(url_for('admin_login'))
        
    if request.method == 'POST':
        try:
            # CSRF protection
            if not validate_csrf_token():
                flash('Security token invalid. Please try again.', 'danger')
                return redirect(url_for('admin_login'))
            
            if (request.form['username'] == app.config['ADMIN_USERNAME'] and 
                check_password_hash(app.config['ADMIN_PASSWORD_HASH'], request.form['password'])):
                session['admin_logged_in'] = True
                # Regenerate session ID on login
                session.regenerate()
                flash('Logged in successfully', 'success')
                return redirect(url_for('admin_dashboard'))
            flash('Invalid credentials', 'danger')
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('Login failed. Please try again.', 'danger')
    
    return render_template('admin/login.html', csrf_token=generate_csrf_token())

@app.route('/admin/logout')
def admin_logout():
    try:
        session.pop('admin_logged_in', None)
        # Clear session completely
        session.clear()
        flash('Logged out successfully', 'success')
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        flash('Logout failed', 'danger')
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
        return render_template('admin/dashboard.html',
                               album_count=0,
                               user_count=0,
                               current_date=datetime.now().strftime("%Y-%m-%d"))

@app.route('/admin/add-album', methods=['GET', 'POST'])
def add_album():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        try:
            # CSRF protection
            if not validate_csrf_token():
                flash('Security token invalid. Please try again.', 'danger')
                return redirect(url_for('add_album'))
            
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
            
            # Verify actual image format using file signatures
            if not is_valid_image(cover_path):
                os.remove(cover_path)
                flash('Invalid image format', 'danger')
                return redirect(request.url)
            
            # Escape user input to prevent XSS
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
                
        except ValueError as e:
            flash('Invalid price format', 'danger')
        except Exception as e:
            logger.error(f"Add album error: {str(e)}", exc_info=True)
            flash(f'Error adding album: {str(e)}', 'danger')
    
    return render_template('admin/add_album.html', csrf_token=generate_csrf_token())

# User registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            # Rate limiting for registrations
            ip = request.remote_addr
            if not check_rate_limit(ip, app.config['REGISTER_RATE_LIMIT'], app.config['RATE_LIMIT_WINDOW']):
                flash('Too many registration attempts. Please try again later.', 'warning')
                return redirect(url_for('register'))
            
            # CSRF protection
            if not validate_csrf_token():
                flash('Security token invalid. Please try again.', 'danger')
                return redirect(url_for('register'))
            
            users = load_data(app.config['USERS_FILE'])
            username = request.form['username'].strip()
            email = request.form['email'].strip()
            
            if any(u['username'] == username for u in users):
                flash('Username already exists', 'danger')
                return redirect(request.url)
                
            if any(u['email'] == email for u in users):
                flash('Email already registered', 'danger')
                return redirect(request.url)
            
            # Stronger password hashing
            new_user = {
                'id': len(users) + 1,
                'username': escape(username),
                'email': escape(email),
                'password': generate_password_hash(
                    request.form['password'],
                    method='pbkdf2:sha256:600000'
                ),
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
        
        # Disable debug mode in production
        if os.getenv('FLASK_ENV') == 'production':
            debug = False
            
        logger.info(f"Starting server on port {port} (debug={debug})")
        app.run(host=os.getenv('HOST', '0.0.0.0'), port=port, debug=debug)
    except Exception as e:
        logger.critical(f"Failed to start server: {str(e)}")
