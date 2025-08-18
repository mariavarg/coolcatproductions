import os
import json
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from dotenv import load_dotenv
# Add these imports at the TOP of app.py
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)

# After app = Flask(__name__)

# Initialize CSRF Protection
csrf = CSRFProtect(app)

# Initialize Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Configuration
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY', 'dev-key-' + os.urandom(16).hex()),
    USERS_FILE=os.path.join('data', 'users.json'),
    ALBUMS_FILE=os.path.join('data', 'albums.json'),
    COVERS_FOLDER=os.path.join('static', 'uploads', 'covers'),
    UPLOAD_FOLDER='static/uploads',
    ALLOWED_EXTENSIONS=set(os.getenv('ALLOWED_EXTENSIONS', 'png,jpg,jpeg,webp').split(',')),
    ADMIN_USERNAME=os.getenv('ADMIN_USERNAME', 'admin'),
    ADMIN_PASSWORD_HASH=generate_password_hash(os.getenv('ADMIN_PASSWORD', 'admin123')),
    MAX_CONTENT_LENGTH=int(os.getenv('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))  # 16MB default
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

# Error handlers
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

@app.before_request
def enforce_https():
    """Redirect HTTP to HTTPS in production"""
    if request.headers.get('X-Forwarded-Proto') == 'http' and app.env == 'production':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

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
    """Shopping cart placeholder"""
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
        return render_template('album.html', album=album)
    except Exception as e:
        logger.error(f"Album route error: {str(e)}")
        abort(500)

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
        
    if request.method == 'POST':
        try:
            if (request.form['username'] == app.config['ADMIN_USERNAME'] and 
                check_password_hash(app.config['ADMIN_PASSWORD_HASH'], request.form['password'])):
                session['admin_logged_in'] = True
                flash('Logged in successfully', 'success')
                return redirect(url_for('admin_dashboard'))
            flash('Invalid credentials', 'danger')
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('Login failed. Please try again.', 'danger')
    
    return render_template('admin/login.html')

@app.route('/admin/logout')
def admin_logout():
    try:
        session.pop('admin_logged_in', None)
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
            
            new_album = {
                'id': len(albums) + 1,
                'title': request.form['title'].strip(),
                'artist': request.form['artist'].strip(),
                'year': request.form['year'].strip(),
                'cover': os.path.join('uploads', 'covers', filename).replace('\\', '/'),
                'tracks': [t.strip() for t in request.form['tracks'].split('\n') if t.strip()],
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
    
    return render_template('admin/add_album.html')

# User registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            users = load_data(app.config['USERS_FILE'])
            
            if any(u['username'] == request.form['username'] for u in users):
                flash('Username already exists', 'danger')
                return redirect(request.url)
                
            if any(u['email'] == request.form['email'] for u in users):
                flash('Email already registered', 'danger')
                return redirect(request.url)
            
            new_user = {
                'id': len(users) + 1,
                'username': request.form['username'].strip(),
                'email': request.form['email'].strip(),
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
            
    return render_template('register.html')

if __name__ == '__main__':
    try:
        port = int(os.getenv('PORT', 5000))
        debug = os.getenv('DEBUG', 'False').lower() == 'true'
        logger.info(f"Starting server on port {port} (debug={debug})")
        app.run(host=os.getenv('HOST', '0.0.0.0'), port=port, debug=debug)
    except Exception as e:
        logger.critical(f"Failed to start server: {str(e)}")
