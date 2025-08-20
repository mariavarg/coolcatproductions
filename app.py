import os
import json
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from dotenv import load_dotenv
from markupsafe import escape

# Initialize
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-' + os.urandom(16).hex())

# Configuration
app.config.update(
    USERS_FILE=os.path.join('data', 'users.json'),
    ALBUMS_FILE=os.path.join('data', 'albums.json'),
    COVERS_FOLDER=os.path.join('static', 'uploads', 'covers'),
    UPLOAD_FOLDER='static/uploads',
    ALLOWED_EXTENSIONS={'png', 'jpg', 'jpeg', 'webp'},
    ADMIN_USERNAME=os.getenv('ADMIN_USERNAME', 'admin'),
    ADMIN_PASSWORD_HASH=generate_password_hash(os.getenv('ADMIN_PASSWORD', 'admin123')),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024
)

# Ensure directories exist
os.makedirs('data', exist_ok=True)
os.makedirs(app.config['COVERS_FOLDER'], exist_ok=True)

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def load_data(filename):
    try:
        if os.path.exists(filename):
            with open(filename) as f:
                return json.load(f)
        return []
    except:
        return []

def save_data(data, filename):
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except:
        return False

# Routes with basic functionality
@app.route('/')
def home():
    albums = load_data(app.config['ALBUMS_FILE'])
    return render_template('index.html', albums=albums[:4] if albums else [])

@app.route('/shop')
def shop():
    albums = load_data(app.config['ALBUMS_FILE'])
    return render_template('shop.html', albums=albums if albums else [])

@app.route('/album/<int:album_id>')
def album(album_id):
    albums = load_data(app.config['ALBUMS_FILE'])
    album = next((a for a in albums if a['id'] == album_id), None)
    if not album:
        abort(404)
    return render_template('album.html', album=album)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        users = load_data(app.config['USERS_FILE'])
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if any(u['username'] == username for u in users):
            flash('Username already exists', 'danger')
        elif any(u['email'] == email for u in users):
            flash('Email already registered', 'danger')
        else:
            new_user = {
                'id': len(users) + 1,
                'username': username,
                'email': email,
                'password': generate_password_hash(password),
                'joined': datetime.now().strftime("%Y-%m-%d")
            }
            users.append(new_user)
            if save_data(users, app.config['USERS_FILE']):
                flash('Registration successful!', 'success')
                return redirect(url_for('home'))
    
    return render_template('register.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if username == app.config['ADMIN_USERNAME'] and check_password_hash(app.config['ADMIN_PASSWORD_HASH'], password):
            session['admin_logged_in'] = True
            flash('Logged in successfully', 'success')
            return redirect(url_for('admin_dashboard'))
        
        flash('Invalid credentials', 'danger')
    
    return render_template('admin/login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('home'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    albums = load_data(app.config['ALBUMS_FILE'])
    users = load_data(app.config['USERS_FILE'])
    return render_template('admin/dashboard.html',
                           album_count=len(albums),
                           user_count=len(users))

@app.route('/admin/add-album', methods=['GET', 'POST'])
def add_album():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        albums = load_data(app.config['ALBUMS_FILE'])
        cover = request.files.get('cover')
        
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
            'title': request.form.get('title', '').strip(),
            'artist': request.form.get('artist', '').strip(),
            'year': request.form.get('year', '').strip(),
            'cover': os.path.join('uploads', 'covers', filename).replace('\\', '/'),
            'tracks': [t.strip() for t in request.form.get('tracks', '').split('\n') if t.strip()],
            'added': datetime.now().strftime("%Y-%m-%d"),
            'price': round(float(request.form.get('price', 0)), 2)
        }
        
        albums.append(new_album)
        if save_data(albums, app.config['ALBUMS_FILE']):
            flash('Album added successfully', 'success')
            return redirect(url_for('shop'))
        else:
            flash('Failed to save album', 'danger')
    
    return render_template('admin/add_album.html')

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
