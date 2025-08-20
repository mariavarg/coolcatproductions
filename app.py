import os
import json
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from dotenv import load_dotenv

# Initialize
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
load_dotenv()

app = Flask(__name__)

# Basic config
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-12345')
app.config['USERS_FILE'] = os.path.join('data', 'users.json')
app.config['ALBUMS_FILE'] = os.path.join('data', 'albums.json')
app.config['COVERS_FOLDER'] = os.path.join('static', 'uploads', 'covers')

# Ensure directories exist
os.makedirs('data', exist_ok=True)
os.makedirs(app.config['COVERS_FOLDER'], exist_ok=True)

# Helper functions
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

# Routes - SIMPLIFIED
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

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if username == os.getenv('ADMIN_USERNAME', 'admin'):
            stored_hash = generate_password_hash(os.getenv('ADMIN_PASSWORD', 'admin123'))
            if check_password_hash(stored_hash, password):
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
