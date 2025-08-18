import os
import json
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)

# Configuration
app.config.update(
    SECRET_KEY='your-secret-key-here',  # Change this!
    USERS_FILE='data/users.json',
    ALBUMS_FILE='data/albums.json',
    COVERS_FOLDER='static/uploads/covers',
    UPLOAD_FOLDER='static/uploads',
    ALLOWED_EXTENSIONS={'png', 'jpg', 'jpeg', 'webp'},
    ADMIN_USERNAME='your_admin_username',  # Change this!
    ADMIN_PASSWORD_HASH=generate_password_hash('your_admin_password')  # Change this!
)

# Ensure directories exist
os.makedirs('templates/admin', exist_ok=True)
os.makedirs('data', exist_ok=True)
os.makedirs(app.config['COVERS_FOLDER'], exist_ok=True)

# Helper functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def load_data(filename):
    try:
        with open(filename) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_data(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

# Routes
@app.route('/')
def home():
    albums = load_data(app.config['ALBUMS_FILE'])
    return render_template('index.html', albums=albums[:4])  # Show only 4 on home page

@app.route('/shop')
def shop():
    albums = load_data(app.config['ALBUMS_FILE'])
    return render_template('shop.html', albums=albums)

@app.route('/album/<int:album_id>')
def album(album_id):
    albums = load_data(app.config['ALBUMS_FILE'])
    album = next((a for a in albums if a['id'] == album_id), None)
    if not album:
        abort(404)
    return render_template('album.html', album=album)

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if (request.form['username'] == app.config['ADMIN_USERNAME'] and 
            check_password_hash(app.config['ADMIN_PASSWORD_HASH'], request.form['password'])):
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
    return render_template('admin/dashboard.html')

@app.route('/admin/add-album', methods=['GET', 'POST'])
def add_album():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        albums = load_data(app.config['ALBUMS_FILE'])
        cover = request.files['cover']
        
        if cover and allowed_file(cover.filename):
            filename = secure_filename(cover.filename)
            cover.save(os.path.join(app.config['COVERS_FOLDER'], filename))
            
            new_album = {
                'id': len(albums) + 1,
                'title': request.form['title'],
                'artist': request.form['artist'],
                'year': request.form['year'],
                'cover': f"uploads/covers/{filename}",
                'tracks': [t.strip() for t in request.form['tracks'].split('\n') if t.strip()],
                'added': datetime.now().strftime("%Y-%m-%d"),
                'price': float(request.form.get('price', 0)),
                'on_sale': 'on_sale' in request.form,
                'sale_price': float(request.form.get('sale_price', 0)) if request.form.get('sale_price') else None
            }
            
            albums.append(new_album)
            save_data(albums, app.config['ALBUMS_FILE'])
            flash('Album added successfully', 'success')
            return redirect(url_for('shop'))
    
    return render_template('admin/add_album.html')

# User registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        users = load_data(app.config['USERS_FILE'])
        users.append({
            'id': len(users) + 1,
            'username': request.form['username'],
            'email': request.form['email'],
            'password': generate_password_hash(request.form['password']),
            'joined': datetime.now().strftime("%Y-%m-%d")
        })
        save_data(users, app.config['USERS_FILE'])
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('home'))
    return render_template('register.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
