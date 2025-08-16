from flask import Flask, render_template, request, redirect, url_for
import json
import os
from werkzeug.utils import secure_filename

# Add health check route
@app.route('/health')
def health():
    return "OK", 200

app = Flask(__name__)

# ===== Basic Security Setup =====
app.secret_key = os.urandom(24)  # Random secret key
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024  # 8MB file limit

# ===== JSON Database =====
DB_PATH = 'data/albums.json'

def get_albums():
    """Safe JSON reading"""
    if not os.path.exists(DB_PATH):
        os.makedirs('data', exist_ok=True)
        with open(DB_PATH, 'w') as f:
            json.dump([], f)
        return []
    
    try:
        with open(DB_PATH, 'r') as f:
            return json.load(f)
    except:
        return []  # Return empty if corrupted

def save_albums(albums):
    """Safe JSON writing"""
    with open(DB_PATH, 'w') as f:
        json.dump(albums, f, indent=2)

# ===== Safe Uploads =====
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    """Check if extension is safe"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ===== Routes =====
@app.route('/')
def home():
    return render_template('shop.html', albums=get_albums())

@app.route('/add', methods=['POST'])
def add_album():
    albums = get_albums()
    
    # Basic input validation
    try:
        new_album = {
            'id': len(albums) + 1,
            'title': request.form['title'][:100],  # Limit length
            'artist': request.form['artist'][:100],
            'price': min(float(request.form['price']), 999.99),  # Cap price
            'image': 'placeholder.jpg'
        }
    except:
        return redirect(url_for('home'))  # Fail silently
    
    # Handle file upload
    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            new_album['image'] = filename
    
    albums.append(new_album)
    save_albums(albums)
    return redirect(url_for('home'))

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(host='0.0.0.0', port=5000)
