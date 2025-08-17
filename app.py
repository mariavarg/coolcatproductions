import os
import json
from datetime import datetime
from flask import Flask, render_template, url_for, flash, session, redirect, request, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-key-123'),
    BRAND_NAME="VinylVault",
    ADMIN_USERNAME=os.environ.get('ADMIN_USER', 'admin'),
    ADMIN_PASSWORD_HASH=generate_password_hash(os.environ.get('ADMIN_PASS', 'music123')),
    PRODUCTS_FILE='data/products.json',
    CART_FILE='data/cart.json',
    UPLOAD_FOLDER='static/uploads',
    ALLOWED_EXTENSIONS={'png', 'jpg', 'jpeg', 'gif'},
    MAX_CONTENT_LENGTH=16 * 1024 * 1024  # 16MB
)

# Ensure directories exist
os.makedirs('templates/admin', exist_ok=True)
os.makedirs('data', exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Helper functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_cart_count():
    try:
        with open(app.config['CART_FILE']) as f:
            return len(json.load(f))
    except:
        return 0

def load_products():
    try:
        with open(app.config['PRODUCTS_FILE']) as f:
            return json.load(f)
    except:
        return []

def save_products(products):
    with open(app.config['PRODUCTS_FILE'], 'w') as f:
        json.dump(products, f, indent=2)

# Context processors
@app.context_processor
def inject_globals():
    return {
        'brand': app.config['BRAND_NAME'],
        'current_year': datetime.now().year,
        'cart_count': get_cart_count(),
        'cache_buster': datetime.now().timestamp()
    }

# Routes
@app.route('/')
def home():
    products = load_products()[:4]  # Show 4 featured products
    return render_template('index.html', featured_products=products)

@app.route('/shop')
def shop():
    products = load_products()
    return render_template('shop.html', products=products)

@app.route('/cart')
def cart():
    try:
        with open(app.config['CART_FILE']) as f:
            cart_items = json.load(f)
        return render_template('cart.html', cart_items=cart_items)
    except:
        return render_template('cart.html', cart_items=[])

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if (request.form['username'] == app.config['ADMIN_USERNAME'] and 
            check_password_hash(app.config['ADMIN_PASSWORD_HASH'], request.form['password'])):
            session['admin_logged_in'] = True
            flash('Logged in successfully', 'success')
            return redirect(url_for('add_product'))
        flash('Invalid credentials', 'danger')
    return render_template('admin/login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('home'))

@app.route('/admin/add-product', methods=['GET', 'POST'])
def add_product():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        # Handle file upload
        cover_image = request.files['cover_image']
        filename = None
        
        if cover_image and allowed_file(cover_image.filename):
            filename = secure_filename(cover_image.filename)
            cover_image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Create new product
        products = load_products()
        new_product = {
            'id': len(products) + 1,
            'title': request.form['title'],
            'artist': request.form['artist'],
            'format': request.form['format'],
            'price': float(request.form['price']),
            'on_sale': 'on_sale' in request.form,
            'sale_price': float(request.form['sale_price']) if request.form['sale_price'] else None,
            'image': f"uploads/{filename}" if filename else None,
            'tracks': [t.strip() for t in request.form['tracks'].split('\n') if t.strip()],
            'date_added': datetime.now().strftime("%Y-%m-%d")
        }
        
        products.append(new_product)
        save_products(products)
        flash('Product added successfully', 'success')
        return redirect(url_for('shop'))
    
    return render_template('admin/add_product.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)))
