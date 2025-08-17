import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import uuid
import logging
import datetime
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__, static_folder='static')

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# App configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-fallback-key')
app.config['UPLOAD_FOLDER'] = 'static/uploads/covers'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png', 'webp'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB

# Create directories if they don't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('data', exist_ok=True)
os.makedirs('data/backups', exist_ok=True)

# Initialize extensions
csrf = CSRFProtect(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "100 per hour"]
)

# Add this static files route HERE
@app.route('/static/<path:filename>')
def static_files(filename):
    """Ensure static files are served correctly with caching"""
    cache_timeout = app.get_send_file_max_age(filename)
    return send_from_directory(
        app.static_folder,
        filename,
        cache_timeout=cache_timeout
    )
# Constants
BRAND_NAME = "Cool Cat Productions-Druna C."
VAT_RATE = 0.20  # 20% VAT

# Admin credentials
ADMIN_USER = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASS_HASH = generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'securepassword'))

# Helper functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def load_products():
    try:
        file_path = 'data/products.json'
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                json.dump([], f)
            return []
        
        with open(file_path, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                with open(file_path, 'w') as f:
                    json.dump([], f)
                return []
    except Exception as e:
        logger.error(f"Error loading products: {str(e)}")
        return []

def save_products(products):
    try:
        with open('data/products.json', 'w') as f:
            json.dump(products, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving products: {str(e)}")
        return False

def load_albums():
    try:
        with open('data/albums.json', 'r') as f:
            return json.load(f)
    except:
        return []

def save_albums(albums):
    with open('data/albums.json', 'w') as f:
        json.dump(albums, f, indent=2)

def get_cart_details():
    cart_items = session.get('cart', [])
    products = load_products()
    cart_products = []
    subtotal = 0.0
    
    for item in cart_items:
        product = next((p for p in products if p['id'] == item['id']), None)
        if product:
            price = product['sale_price'] if product.get('on_sale', False) else product['price']
            item_total = price * item['quantity']
            subtotal += item_total
            cart_products.append({
                'id': product['id'],
                'name': product['title'],
                'artist': product['artist'],
                'price': price,
                'image': product['image'],
                'quantity': item['quantity'],
                'item_total': item_total
            })
    
    vat = subtotal * VAT_RATE
    total = subtotal + vat
    
    return {
        'cart_items': cart_products,
        'subtotal': subtotal,
        'vat': vat,
        'total': total
    }

# Authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Admin access required', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Security headers
@app.after_request
def add_security_headers(response):
    csp = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src 'self' fonts.gstatic.com; script-src 'self'"
    headers = {
        'Content-Security-Policy': csp,
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    }
    for key, value in headers.items():
        response.headers[key] = value
    return response

# Cache control for static files
@app.after_request
def add_cache_headers(response):
    if request.path.startswith('/static/'):
        response.cache_control.max_age = 3600
    return response

# Global template variables
@app.context_processor
def inject_global_data():
    cart_details = get_cart_details()
    return {
        'brand': BRAND_NAME,
        'current_year': datetime.datetime.now().year,
        'cart_count': len(session.get('cart', [])),
        'cart_total': cart_details['total'],
        'cart_items': cart_details['cart_items']
    }

# Initialize cart
@app.before_request
def initialize_cart():
    if 'cart' not in session:
        session['cart'] = []

# Routes
@app.route('/')
def home():
    try:
        featured = load_products()[:3]
        return render_template('index.html', featured=featured)
    except Exception as e:
        logger.error(f"Home route error: {str(e)}")
        return render_template('error.html', message='Home page loading failed'), 500

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 
                             'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/shop')
def shop():
    try:
        # Try albums.json first, fall back to products.json
        try:
            with open('data/albums.json', 'r') as f:
                albums = json.load(f)
                return render_template('shop.html', albums=albums)
        except FileNotFoundError:
            products = load_products()
            return render_template('shop.html', albums=products)
    except Exception as e:
        logger.error(f"Shop loading error: {str(e)}")
        return render_template('error.html', message='Shop loading failed'), 500

@app.route('/product/<product_id>')
def product(product_id):
    try:
        products = load_products()
        product = next((p for p in products if p['id'] == product_id), None)
        if product:
            return render_template('product.html', product=product)
        flash('Product not found', 'error')
        return redirect(url_for('shop'))
    except Exception as e:
        logger.error(f"Product route error: {str(e)}")
        return render_template('error.html', message='Product loading failed'), 500

@app.route('/cart')
def cart():
    try:
        cart_details = get_cart_details()
        return render_template(
            'cart.html', 
            cart=cart_details['cart_items'], 
            subtotal=cart_details['subtotal'],
            vat=cart_details['vat'],
            total=cart_details['total'],
            vat_rate=VAT_RATE*100
        )
    except Exception as e:
        logger.error(f"Cart route error: {str(e)}")
        return render_template('error.html', message='Cart loading failed'), 500

@app.route('/add_to_cart/<product_id>', methods=['POST'])
def add_to_cart(product_id):
    try:
        quantity = int(request.form.get('quantity', 1))
        cart = session.get('cart', [])
        
        products = load_products()
        if not any(p['id'] == product_id for p in products):
            flash('Product not found', 'error')
            return redirect(url_for('shop'))
        
        found = False
        for item in cart:
            if item['id'] == product_id:
                item['quantity'] += quantity
                found = True
                break
        
        if not found:
            cart.append({'id': product_id, 'quantity': quantity})
        
        session['cart'] = cart
        flash('Item added to cart!', 'success')
        return redirect(url_for('product', product_id=product_id))
    except Exception as e:
        logger.error(f"Add to cart error: {str(e)}")
        return render_template('error.html', message='Could not add to cart'), 500

@app.route('/remove_from_cart/<product_id>')
def remove_from_cart(product_id):
    try:
        cart = session.get('cart', [])
        new_cart = [item for item in cart if item['id'] != product_id]
        
        if len(new_cart) < len(cart):
            session['cart'] = new_cart
            flash('Item removed from cart', 'info')
        else:
            flash('Item not found in cart', 'error')
            
        return redirect(url_for('cart'))
    except Exception as e:
        logger.error(f"Remove from cart error: {str(e)}")
        return render_template('error.html', message='Could not remove item'), 500

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/checkout')
def checkout():
    flash('Checkout functionality coming soon!', 'info')
    return redirect(url_for('cart'))

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    try:
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            
            if username == ADMIN_USER and check_password_hash(ADMIN_PASS_HASH, password):
                session['admin_logged_in'] = True
                flash('Admin login successful', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid credentials', 'error')
        return render_template('admin/login.html')
    except Exception as e:
        logger.error(f"Admin login error: {str(e)}")
        return render_template('error.html', message='Admin login failed'), 500

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Admin logged out', 'info')
    return redirect(url_for('home'))

@app.route('/admin/add_product', methods=['GET', 'POST'])
@admin_required
def add_product():
    try:
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            artist = request.form.get('artist', '').strip()
            format_type = request.form.get('format', '').strip()
            price = float(request.form.get('price', 0))
            on_sale = 'on_sale' in request.form
            sale_price = float(request.form.get('sale_price', 0)) if on_sale else None
            tracks = [t.strip() for t in request.form.get('tracks', '').split('\n') if t.strip()]
            
            cover_image = request.files.get('cover_image')
            filename = None
            if cover_image and allowed_file(cover_image.filename):
                filename = secure_filename(cover_image.filename)
                cover_image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                filename = f"uploads/covers/{filename}"
            
            product = {
                'id': str(uuid.uuid4()),
                'title': title,
                'artist': artist,
                'format': format_type,
                'price': price,
                'on_sale': on_sale,
                'sale_price': sale_price,
                'image': filename,
                'tracks': tracks,
                'created_at': datetime.datetime.now().isoformat()
            }
            
            products = load_products()
            products.append(product)
            save_products(products)
            
            flash('Product added successfully', 'success')
            return redirect(url_for('product', product_id=product['id']))
        
        return render_template('admin/add_product.html')
    except Exception as e:
        logger.error(f"Add product error: {str(e)}")
        flash('Error adding product', 'error')
        return render_template('admin/add_product.html')


@app.route('/admin/add_album', methods=['GET', 'POST'])
@admin_required
def add_album():
       if request.method == 'POST':
        try:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            cover_image = request.files['cover_image']
            if cover_image and allowed_file(cover_image.filename):
                filename = secure_filename(f"{str(uuid.uuid4())}.{cover_image.filename.split('.')[-1]}")
                cover_image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            else:
                flash('Invalid image file', 'error')
                return redirect(request.url)
            
            new_album = {
                'id': str(uuid.uuid4()),
                'title': request.form['title'],
                'artist': request.form['artist'],
                'format': request.form['format'],
                'image': f"uploads/covers/{filename}",
                'tracks': [t.strip() for t in request.form['tracks'].split('\n') if t.strip()],
                'date_added': datetime.datetime.now().isoformat()
            }
            
            albums = load_albums()
            albums.append(new_album)
            save_albums(albums)
            
            flash('Album added successfully!', 'success')
            return redirect(url_for('shop'))
            
        except Exception as e:
            flash(f'Error adding album: {str(e)}', 'error')
            return redirect(request.url)
    
    return render_template('admin/add_album.html')

# Run the app
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
