import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import uuid
import logging
import datetime
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, abort, jsonify
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__, static_folder='static')

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='app.log' if not app.debug else None,
    filemode='a'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# App configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(24).hex()),
    UPLOAD_FOLDER='static/uploads/covers',
    ALLOWED_EXTENSIONS={'jpg', 'jpeg', 'png', 'webp'},
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,  # 5MB
    ADMIN_CREDENTIALS_FILE='data/admin_credentials.json',
    TEMPLATES_AUTO_RELOAD=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=1)
)

# Create directories if they don't exist
required_dirs = [
    app.config['UPLOAD_FOLDER'],
    'data',
    'data/backups',
    'static/uploads'
]

for directory in required_dirs:
    try:
        os.makedirs(directory, exist_ok=True)
        logger.info(f"Directory verified/created: {directory}")
    except OSError as e:
        logger.error(f"Failed to create directory {directory}: {str(e)}")
        raise RuntimeError(f"Could not create required directory: {directory}")

# Initialize extensions
csrf = CSRFProtect(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "100 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)

# Constants
BRAND_NAME = "Cool Cat Productions-Druna C."
VAT_RATE = 0.20  # 20% VAT
CACHE_BUSTER = str(int(datetime.datetime.now().timestamp()))

# Helper functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def load_json_file(filepath, default=None):
    if default is None:
        default = []
    try:
        if not os.path.exists(filepath):
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(default, f, ensure_ascii=False, indent=2)
            return default
        
        with open(filepath, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in {filepath}: {str(e)}")
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(default, f, ensure_ascii=False, indent=2)
                return default
    except Exception as e:
        logger.error(f"Error loading {filepath}: {str(e)}")
        return default

def save_json_file(filepath, data):
    try:
        temp_file = f"{filepath}.tmp"
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(temp_file, filepath)
        return True
    except Exception as e:
        logger.error(f"Error saving to {filepath}: {str(e)}")
        try:
            os.unlink(temp_file)
        except:
            pass
        return False

# Product management
def load_products():
    """Load all products with error handling"""
    try:
        if not os.path.exists('data/products.json'):
            with open('data/products.json', 'w') as f:
                json.dump([], f)
        products = load_json_file('data/products.json')
        logger.debug(f"Loaded {len(products)} products")
        return products
    except Exception as e:
        logger.error(f"Error loading products: {str(e)}")
        return []

def save_products(products):
    """Save products with error handling"""
    try:
        return save_json_file('data/products.json', products)
    except Exception as e:
        logger.error(f"Error saving products: {str(e)}")
        return False

def get_product_by_id(product_id):
    """Get product by ID with error handling"""
    try:
        products = load_products()
        return next((p for p in products if p['id'] == product_id), None)
    except Exception as e:
        logger.error(f"Error finding product {product_id}: {str(e)}")
        return None

def get_cart_details():
    """Get cart details with error handling"""
    try:
        cart_items = session.get('cart', [])
        products = load_products()
        cart_products = []
        subtotal = 0.0
        
        for item in cart_items:
            product = next((p for p in products if p['id'] == item['id']), None)
            if product:
                price = product.get('sale_price', product.get('price', 0))
                item_total = price * item.get('quantity', 0)
                subtotal += item_total
                cart_products.append({
                    'id': product['id'],
                    'name': product.get('title', 'Unknown'),
                    'artist': product.get('artist', 'Unknown'),
                    'price': price,
                    'image': product.get('image', ''),
                    'quantity': item.get('quantity', 0),
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
    except Exception as e:
        logger.error(f"Error getting cart details: {str(e)}")
        return {
            'cart_items': [],
            'subtotal': 0.0,
            'vat': 0.0,
            'total': 0.0
        }

# Admin management
def load_admin_credentials():
    return load_json_file(app.config['ADMIN_CREDENTIALS_FILE'], {})

def save_admin_credentials(username, password):
    credentials = {
        'username': username,
        'password_hash': generate_password_hash(password, method='scrypt'),
        'created_at': datetime.datetime.now().isoformat(),
        'last_updated': datetime.datetime.now().isoformat()
    }
    return save_json_file(app.config['ADMIN_CREDENTIALS_FILE'], credentials)

def is_admin_registered():
    return os.path.exists(app.config['ADMIN_CREDENTIALS_FILE'])

def get_admin_credentials():
    credentials = load_admin_credentials()
    return credentials.get('username'), credentials.get('password_hash')

# Initialize admin credentials
ADMIN_USER, ADMIN_PASS_HASH = get_admin_credentials()

# Authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Admin access required. Please log in.', 'error')
            return redirect(url_for('admin_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Security headers
@app.after_request
def add_security_headers(response):
    headers = {
        'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src 'self' fonts.gstatic.com; script-src 'self'",
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Cache-Control': 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
    }
    for key, value in headers.items():
        response.headers[key] = value
    return response

# Error handlers
@app.errorhandler(400)
def bad_request(e):
    logger.warning(f"Bad request: {str(e)}")
    return render_template('400.html', error=str(e)), 400

@app.errorhandler(403)
def forbidden(e):
    logger.warning(f"Forbidden access: {str(e)}")
    return render_template('403.html', error=str(e)), 403

@app.errorhandler(404)
def page_not_found(e):
    logger.info(f"Page not found: {request.url}")
    return render_template('404.html', error=str(e)), 404

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Server error: {str(e)}", exc_info=True)
    return render_template('500.html', error=str(e) if app.debug else None), 500

# Context processors
@app.context_processor
def inject_global_data():
    try:
        cart_details = get_cart_details()
        return {
            'brand': BRAND_NAME,
            'current_year': datetime.datetime.now().year,
            'cart_count': len(session.get('cart', [])),
            'cart_total': cart_details.get('total', 0),
            'cart_items': cart_details.get('cart_items', []),
            'cache_buster': CACHE_BUSTER
        }
    except Exception as e:
        logger.error(f"Error in context processor: {str(e)}")
        return {
            'brand': BRAND_NAME,
            'current_year': datetime.datetime.now().year,
            'cart_count': 0,
            'cart_total': 0,
            'cart_items': [],
            'cache_buster': CACHE_BUSTER
        }

# Before request setup
@app.before_request
def before_request():
    if 'cart' not in session:
        session['cart'] = []
    session.permanent = True

# Routes
@app.route('/')
def home():
    try:
        featured = load_products()[:3]
        return render_template('index.html', featured=featured)
    except Exception as e:
        logger.error(f"Error in home route: {str(e)}", exc_info=True)
        abort(500)

@app.route('/shop')
def shop():
    try:
        products = load_products()
        return render_template('shop.html', products=products)
    except Exception as e:
        logger.error(f"Error loading shop: {str(e)}")
        abort(500)

@app.route('/product/<product_id>')
def product(product_id):
    try:
        product = get_product_by_id(product_id)
        if product:
            return render_template('product.html', product=product)
        abort(404)
    except Exception as e:
        logger.error(f"Error loading product {product_id}: {str(e)}")
        abort(500)

# Admin routes
@app.route('/admin/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def admin_register():
    if session.get('admin_logged_in'):
        return redirect(url_for('home'))
    if is_admin_registered():
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not password:
            flash('Username and password are required', 'error')
        elif len(username) < 4:
            flash('Username must be at least 4 characters', 'error')
        elif password != confirm_password:
            flash('Passwords do not match', 'error')
        elif len(password) < 8:
            flash('Password must be at least 8 characters', 'error')
        elif save_admin_credentials(username, password):
            global ADMIN_USER, ADMIN_PASS_HASH
            ADMIN_USER, ADMIN_PASS_HASH = get_admin_credentials()
            flash('Admin account created successfully! Please log in.', 'success')
            return redirect(url_for('admin_login'))
        else:
            flash('Failed to create admin account', 'error')

    return render_template('admin/register.html')

@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def admin_login():
    if not is_admin_registered():
        return redirect(url_for('admin_register'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        stored_username, stored_password_hash = get_admin_credentials()
        
        if username == stored_username and check_password_hash(stored_password_hash, password):
            session['admin_logged_in'] = True
            session['admin_last_login'] = datetime.datetime.now().isoformat()
            flash('Admin login successful', 'success')
            return redirect(request.args.get('next') or url_for('home'))
        flash('Invalid credentials', 'error')

    return render_template('admin/login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_last_login', None)
    flash('Admin logged out', 'info')
    return redirect(url_for('home'))

# Health check
@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.datetime.now().isoformat()
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug_mode,
        threaded=True
    )
    # At the very bottom of app.py
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
