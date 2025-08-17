import os
import json
import uuid
import logging
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['UPLOAD_FOLDER'] = 'static/uploads/covers'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png', 'webp'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB
csrf = CSRFProtect(app)

# Branding configuration
BRAND_NAME = "Cool Cat Productions-Druna C."

# Ensure upload and data directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('data', exist_ok=True)

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)

# VAT Configuration
VAT_RATE = 0.20  # 20% VAT

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def load_products():
    try:
        if not os.path.exists('data/products.json'):
            with open('data/products.json', 'w') as f:
                json.dump([], f)
            return []
        
        with open('data/products.json', 'r') as f:
            return json.load(f)
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

# Admin authentication
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Admin access required', 'error')
            return redirect(url_for('home'))
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

# Context processor to inject brand name into all templates
@app.context_processor
def inject_brand():
    return {'brand': BRAND_NAME}

# Routes
@app.route('/')
def home():
    try:
        return render_template('index.html', featured=load_products()[:3])
    except Exception as e:
        logger.error(f"Error in home route: {str(e)}")
        flash('An error occurred while loading the home page', 'error')
        return render_template('error.html'), 500

@app.route('/shop')
def shop():
    try:
        return render_template('shop.html', products=load_products())
    except Exception as e:
        logger.error(f"Error in shop route: {str(e)}")
        flash('An error occurred while loading products', 'error')
        return render_template('error.html'), 500

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
        logger.error(f"Error in product route: {str(e)}")
        flash('An error occurred while loading the product', 'error')
        return render_template('error.html'), 500

# ... (other routes remain the same as previous version) ...

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
