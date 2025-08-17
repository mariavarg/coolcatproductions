import os
import json
import uuid
import logging
import re
import traceback
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import datetime

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_secret_key')
app.config['UPLOAD_FOLDER'] = 'static/uploads/covers'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png', 'webp'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB

# Create directories if they don't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('data', exist_ok=True)

csrf = CSRFProtect(app)

# Branding configuration
BRAND_NAME = "Cool Cat Productions-Druna C."

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
limiter.init_app(app)

# VAT Configuration
VAT_RATE = 0.20  # 20% VAT

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def repair_json(json_str):
    """Attempt to repair common JSON formatting issues"""
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        logger.warning(f"JSON repair needed: {str(e)}")
        try:
            repaired = json_str.replace("'", '"')
            repaired = re.sub(r',\s*}', '}', repaired)
            repaired = re.sub(r',\s*]', ']', repaired)
            repaired = re.sub(r'(?<!\\)"', r'\"', repaired)
            return json.loads(repaired)
        except Exception as e2:
            logger.error(f"JSON repair failed: {str(e2)}")
            return []

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
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error: {str(e)} - attempting repair")
                f.seek(0)
                content = f.read()
                repaired = repair_json(content)
                with open(file_path, 'w') as outfile:
                    json.dump(repaired, outfile, indent=2)
                return repaired
    except Exception as e:
        logger.error(f"Critical error loading products: {str(e)}\n{traceback.format_exc()}")
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

# Context processor to inject brand name and current year
@app.context_processor
def inject_global_data():
    return {
        'brand': BRAND_NAME,
        'current_year': datetime.datetime.now().year
    }

# Routes
@app.route('/')
def home():
    try:
        featured = load_products()[:3]
        return render_template('index.html', featured=featured)
    except Exception as e:
        logger.error(f"Error in home route: {str(e)}\n{traceback.format_exc()}")
        return render_template('error.html', message='Home page loading failed'), 500

@app.route('/shop')
def shop():
    try:
        products = load_products()
        return render_template('shop.html', products=products)
    except Exception as e:
        logger.error(f"Error in shop route: {str(e)}")
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
        logger.error(f"Error in product route: {str(e)}")
        return render_template('error.html', message='Product loading failed'), 500

@app.route('/add-to-cart/<product_id>')
def add_to_cart(product_id):
    try:
        if 'cart' not in session:
            session['cart'] = {}
        
        session['cart'][product_id] = session['cart'].get(product_id, 0) + 1
        session.modified = True
        flash('Item added to cart', 'success')
        return redirect(url_for('shop'))
    except Exception as e:
        logger.error(f"Error adding to cart: {str(e)}")
        flash('Failed to add item to cart', 'error')
        return redirect(url_for('shop'))

@app.route('/cart')
def cart():
    try:
        cart_items = []
        subtotal = 0.0
        
        products = {p['id']: p for p in load_products()}
        for product_id, quantity in session.get('cart', {}).items():
            if product_id in products:
                product = products[product_id]
                price = product.get('sale_price', product['price'])
                item_total = float(price) * quantity
                subtotal += item_total
                
                cart_items.append({
                    'id': product_id,
                    'details': product,
                    'quantity': quantity,
                    'item_total': item_total
                })
        
        vat = subtotal * VAT_RATE
        total = subtotal + vat
        
        return render_template('cart.html', 
                              cart=cart_items, 
                              subtotal=subtotal,
                              vat=vat,
                              total=total)
    except Exception as e:
        logger.error(f"Error loading cart: {str(e)}")
        return render_template('error.html', message='Cart loading failed'), 500

@app.route('/remove-from-cart/<product_id>')
def remove_from_cart(product_id):
    try:
        if 'cart' in session and product_id in session['cart']:
            session['cart'].pop(product_id)
            session.modified = True
            flash('Item removed from cart', 'info')
        return redirect(url_for('cart'))
    except Exception as e:
        logger.error(f"Error removing from cart: {str(e)}")
        flash('Failed to remove item from cart', 'error')
        return redirect(url_for('cart'))

@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def admin_login():
    try:
        if request.method == 'POST':
            admin_password = os.environ.get('ADMIN_PASSWORD')
            if admin_password and request.form.get('password') == admin_password:
                session['admin_logged_in'] = True
                return redirect(url_for('add_product'))
            flash('Invalid credentials', 'error')
        return render_template('admin/login.html')
    except Exception as e:
        logger.error(f"Admin login error: {str(e)}")
        return render_template('admin/login.html', error=True), 500

@app.route('/admin/add-product', methods=['GET', 'POST'])
@admin_required
@limiter.limit("10 per minute")
def add_product():
    try:
        if request.method == 'POST':
            # Handle file upload
            image_file = request.files['cover_image']
            filename = 'default.jpg'
            
            if image_file and image_file.filename != '' and allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
            
            # Get form data
            tracks = [t.strip() for t in request.form.get('tracks', '').split('\n') if t.strip()]
            on_sale = 'on_sale' in request.form
            
            # Price validation
            try:
                price = float(request.form.get('price', 0))
                sale_price = float(request.form.get('sale_price', 0)) if on_sale and request.form.get('sale_price') else None
            except (ValueError, TypeError):
                flash('Invalid price format. Please enter numbers only.', 'error')
                return render_template('admin/add_product.html')
            
            # Create new product
            new_product = {
                'id': str(uuid.uuid4()),
                'title': request.form.get('title', ''),
                'artist': request.form.get('artist', ''),
                'format': request.form.get('format', 'CD'),
                'price': price,
                'sale_price': sale_price,
                'image': filename,
                'tracks': tracks,
                'on_sale': on_sale
            }
            
            # Save to database
            products = load_products()
            products.append(new_product)
            if save_products(products):
                flash('Product added successfully', 'success')
                return redirect(url_for('shop'))
            else:
                flash('Failed to save product', 'error')
        
        return render_template('admin/add_product.html')
    except Exception as e:
        logger.error(f"Error adding product: {str(e)}")
        return render_template('admin/add_product.html', error=True), 500

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    try:
        if request.method == 'POST':
            session.pop('cart', None)
            flash('Order placed successfully!', 'success')
            return redirect(url_for('home'))
        
        return render_template('checkout.html')
    except Exception as e:
        logger.error(f"Checkout error: {str(e)}")
        return render_template('error.html', message='Checkout failed'), 500

@app.route('/admin/logout')
def admin_logout():
    try:
        session.pop('admin_logged_in', None)
        return redirect(url_for('home'))
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        flash('Logout failed', 'error')
        return redirect(url_for('home'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
