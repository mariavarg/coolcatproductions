import os
import json
import uuid
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['UPLOAD_FOLDER'] = 'static/uploads/covers'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png', 'webp'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB
csrf = CSRFProtect(app)

# Fixed Rate Limiting initialization
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)  # Properly attach the app using init_app

# VAT Configuration
VAT_RATE = 0.20  # 20% VAT

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def load_products():
    if not os.path.exists('data/products.json'):
        os.makedirs('data', exist_ok=True)
        with open('data/products.json', 'w') as f:
            json.dump([], f)
        return []
    
    with open('data/products.json', 'r') as f:
        return json.load(f)

def save_products(products):
    with open('data/products.json', 'w') as f:
        json.dump(products, f, indent=2)

# Admin authentication
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('admin_logged_in') != True:
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

# Routes
@app.route('/')
def home():
    return render_template('index.html', featured=load_products()[:3])

@app.route('/shop')
def shop():
    return render_template('shop.html', products=load_products())

@app.route('/product/<product_id>')
def product(product_id):
    products = load_products()
    product = next((p for p in products if p['id'] == product_id), None)
    if product:
        return render_template('product.html', product=product)
    flash('Product not found', 'error')
    return redirect(url_for('shop'))

@app.route('/add-to-cart/<product_id>')
def add_to_cart(product_id):
    if 'cart' not in session:
        session['cart'] = {}
    
    session['cart'][product_id] = session['cart'].get(product_id, 0) + 1
    session.modified = True
    flash('Item added to cart', 'success')
    return redirect(url_for('shop'))

@app.route('/cart')
def cart():
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

@app.route('/remove-from-cart/<product_id>')
def remove_from_cart(product_id):
    if product_id in session.get('cart', {}):
        session['cart'].pop(product_id)
        session.modified = True
        flash('Item removed from cart', 'info')
    return redirect(url_for('cart'))

@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def admin_login():
    if request.method == 'POST':
        if request.form.get('password') == os.environ.get('ADMIN_PASSWORD'):
            session['admin_logged_in'] = True
            return redirect(url_for('add_product'))
        flash('Invalid credentials', 'error')
    return render_template('admin/login.html')

@app.route('/admin/add-product', methods=['GET', 'POST'])
@admin_required
@limiter.limit("10 per minute")
def add_product():
    if request.method == 'POST':
        try:
            # Handle file upload
            image_file = request.files['cover_image']
            filename = 'default.jpg'
            
            if image_file and allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
            
            # Get form data
            tracks = [t.strip() for t in request.form['tracks'].split('\n') if t.strip()]
            on_sale = 'on_sale' in request.form
            
            # Price validation
            try:
                price = float(request.form['price'])
                sale_price = float(request.form['sale_price']) if on_sale and request.form['sale_price'] else None
            except ValueError:
                flash('Invalid price format. Please enter numbers only.', 'error')
                return render_template('admin/add_product.html')
            
            # Create new product
            new_product = {
                'id': str(uuid.uuid4()),
                'title': request.form['title'],
                'artist': request.form['artist'],
                'format': request.form['format'],
                'price': price,
                'sale_price': sale_price,
                'image': filename,
                'tracks': tracks,
                'on_sale': on_sale
            }
            
            # Save to database
            products = load_products()
            products.append(new_product)
            save_products(products)
            
            flash('Product added successfully', 'success')
            return redirect(url_for('shop'))
        
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('admin/add_product.html')

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        # Process payment and shipping
        session.pop('cart', None)
        flash('Order placed successfully!', 'success')
        return redirect(url_for('home'))
    
    return render_template('checkout.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    port = int(os.environ.get('PORT', 10000))
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)data:; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src 'self' fonts.gstatic.com; script-src 'self'"
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

# Routes
@app.route('/')
def home():
    return render_template('index.html', featured=load_products()[:3])

@app.route('/shop')
def shop():
    return render_template('shop.html', products=load_products())

@app.route('/product/<product_id>')
def product(product_id):
    products = load_products()
    product = next((p for p in products if p['id'] == product_id), None)
    if product:
        return render_template('product.html', product=product)
    flash('Product not found', 'error')
    return redirect(url_for('shop'))

@app.route('/add-to-cart/<product_id>')
def add_to_cart(product_id):
    if 'cart' not in session:
        session['cart'] = {}
    
    session['cart'][product_id] = session['cart'].get(product_id, 0) + 1
    session.modified = True
    flash('Item added to cart', 'success')
    return redirect(url_for('shop'))

@app.route('/cart')
def cart():
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

@app.route('/remove-from-cart/<product_id>')
def remove_from_cart(product_id):
    if product_id in session.get('cart', {}):
        session['cart'].pop(product_id)
        session.modified = True
        flash('Item removed from cart', 'info')
    return redirect(url_for('cart'))

@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def admin_login():
    if request.method == 'POST':
        if request.form.get('password') == os.environ.get('ADMIN_PASSWORD'):
            session['admin_logged_in'] = True
            return redirect(url_for('add_product'))
        flash('Invalid credentials', 'error')
    return render_template('admin/login.html')

@app.route('/admin/add-product', methods=['GET', 'POST'])
@admin_required
@limiter.limit("10 per minute")
def add_product():
    if request.method == 'POST':
        try:
            # Handle file upload
            image_file = request.files['cover_image']
            filename = 'default.jpg'
            
            if image_file and allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
            
            # Get form data
            tracks = [t.strip() for t in request.form['tracks'].split('\n') if t.strip()]
            on_sale = 'on_sale' in request.form
            
            # Price validation
            try:
                price = float(request.form['price'])
                sale_price = float(request.form['sale_price']) if on_sale and request.form['sale_price'] else None
            except ValueError:
                flash('Invalid price format. Please enter numbers only.', 'error')
                return render_template('admin/add_product.html')
            
            # Create new product
            new_product = {
                'id': str(uuid.uuid4()),
                'title': request.form['title'],
                'artist': request.form['artist'],
                'format': request.form['format'],
                'price': price,
                'sale_price': sale_price,
                'image': filename,
                'tracks': tracks,
                'on_sale': on_sale
            }
            
            # Save to database
            products = load_products()
            products.append(new_product)
            save_products(products)
            
            flash('Product added successfully', 'success')
            return redirect(url_for('shop'))
        
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('admin/add_product.html')

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        # Process payment and shipping
        session.pop('cart', None)
        flash('Order placed successfully!', 'success')
        return redirect(url_for('home'))
    
    return render_template('checkout.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('DEBUG', 'False') == 'True')import os
import json
import uuid
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['UPLOAD_FOLDER'] = 'static/uploads/covers'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png', 'webp'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB
csrf = CSRFProtect(app)

# Fixed Rate Limiting initialization
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)  # Properly attach the app using init_app

# VAT Configuration
VAT_RATE = 0.20  # 20% VAT

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def load_products():
    if not os.path.exists('data/products.json'):
        os.makedirs('data', exist_ok=True)
        with open('data/products.json', 'w') as f:
            json.dump([], f)
        return []
    
    with open('data/products.json', 'r') as f:
        return json.load(f)

def save_products(products):
    with open('data/products.json', 'w') as f:
        json.dump(products, f, indent=2)

# Admin authentication
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('admin_logged_in') != True:
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

# Routes
@app.route('/')
def home():
    return render_template('index.html', featured=load_products()[:3])

@app.route('/shop')
def shop():
    return render_template('shop.html', products=load_products())

@app.route('/product/<product_id>')
def product(product_id):
    products = load_products()
    product = next((p for p in products if p['id'] == product_id), None)
    if product:
        return render_template('product.html', product=product)
    flash('Product not found', 'error')
    return redirect(url_for('shop'))

@app.route('/add-to-cart/<product_id>')
def add_to_cart(product_id):
    if 'cart' not in session:
        session['cart'] = {}
    
    session['cart'][product_id] = session['cart'].get(product_id, 0) + 1
    session.modified = True
    flash('Item added to cart', 'success')
    return redirect(url_for('shop'))

@app.route('/cart')
def cart():
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

@app.route('/remove-from-cart/<product_id>')
def remove_from_cart(product_id):
    if product_id in session.get('cart', {}):
        session['cart'].pop(product_id)
        session.modified = True
        flash('Item removed from cart', 'info')
    return redirect(url_for('cart'))

@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def admin_login():
    if request.method == 'POST':
        if request.form.get('password') == os.environ.get('ADMIN_PASSWORD'):
            session['admin_logged_in'] = True
            return redirect(url_for('add_product'))
        flash('Invalid credentials', 'error')
    return render_template('admin/login.html')

@app.route('/admin/add-product', methods=['GET', 'POST'])
@admin_required
@limiter.limit("10 per minute")
def add_product():
    if request.method == 'POST':
        try:
            # Handle file upload
            image_file = request.files['cover_image']
            filename = 'default.jpg'
            
            if image_file and allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
            
            # Get form data
            tracks = [t.strip() for t in request.form['tracks'].split('\n') if t.strip()]
            on_sale = 'on_sale' in request.form
            
            # Price validation
            try:
                price = float(request.form['price'])
                sale_price = float(request.form['sale_price']) if on_sale and request.form['sale_price'] else None
            except ValueError:
                flash('Invalid price format. Please enter numbers only.', 'error')
                return render_template('admin/add_product.html')
            
            # Create new product
            new_product = {
                'id': str(uuid.uuid4()),
                'title': request.form['title'],
                'artist': request.form['artist'],
                'format': request.form['format'],
                'price': price,
                'sale_price': sale_price,
                'image': filename,
                'tracks': tracks,
                'on_sale': on_sale
            }
            
            # Save to database
            products = load_products()
            products.append(new_product)
            save_products(products)
            
            flash('Product added successfully', 'success')
            return redirect(url_for('shop'))
        
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('admin/add_product.html')

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        # Process payment and shipping
        session.pop('cart', None)
        flash('Order placed successfully!', 'success')
        return redirect(url_for('home'))
    
    return render_template('checkout.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('DEBUG', 'False') == 'True')
