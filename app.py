from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import json
import uuid
from werkzeug.utils import secure_filename

# Initialize Flask app
app = Flask(__name__)

# ======================
# BASIC CONFIGURATION
# ======================

# Secret key for sessions (in production, use environment variable)
app.secret_key = 'your-secret-key-here'  # Change this!

# File upload settings
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ======================
# HELPER FUNCTIONS
# ======================

def load_products():
    """Load products from JSON file"""
    if not os.path.exists('data/products.json'):
        os.makedirs('data', exist_ok=True)
        with open('data/products.json', 'w') as f:
            json.dump([], f)
        return []
    
    with open('data/products.json', 'r') as f:
        return json.load(f)

def save_products(products):
    """Save products to JSON file"""
    with open('data/products.json', 'w') as f:
        json.dump(products, f, indent=2)

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ======================
# ROUTES
# ======================

@app.route('/')
def home():
    """Homepage with featured products"""
    products = load_products()
    return render_template('home.html', featured=products[:3])

@app.route('/shop')
def shop():
    """Product listing page"""
    products = load_products()
    cart_count = sum(session.get('cart', {}).values())
    return render_template('shop.html', products=products, cart_count=cart_count)

@app.route('/add-to-cart/<product_id>')
def add_to_cart(product_id):
    """Add item to cart"""
    if 'cart' not in session:
        session['cart'] = {}
    
    products = load_products()
    if any(p['id'] == product_id for p in products):
        session['cart'][product_id] = session['cart'].get(product_id, 0) + 1
        session.modified = True
        flash('Item added to cart!', 'success')
    else:
        flash('Product not found!', 'error')
    
    return redirect(url_for('shop'))

@app.route('/checkout')
def checkout():
    """Checkout page"""
    cart = session.get('cart', {})
    products = {p['id']: p for p in load_products()}
    
    cart_items = []
    total = 0.0
    
    for product_id, quantity in cart.items():
        if product_id in products:
            product = products[product_id]
            cart_items.append({
                'details': product,
                'quantity': quantity
            })
            total += float(product['price']) * quantity
    
    return render_template('checkout.html', cart=cart_items, total=total)

@app.route('/remove-from-cart/<product_id>')
def remove_from_cart(product_id):
    """Remove item from cart"""
    if product_id in session.get('cart', {}):
        session['cart'].pop(product_id)
        session.modified = True
        flash('Item removed from cart', 'info')
    return redirect(url_for('checkout'))

# ======================
# ADMIN ROUTES
# ======================

@app.route('/admin/add-product', methods=['GET', 'POST'])
def add_product():
    """Add new product"""
    if request.method == 'POST':
        try:
            # Handle file upload
            image_file = request.files['image']
            filename = 'default.jpg'
            
            if image_file and allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename)
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            # Create new product
            new_product = {
                'id': str(uuid.uuid4()),
                'name': request.form['name'],
                'price': "{:.2f}".format(float(request.form['price'])),
                'description': request.form.get('description', ''),
                'image': filename
            }
            
            # Save to database
            products = load_products()
            products.append(new_product)
            save_products(products)
            
            flash('Product added successfully!', 'success')
            return redirect(url_for('shop'))
        
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('admin/add_product.html')

# ======================
# ERROR HANDLERS
# ======================

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# ======================
# RUN THE APP
# ======================

if __name__ == '__main__':
    # Create necessary folders
    os.makedirs('data', exist_ok=True)
    os.makedirs('static/uploads', exist_ok=True)
    os.makedirs('static/images', exist_ok=True)
    
    # Create default product image if not exists
    if not os.path.exists('static/images/default.jpg'):
        from PIL import Image, ImageDraw
        img = Image.new('RGB', (400, 400), color=(220, 220, 220))
        d = ImageDraw.Draw(img)
        d.text((100, 180), "No Image", fill=(100, 100, 100))
        img.save('static/images/default.jpg')
    
    # Run the app
    app.run(debug=True, port=5000)
