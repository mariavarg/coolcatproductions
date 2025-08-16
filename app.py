from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import json
import uuid
from werkzeug.utils import secure_filename

app = Flask(__name__)

# ======================
# BASIC SECURITY SETUP (For Beginners)
# ======================

# Generate a random secret key (do this ONCE and keep it secret!)
# In production, use: export SECRET_KEY="your-random-string-here"
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-change-me-in-production')

# ======================
# DATABASE SETUP (Simple JSON)
# ======================

DB_FILE = 'data/products.json'

def load_products():
    """Load products from JSON file"""
    if not os.path.exists(DB_FILE):
        os.makedirs('data', exist_ok=True)
        with open(DB_FILE, 'w') as f:
            json.dump([], f)
        return []
    
    with open(DB_FILE, 'r') as f:
        return json.load(f)

def save_products(products):
    """Save products to JSON file"""
    with open(DB_FILE, 'w') as f:
        json.dump(products, f, indent=2)

# ======================
# ROUTES (Simplified for Beginners)
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
    cart_count = len(session.get('cart', {}))
    return render_template('shop.html', products=products, cart_count=cart_count)

@app.route('/add-to-cart/<product_id>')
def add_to_cart(product_id):
    """Add item to cart (basic version)"""
    if 'cart' not in session:
        session['cart'] = {}
    
    products = load_products()
    product_exists = any(p['id'] == product_id for p in products)
    
    if product_exists:
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
    total = 0
    
    for product_id, quantity in cart.items():
        if product_id in products:
            item = products[product_id]
            item['quantity'] = quantity
            cart_items.append(item)
            total += float(item['price']) * quantity
    
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
# ADMIN SECTION (Basic)
# ======================

@app.route('/admin/add-product', methods=['GET', 'POST'])
def add_product():
    """Simple product addition form"""
    if request.method == 'POST':
        try:
            new_product = {
                'id': str(uuid.uuid4()),
                'name': request.form['name'][:100],  # Limit length
                'price': "{:.2f}".format(float(request.form['price'])),
                'description': request.form.get('description', '')[:500],
                'image': 'default.jpg'  # Basic version - no file upload
            }
            
            products = load_products()
            products.append(new_product)
            save_products(products)
            
            flash('Product added!', 'success')
            return redirect(url_for('shop'))
        except:
            flash('Error adding product', 'error')
    
    return render_template('admin/add_product.html')

# ======================
# ERROR HANDLING (Basic)
# ======================

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# ======================
# RUN THE APP
# ======================

if __name__ == '__main__':
    os.makedirs('data', exist_ok=True)
    os.makedirs('static/uploads', exist_ok=True)
    app.run(debug=True, port=5000)  # Debug mode for development only!
