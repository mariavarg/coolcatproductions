from flask import Flask, render_template, request, redirect, url_for, session
import os
import json
import uuid

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for sessions

# Product Database Setup
DB_FILE = 'data/products.json'

def load_products():
    if not os.path.exists(DB_FILE):
        os.makedirs('data', exist_ok=True)
        with open(DB_FILE, 'w') as f:
            json.dump([], f)
        return []
    with open(DB_FILE, 'r') as f:
        return json.load(f)

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/shop')
def shop():
    products = load_products()
    return render_template('shop.html', products=products)

@app.route('/add-to-cart/<product_id>')
def add_to_cart(product_id):
    if 'cart' not in session:
        session['cart'] = []
    
    products = load_products()
    product = next((p for p in products if p['id'] == product_id), None)
    
    if product:
        session['cart'].append(product)
        session.modified = True
    
    return redirect(url_for('shop'))

@app.route('/checkout')
def checkout():
    cart = session.get('cart', [])
    total = sum(float(p['price']) for p in cart)
    return render_template('checkout.html', cart=cart, total=total)

if __name__ == '__main__':
    os.makedirs('static/uploads', exist_ok=True)
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)))
