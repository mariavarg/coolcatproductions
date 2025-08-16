from flask import Flask, render_template, redirect, url_for
import os
import json

app = Flask(__name__)

# ===== Configuration =====
app.secret_key = os.urandom(24)
DB_FILE = 'data/products.json'

# ===== Routes =====
# Only ONE shop_redirect definition
@app.route('/shop')
@app.route('/shop/<path:subpath>')
def shop_redirect(subpath=None):
    return redirect(url_for('sales'), code=301)  # <-- Fix: Added missing comma

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/sales')
def sales():
    products = load_products()
    return render_template('sales.html', products=products)

# ===== Helper Functions =====
def load_products():
    if not os.path.exists(DB_FILE):
        os.makedirs('data', exist_ok=True)
        with open(DB_FILE, 'w') as f:
            json.dump([], f)
    with open(DB_FILE, 'r') as f:
        return json.load(f)

if __name__ == '__main__':
    os.makedirs('static/uploads', exist_ok=True)
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)))
