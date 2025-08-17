import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from dotenv import load_dotenv

# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(24).hex()),
    UPLOAD_FOLDER='static/uploads',
    ALLOWED_EXTENSIONS={'jpg', 'jpeg', 'png', 'webp'},
    MAX_CONTENT_LENGTH=5 * 1024 * 1024  # 5MB
)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Constants
BRAND_NAME = "Cool Cat Productions-Druna C."
CACHE_BUSTER = str(int(datetime.datetime.now().timestamp()))

# Helper function
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Context processor
@app.context_processor
def inject_globals():
    return {
        'brand': BRAND_NAME,
        'current_year': datetime.datetime.now().year,
        'cache_buster': CACHE_BUSTER,
        'cart_count': len(session.get('cart', []))
    }

# Routes
@app.route('/')
def home():
    try:
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error rendering home: {str(e)}")
        abort(500)

@app.route('/shop')
def shop():
    return render_template('shop.html')

@app.route('/cart')
def cart():
    return render_template('cart.html')

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        # Add your authentication logic here
        pass
    return render_template('admin/login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('home'))

@app.route('/admin/add-product')
def add_product():
    return render_template('admin/add_product.html')

# Health check
@app.route('/health')
def health_check():
    return jsonify({"status": "healthy"}), 200

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Server error: {str(e)}")
    return render_template('500.html'), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
