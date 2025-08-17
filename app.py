import os
import json
import uuid
import logging
import re
import traceback
import datetime  # Make sure to import datetime
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
        'current_year': datetime.datetime.now().year  # Add current year here
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

# ... (rest of the routes remain the same) ...

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
