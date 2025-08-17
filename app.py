import os
import json
import uuid
import logging
import re
import traceback
import datetime
import shutil
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
os.makedirs('data/backups', exist_ok=True)  # Create backup directory

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
        # First try to parse directly
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        logger.warning(f"JSON repair needed: {str(e)}")
        try:
            # Try to fix common issues
            repaired = json_str
            
            # Replace single quotes with double quotes for property names
            repaired = re.sub(r"(\s*)(\w+)(\s*):", r'\1"\2"\3:', repaired)
            
            # Remove trailing commas
            repaired = re.sub(r',\s*([}\]])', r'\1', repaired)
            
            # Escape unescaped quotes
            repaired = re.sub(r'(?<!\\)"', r'\"', repaired)
            
            # Try parsing again
            return json.loads(repaired)
        except Exception as e2:
            logger.error(f"JSON repair failed: {str(e2)}")
            raise  # Re-raise to handle in calling function

def load_products():
    try:
        file_path = 'data/products.json'
        backup_dir = 'data/backups'
        
        # Create file if it doesn't exist
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                json.dump([], f)
            return []
        
        # Load and validate JSON
        with open(file_path, 'r') as f:
            content = f.read()
            
            # If file is empty, return empty list
            if not content.strip():
                return []
                
            try:
                return json.loads(content)
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error: {str(e)} - attempting repair")
                
                try:
                    # Attempt to repair JSON
                    repaired = repair_json(content)
                    
                    # Save repaired version
                    with open(file_path, 'w') as outfile:
                        json.dump(repaired, outfile, indent=2)
                    
                    return repaired
                except Exception as repair_error:
                    logger.critical(f"Critical JSON repair failed: {str(repair_error)}")
                    
                    # Create backup of corrupted file
                    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    backup_path = os.path.join(backup_dir, f"products_backup_{timestamp}.json")
                    with open(backup_path, 'w') as backup_file:
                        backup_file.write(content)
                    
                    logger.info(f"Created backup of corrupted file at {backup_path}")
                    
                    # Reset to empty products list
                    with open(file_path, 'w') as reset_file:
                        json.dump([], reset_file)
                    
                    logger.warning("Reset products.json to empty list due to irreparable corruption")
                    return []
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

# Context processor to inject brand name and current year
@app.context_processor
def inject_global_data():
    return {
        'brand': BRAND_NAME,
        'current_year': datetime.datetime.now().year
    }

# ... (rest of the code remains the same as previous working version) ...
