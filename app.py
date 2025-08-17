import os
import json
from flask import Flask, request, jsonify, redirect, url_for, render_template, abort
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from dotenv import load_dotenv

# Initialize Flask app
app = Flask(__name__)

# Load environment variables
load_dotenv()

# Configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(24).hex()),
    DEBUG=os.environ.get('DEBUG', 'False').lower() == 'true',
    DATA_FILE='data.json',
    UPLOAD_FOLDER='uploads',
    ALLOWED_EXTENSIONS={'txt', 'pdf', 'png', 'jpg'}
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# JSON Data Helpers
def load_data():
    """Load data from JSON file or return default structure"""
    try:
        with open(app.config['DATA_FILE'], 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "users": [],
            "posts": [],
            "files": []
        }

def save_data(data):
    """Save data to JSON file"""
    with open(app.config['DATA_FILE'], 'w') as f:
        json.dump(data, f, indent=2)

# Routes
@app.route('/')
def home():
    """Homepage with API instructions"""
    return render_template('index.html')

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    try:
        data = load_data()  # Test JSON access
        return jsonify({
            "status": "healthy",
            "users": len(data['users']),
            "posts": len(data['posts'])
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({"status": "unhealthy"}), 500

@app.route('/api/users', methods=['GET', 'POST'])
def users():
    """User management endpoint"""
    data = load_data()
    
    if request.method == 'POST':
        new_user = {
            "id": len(data['users']) + 1,
            "username": request.json.get('username'),
            "email": request.json.get('email'),
            "password": generate_password_hash(request.json.get('password'))
        }
        data['users'].append(new_user)
        save_data(data)
        return jsonify(new_user), 201
    
    return jsonify(data['users'])

@app.route('/api/users/<int:user_id>', methods=['GET', 'DELETE'])
def user_detail(user_id):
    """Single user operations"""
    data = load_data()
    user = next((u for u in data['users'] if u['id'] == user_id), None)
    
    if not user:
        abort(404, description="User not found")
    
    if request.method == 'DELETE':
        data['users'] = [u for u in data['users'] if u['id'] != user_id]
        save_data(data)
        return jsonify({"message": "User deleted"}), 200
    
    return jsonify(user)

# File Upload Example
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/upload', methods=['POST'])
def upload_file():
    """File upload endpoint"""
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        data = load_data()
        data['files'].append({
            "id": len(data['files']) + 1,
            "name": filename,
            "path": f"/uploads/{filename}"
        })
        save_data(data)
        
        return jsonify({"message": "File uploaded successfully"}), 201
    
    return jsonify({"error": "File type not allowed"}), 400

# Error Handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify(error=str(e)), 404

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Server error: {str(e)}")
    return jsonify(error="Internal server error"), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=app.config['DEBUG'])
