import os
import json
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
    DEBUG=os.environ.get('DEBUG', 'False').lower() == 'true'
)

# JSON file for data storage
DATA_FILE = "data.json"

def load_data():
    """Load data from JSON file"""
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"users": [], "posts": []}  # Default structure

def save_data(data):
    """Save data to JSON file"""
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# Example route storing data in JSON
@app.route('/add_user', methods=['POST'])
def add_user():
    data = load_data()
    new_user = {
        "id": len(data["users"]) + 1,
        "username": request.form.get("username"),
        "email": request.form.get("email")
    }
    data["users"].append(new_user)
    save_data(data)
    return jsonify({"message": "User added", "user": new_user}), 201

@app.route('/get_users')
def get_users():
    data = load_data()
    return jsonify(data["users"])

# Health check endpoint (updated to check JSON instead of DB)
@app.route('/health')
def health_check():
    try:
        load_data()  # Test JSON read
        return jsonify({"status": "healthy"}), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({"status": "unhealthy"}), 500

# Rest of your routes...

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=app.debug)
