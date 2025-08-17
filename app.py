import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

# Initialize Flask app
app = Flask(__name__)

# Load environment variables
load_dotenv()

# Configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY') or os.urandom(24).hex(),
    ENV=os.environ.get('FLASK_ENV', 'production'),
    DEBUG=os.environ.get('FLASK_ENV') == 'development',
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///app.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False
)

# Initialize extensions
db = SQLAlchemy(app)
CORS(app)  # Remove if not needed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Log all requests
@app.before_request
def log_request():
    logger.info(f"{request.method} {request.path} - IP: {request.remote_addr}")

# Health check endpoint
@app.route('/health')
def health_check():
    try:
        # Test database connection
        db.engine.execute("SELECT 1")
        return jsonify({"status": "healthy"}), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({"status": "unhealthy"}), 500

# Debug routes (only in development)
if app.debug and app.config['ENV'] == 'development':
    @app.route('/debug')
    def debug_info():
        return jsonify({
            "session": dict(session),
            "config": {k: v for k, v in app.config.items() if not k.startswith('SECRET')}
        })

# Error handlers
@app.errorhandler(404)
def not_found(e):
    if request.accept_mimetypes.accept_json:
        return jsonify({"error": "Not found"}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Server error: {str(e)}")
    return render_template('500.html'), 500

# Your existing routes here...

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
