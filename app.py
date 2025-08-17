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
    DEBUG=os.environ.get('DEBUG', 'False').lower() == 'true'
)

# Health check endpoint
@app.route('/health')
def health_check():
    """Endpoint for health checks"""
    try:
        # Test database connection if you have one
        # Test essential services
        return jsonify({
            "status": "healthy",
            "debug": app.debug,
            "environment": os.environ.get('FLASK_ENV', 'production')
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({"status": "unhealthy"}), 500

# Debug routes (only in development)
if app.debug:
    @app.route('/debug')
    def debug_info():
        """Debug information endpoint"""
        return jsonify({
            "session": dict(session),
            "environment": dict(os.environ),
            "config": {k: v for k, v in app.config.items() if not k.startswith('SECRET')}
        })
    
    @app.route('/test-error')
    def test_error():
        """Route to test error handling"""
        raise ValueError("This is a test error")

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Server error: {str(e)}")
    return render_template('500.html'), 500

# Your existing routes here...

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(
        host='0.0.0.0',
        port=port,
        debug=app.debug,
        threaded=True
    )
