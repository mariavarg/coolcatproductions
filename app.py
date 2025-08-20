from flask import Flask, render_template

app = Flask(__name__)

# Basic routes - JUST UI, no functionality
@app.route('/')
def home():
    return render_template('index.html', albums=[])

@app.route('/shop')
def shop():
    return render_template('shop.html', albums=[])

@app.route('/album/<int:album_id>')
def album(album_id):
    # Simple dummy data for UI display only
    dummy_album = {
        'id': album_id,
        'title': 'Album Title',
        'artist': 'Artist Name',
        'cover': '/static/images/placeholder.jpg',
        'price': 19.99,
        'tracks': ['Track 1', 'Track 2', 'Track 3']
    }
    return render_template('album.html', album=dummy_album)

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/admin/login')
def admin_login():
    return render_template('admin/login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    return render_template('admin/dashboard.html', album_count=0, user_count=0)

@app.route('/admin/add-album')
def add_album():
    return render_template('admin/add_album.html')

# Remove error handlers temporarily - they might be causing issues
# @app.errorhandler(404)
# def not_found(e):
#     return render_template('404.html'), 404
# 
# @app.errorhandler(500)
# def internal_error(e):
#     return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
