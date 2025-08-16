from flask import Flask, render_template, request, redirect, url_for
import json
import os

app = Flask(__name__)

# JSON database setup
DB_FILE = 'data/albums.json'

def load_albums():
    """Load albums from JSON file"""
    if not os.path.exists(DB_FILE):
        os.makedirs('data', exist_ok=True)
        with open(DB_FILE, 'w') as f:
            json.dump([], f)
        return []
    
    with open(DB_FILE, 'r') as f:
        return json.load(f)

def save_albums(albums):
    """Save albums to JSON file"""
    with open(DB_FILE, 'w') as f:
        json.dump(albums, f, indent=2)

@app.route('/')
def home():
    """Show all albums"""
    return render_template('shop.html', albums=load_albums())

@app.route('/add', methods=['POST'])
def add_album():
    """Add new album"""
    albums = load_albums()
    albums.append({
        "id": len(albums) + 1,
        "title": request.form['title'],
        "artist": request.form['artist'],
        "price": float(request.form['price']),
        "image": "placeholder.jpg"  # Default image
    })
    save_albums(albums)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run()
