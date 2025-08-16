from flask import Flask, render_template
import os
import json

app = Flask(__name__)

# Database setup
ALBUMS_FILE = 'data/albums.json'
os.makedirs('data', exist_ok=True)
os.makedirs('static/images/covers', exist_ok=True)

def load_albums():
    try:
        if not os.path.exists(ALBUMS_FILE):
            # Initialize with your two albums
            initial_albums = [
                {
                    "id": "1",
                    "title": "YOUR FIRST ALBUM",
                    "artist": "ARTIST NAME",
                    "year": "2023",
                    "price": "24.99",
                    "image": "your-first-cover.jpg",
                    "tracks": ["Track 1", "Track 2"]
                },
                {
                    "id": "2", 
                    "title": "YOUR SECOND ALBUM",
                    "artist": "ARTIST NAME",
                    "year": "2023",
                    "price": "19.99",
                    "image": "your-second-cover.jpg",
                    "tracks": ["Track A", "Track B"]
                }
            ]
            with open(ALBUMS_FILE, 'w') as f:
                json.dump(initial_albums, f, indent=2)
            return initial_albums
        
        with open(ALBUMS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading albums: {str(e)}")
        return []

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/shop')
def shop():
    albums = load_albums()
    return render_template('shop.html', albums=albums)

@app.route('/checkout')
def checkout():
    return render_template('checkout.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
