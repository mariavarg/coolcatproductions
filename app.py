from flask import Flask, render_template
import os
import json

app = Flask(__name__)

# Configuration
ALBUMS_FILE = os.path.join('data', 'albums.json')
COVERS_DIR = os.path.join('static', 'images', 'covers')

# Create directories if they don't exist
os.makedirs('data', exist_ok=True)
os.makedirs(COVERS_DIR, exist_ok=True)

def load_albums():
    try:
        if not os.path.exists(ALBUMS_FILE):
            # Initialize empty if file doesn't exist
            with open(ALBUMS_FILE, 'w') as f:
                json.dump([], f)
            return []

        with open(ALBUMS_FILE) as f:
            albums = json.load(f)
            
            # Verify each album has required fields
            required_fields = ['id', 'title', 'artist', 'image']
            for album in albums:
                if not all(field in album for field in required_fields):
                    raise ValueError("Missing required album fields")
            
            return albums

    except Exception as e:
        print(f"ERROR LOADING ALBUMS: {str(e)}")
        return []  # Return empty list if error occurs

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/shop')
def shop():
    try:
        albums = load_albums()
        # Verify images exist
        for album in albums:
            img_path = os.path.join(COVERS_DIR, album['image'])
            if not os.path.exists(img_path):
                print(f"Missing image: {img_path}")
        return render_template('shop.html', albums=albums)
    except Exception as e:
        print(f"SHOP ROUTE ERROR: {str(e)}")
        return render_template('shop.html', albums=[])

@app.route('/checkout')
def checkout():
    return render_template('checkout.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
