from flask import Flask, render_template, session
import os
import json

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# Database setup
ALBUMS_FILE = 'data/albums.json'
os.makedirs('data', exist_ok=True)
os.makedirs('static/images/covers', exist_ok=True)

def load_albums():
    if not os.path.exists(ALBUMS_FILE):
        with open(ALBUMS_FILE, 'w') as f:
            json.dump([], f)
        return []
    with open(ALBUMS_FILE, 'r') as f:
        return json.load(f)

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
