from flask import Flask, render_template
import os

app = Flask(__name__)

# DrunaC Catalog
DRUNAC_INVENTORY = [
    {
        "id": "DCR-001",
        "title": "CYBER DAWN VINYL",
        "artist": "Druna C",
        "format": "vinyl",
        "price": 34.99,
        "image": "cyber-dawn.jpg",
        "tracks": ["Neon Sunrise", "Data Storm"]
    }
]

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/shop')
def shop():
    return render_template('shop.html', products=DRUNAC_INVENTORY)

# Required for Render
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
