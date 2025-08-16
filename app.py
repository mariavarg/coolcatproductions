cat > app.py <<'EOF'
from flask import Flask, render_template
app = Flask(__name__)

DRUNAC_CATALOG = [
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
    return render_template('shop.html', products=DRUNAC_CATALOG)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
EOF
