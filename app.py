cat > app.py <<'EOF'
from flask import Flask, render_template
app = Flask(__name__)

DRUNAC_INVENTORY = [
    {
        "id": "drc-001",
        "title": "DRUNA C - VOL. 1",
        "artist": "CoolCat Productions",
        "format": "vinyl",
        "price": 34.99,
        "image": "druna-vol1.jpg",
        "tracks": ["Track 1", "Track 2", "Track 3"]
    },
    {
        "id": "drc-002",
        "title": "DRUNA C - VOL. 2",
        "artist": "CoolCat Productions", 
        "format": "cd",
        "price": 14.99,
        "image": "druna-vol2.jpg",
        "tracks": ["Track A", "Track B"]
    },
    {
        "id": "drc-003",
        "title": "DRUNA C - DIGITAL COLLECTION",
        "artist": "CoolCat Productions",
        "format": "mp3",
        "price": 9.99,
        "image": "druna-digital.jpg",
        "tracks": ["Digital 1", "Digital 2"]
    }
]

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/shop')
def shop():
    return render_template('shop.html', items=DRUNAC_INVENTORY)

@app.route('/format/<fmt>')
def format_filter(fmt):
    filtered = [item for item in DRUNAC_INVENTORY if item['format'] == fmt]
    return render_template('shop.html', items=filtered)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
EOF
