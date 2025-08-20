from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html', albums=[])

@app.route('/shop')
def shop():
    return render_template('shop.html', albums=[])

@app.route('/album/<int:album_id>')
def album(album_id):
    return render_template('album.html', album={'id': album_id, 'title': 'Sample', 'artist': 'Artist'})

@app.route('/admin/login')
def admin_login():
    return render_template('admin/login.html')

@app.route('/register')
def register():
    return render_template('register.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
