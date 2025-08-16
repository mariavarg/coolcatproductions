from flask import Flask, render_template, request, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename
from project import calculate_price_with_vat, format_album_title, apply_discount

app = Flask(__name__)
app.secret_key = "change_this_secret_key"  # άλλαξε το πριν το deploy

# Ρυθμίσεις για ανέβασμα αρχείων
UPLOAD_FOLDER = 'static/images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Fake database
albums = [
    {"title": "Compilation", "price": 15.0, "cover": "compilation.jpg"},
    {"title": "The Loveliest Dead", "price": 12.0, "cover": "the loveliest dead.jpg"}
]

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/shop')
def shop():
    return render_template('shop.html', albums=albums, calculate_price_with_vat=calculate_price_with_vat)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        title = format_album_title(request.form['title'])
        price = float(request.form['price'])
        file = request.files['cover']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            albums.append({"title": title, "price": price, "cover": filename})
            flash('Album added successfully!', 'success')
        else:
            flash('Invalid file type', 'danger')
        return redirect(url_for('admin'))

    return render_template('admin.html', albums=albums)

@app.route('/checkout/<title>')
def checkout(title):
    album = next((a for a in albums if a["title"] == title), None)
    if not album:
        flash("Album not found", "danger")
        return redirect(url_for('shop'))
    final_price = calculate_price_with_vat(album["price"])
    return render_template('checkout.html', album=album, final_price=final_price)

if __name__ == '__main__':
    app.run(debug=True)
