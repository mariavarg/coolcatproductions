import json
import os
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "super-secret-key"  # 🔒 change to env var later

ALBUMS_FILE = "albums.json"
UPLOAD_FOLDER = "static/images/albums/"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/shop")
def shop():
    with open(ALBUMS_FILE, "r") as f:
        albums = json.load(f)
    return render_template("shop.html", albums=albums)


@app.route("/admin/upload", methods=["GET", "POST"])
def upload_album():
    if request.method == "POST":
        title = request.form["title"]
        artist = request.form["artist"]
        price = request.form["price"]

        file = request.files["image"]
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            # Load existing albums
            with open(ALBUMS_FILE, "r") as f:
                albums = json.load(f)

            # Add new album
            new_album = {
                "title": title,
                "artist": artist,
                "price": float(price),
                "image": filename,
            }
            albums.append(new_album)

            # Save back to JSON
            with open(ALBUMS_FILE, "w") as f:
                json.dump(albums, f, indent=2)

            flash("Album uploaded successfully!", "success")
            return redirect(url_for("shop"))
        else:
            flash("Invalid file type. Only images allowed.", "danger")

    return render_template("upload.html")
