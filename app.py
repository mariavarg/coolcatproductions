import os
import json
from math import ceil
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")  # Use environment variable in production

# Configuration
ALBUMS_FILE = os.path.join(os.getcwd(), "albums.json")
UPLOAD_FOLDER = os.path.join(os.getcwd(), "static", "images", "albums")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
ALBUMS_PER_PAGE = 6  # Number of albums per page

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def initialize_albums_file():
    """Create albums.json if it doesn't exist"""
    if not os.path.exists(ALBUMS_FILE):
        with open(ALBUMS_FILE, "w") as f:
            json.dump([], f)

def save_albums(albums):
    """Save albums to JSON file with error handling"""
    try:
        with open(ALBUMS_FILE, "w") as f:
            json.dump(albums, f, indent=2)
        return True
    except Exception as e:
        app.logger.error(f"Error saving albums: {str(e)}")
        return False

def load_albums():
    """Load albums from JSON file with error handling"""
    initialize_albums_file()
    try:
        with open(ALBUMS_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        app.logger.error("Invalid JSON in albums file, resetting")
        save_albums([])
        return []
    except Exception as e:
        app.logger.error(f"Error loading albums: {str(e)}")
        return []

@app.route("/")
def home():
    return redirect(url_for("shop"))

@app.route("/shop")
@app.route("/shop/<int:page>")
def shop(page=1):
    try:
        albums = load_albums()
        total_albums = len(albums)
        total_pages = ceil(total_albums / ALBUMS_PER_PAGE) or 1  # Ensure at least 1 page
        
        # Validate page number
        page = max(1, min(page, total_pages))
        
        start_idx = (page - 1) * ALBUMS_PER_PAGE
        paginated_albums = albums[start_idx : start_idx + ALBUMS_PER_PAGE]
        
        return render_template(
            "shop.html",
            albums=paginated_albums,
            page=page,
            total_pages=total_pages
        )
    except Exception as e:
        app.logger.error(f"Shop route error: {str(e)}")
        flash("Failed to load albums. Please try again later.", "danger")
        return redirect(url_for("shop"))

@app.route("/admin/upload", methods=["GET", "POST"])
def upload_album():
    if request.method == "POST":
        try:
            # Validate form data
            title = request.form.get("title", "").strip()
            artist = request.form.get("artist", "").strip()
            price = request.form.get("price", "0")
            
            if not title or not artist:
                flash("Title and artist are required", "danger")
                return redirect(url_for("upload_album"))
            
            try:
                price = float(price)
                if price <= 0:
                    raise ValueError("Price must be positive")
            except ValueError:
                flash("Invalid price format", "danger")
                return redirect(url_for("upload_album"))
            
            # Handle file upload
            if "image" not in request.files:
                flash("No file selected", "danger")
                return redirect(url_for("upload_album"))
            
            file = request.files["image"]
            if file.filename == "":
                flash("No selected file", "danger")
                return redirect(url_for("upload_album"))
            
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                
                # Ensure unique filename
                counter = 1
                while os.path.exists(filepath):
                    name, ext = os.path.splitext(filename)
                    filename = f"{name}_{counter}{ext}"
                    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                    counter += 1
                
                file.save(filepath)
                
                # Add new album
                albums = load_albums()
                new_album = {
                    "title": title,
                    "artist": artist,
                    "price": price,
                    "image": filename,
                }
                albums.append(new_album)
                
                if save_albums(albums):
                    flash("Album uploaded successfully!", "success")
                    return redirect(url_for("shop"))
                else:
                    flash("Failed to save album data", "danger")
            else:
                flash("Invalid file type. Allowed: png, jpg, jpeg, gif", "danger")
        
        except Exception as e:
            app.logger.error(f"Upload error: {str(e)}")
            flash("An error occurred during upload", "danger")
    
    return render_template("upload.html")

if __name__ == "__main__":
    app.run(debug=True)
