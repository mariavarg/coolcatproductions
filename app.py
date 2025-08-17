import json
import os
from flask import Flask, render_template, request, redirect, url_for
from project import calculate_price_with_vat, format_album_title, apply_discount

app = Flask(__name__)

# Path to albums.json and orders.json
ALBUMS_FILE = os.path.join("data", "albums.json")
ORDERS_FILE = os.path.join("data", "orders.json")


def load_albums():
    with open(ALBUMS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_order(order):
    orders = []
    if os.path.exists(ORDERS_FILE):
        with open(ORDERS_FILE, "r", encoding="utf-8") as f:
            try:
                orders = json.load(f)
            except json.JSONDecodeError:
                orders = []
    orders.append(order)
    with open(ORDERS_FILE, "w", encoding="utf-8") as f:
        json.dump(orders, f, indent=4)


@app.route("/")
def home():
    albums = load_albums()
    return render_template("shop.html", albums=albums)


@app.route("/order/<int:album_id>", methods=["GET", "POST"])
def order(album_id):
    albums = load_albums()
    album = albums[album_id]

    # Calculate total with VAT
    price = float(album["price"])
    total = calculate_price_with_vat(price)

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        quantity = int(request.form["quantity"])
        final_total = round(total * quantity, 2)

        order = {
            "album": album["title"],
            "artist": album["artist"],
            "price": price,
            "quantity": quantity,
            "customer_name": name,
            "customer_email": email,
            "total": final_total,
        }

        save_order(order)

        return redirect(url_for("home"))

    return render_template("order.html", album=album, total=total)


if __name__ == "__main__":
    app.run(debug=True)
