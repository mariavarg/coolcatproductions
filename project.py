from flask import Flask
app = Flask(__name__)

@app.route("/order/<int:album_id>", methods=["GET", "POST"])
def order(album_id):
    # Load albums
    with open(ALBUMS_FILE, "r") as f:
        albums = json.load(f)

    try:
        album = albums[album_id]
    except IndexError:
        flash("Album not found.", "danger")
        return redirect(url_for("shop"))

    if request.method == "POST":
        customer_name = request.form["name"]
        customer_email = request.form["email"]
        address = request.form["address"]

        # Order details
        order_data = {
            "album": album["title"],
            "artist": album["artist"],
            "price": album["price"],
            "name": customer_name,
            "email": customer_email,
            "address": address,
        }

        # Load existing orders.json or create new list
        if os.path.exists("orders.json"):
            with open("orders.json", "r") as f:
                orders = json.load(f)
        else:
            orders = []

        orders.append(order_data)

        with open("orders.json", "w") as f:
            json.dump(orders, f, indent=2)

        flash("✅ Order placed successfully! We'll contact you soon.", "success")
        return redirect(url_for("shop"))

    return render_template("order.html", album=album, album_id=album_id)
