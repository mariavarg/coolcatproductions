def calculate_price_with_vat(price, vat_rate=0.24):
    """Υπολογίζει την τελική τιμή με ΦΠΑ"""
    return round(price * (1 + vat_rate), 2)

def format_album_title(title):
    """Μορφοποιεί τον τίτλο άλμπουμ με κεφαλαία γράμματα αρχικών"""
    return title.title()

def apply_discount(price, discount_percent):
    """Εφαρμόζει έκπτωση σε τιμή"""
    return round(price * (1 - discount_percent / 100), 2)

def main():
    """Κύρια συνάρτηση για δοκιμή"""
    price = 10
    print("Base Price:", price)
    print("With VAT:", calculate_price_with_vat(price))
    print("Formatted Title:", format_album_title("dark side of the moon"))
    print("Discounted:", apply_discount(price, 10))

if __name__ == "__main__":
    main()
