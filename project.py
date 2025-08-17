def calculate_price_with_vat(price, vat_rate=0.24):
    """Calculate price including VAT (default 24%)."""
    return round(price * (1 + vat_rate), 2)


def format_album_title(title):
    """Format album title (capitalized)."""
    return title.strip().title()


def apply_discount(price, discount_percentage):
    """Apply discount to price."""
    return round(price * (1 - discount_percentage / 100), 2)


def main():
    print("Cool Cat Productions backend is ready")
