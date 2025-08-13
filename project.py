# project.py

def main():
    print("Cool Cat Productions - Virtual Record Shop Backend Ready")

def calculate_price_with_vat(price, vat_rate=0.24):
    """
    Υπολογίζει την τελική τιμή με ΦΠΑ.
    :param price: float - αρχική τιμή
    :param vat_rate: float - ποσοστό ΦΠΑ (προεπιλογή 24%)
    """
    if price < 0:
        raise ValueError("Η τιμή δεν μπορεί να είναι αρνητική")
    return round(price * (1 + vat_rate), 2)

def format_album_title(title):
    """
    Φορμάρει τον τίτλο άλμπουμ ώστε να ξεκινά με κεφαλαίο.
    """
    return title.strip().title()

def apply_discount(price, discount_percentage):
    """
    Εφαρμόζει έκπτωση σε τιμή.
    """
    if not (0 <= discount_percentage <= 100):
        raise ValueError("Το ποσοστό έκπτωσης πρέπει να είναι 0-100")
    return round(price * (1 - discount_percentage / 100), 2)

if __name__ == "__main__":
    main()
