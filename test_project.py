from project import calculate_price_with_vat, format_album_title, apply_discount

def test_calculate_price_with_vat():
    assert calculate_price_with_vat(100) == 124.0
    assert calculate_price_with_vat(50, 0.10) == 55.0

def test_format_album_title():
    assert format_album_title("the loveliest dead") == "The Loveliest Dead"

def test_apply_discount():
    assert apply_discount(100, 10) == 90.0
    assert apply_discount(200, 50) == 100.0

