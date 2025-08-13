# test_project.py
from project import calculate_price_with_vat, format_album_title, apply_discount
import pytest

def test_calculate_price_with_vat():
    assert calculate_price_with_vat(100, 0.24) == 124.0
    assert calculate_price_with_vat(50, 0.10) == 55.0
    with pytest.raises(ValueError):
        calculate_price_with_vat(-10)

def test_format_album_title():
    assert format_album_title("dark side of the moon") == "Dark Side Of The Moon"
    assert format_album_title("  abbey road  ") == "Abbey Road"

def test_apply_discount():
    assert apply_discount(100, 10) == 90.0
    assert apply_discount(200, 50) == 100.0
    with pytest.raises(ValueError):
        apply_discount(100, -5)
    with pytest.raises(ValueError):
        apply_discount(100, 150)
