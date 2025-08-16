import json
import os
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename

"""
project.py - Helper functions for album pricing and formatting
"""

def calculate_price_with_vat(price, vat_rate=0.2):
    """
    Calculate price including VAT (Value Added Tax)
    
    Args:
        price (float): Base price before tax
        vat_rate (float): VAT rate (default 20%)
    
    Returns:
        float: Price including VAT rounded to 2 decimals
    """
    try:
        return round(float(price) * (1 + float(vat_rate)), 2)
    except (TypeError, ValueError):
        return 0.00  # Fallback for invalid inputs


def format_album_title(title):
    """
    Format album title to standard capitalization
    
    Args:
        title (str): Raw title string
    
    Returns:
        str: Title in Title Case (e.g., "the dark side" → "The Dark Side")
    """
    if not isinstance(title, str):
        return str(title)
    return title.title()


def apply_discount(price, discount_percent):
    """
    Apply percentage discount to a price
    
    Args:
        price (float): Original price
        discount_percent (float): Discount percentage (e.g., 10 for 10%)
    
    Returns:
        float: Discounted price rounded to 2 decimals
    """
    try:
        return round(float(price) * (1 - float(discount_percent)/100), 2)
    except (TypeError, ValueError):
        return float(price)  # Return original if discount is invalid


# Optional: Add test cases when run directly
if __name__ == "__main__":
    # Test VAT calculation
    print(f"£10 + VAT: £{calculate_price_with_vat(10)}")  # Should show £12.00
    
    # Test title formatting
    print(f"Formatted title: {format_album_title('the BEST album')}")  # "The Best Album"
    
    # Test discount
    print(f"£50 with 10% off: £{apply_discount(50, 10)}")  # Should show £45.00
