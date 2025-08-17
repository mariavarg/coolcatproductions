import os

# Create directories
os.makedirs('static/css', exist_ok=True)
os.makedirs('static/js', exist_ok=True)
os.makedirs('static/uploads/covers', exist_ok=True)
os.makedirs('templates/admin', exist_ok=True)

# Create empty CSS and JS files
open('static/css/style.css', 'a').close()
open('static/js/main.js', 'a').close()

# Create template files
templates = [
    'templates/base.html',
    'templates/index.html',
    'templates/shop.html',
    'templates/product.html',
    'templates/cart.html',
    'templates/privacy.html',
    'templates/error.html',
    'templates/admin/login.html',
    'templates/admin/add_product.html'
]

for file in templates:
    open(file, 'a').close()

print("Folder structure and empty files created successfully.")
