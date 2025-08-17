import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

# 1. CREATE PROJECT FILES AUTOMATICALLY
def setup_files():
    os.makedirs('static/images/covers', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    
    # Create home.html
    with open('templates/home.html', 'w') as f:
        f.write("""<!DOCTYPE html>
<html>
<head>
    <title>DrunaC Store</title>
    <style>
        body { background: #000; color: #0f0; font-family: monospace; }
        a { color: #0f0; text-decoration: none; border: 1px solid #0f0; padding: 0.5rem; }
    </style>
</head>
<body>
    <h1>COOLCAT PRODUCTIONS</h1>
    <a href="/shop" accesskey="s">ENTER STORE [S]</a>
</body>
</html>""")
    
    # Create shop.html
    with open('templates/shop.html', 'w') as f:
        f.write("""<!DOCTYPE html>
<html>
<head>
    <title>DrunaC Shop</title>
    <style>
        body { background: #000; color: #0f0; font-family: monospace; }
        .product { border: 1px solid #0f0; margin: 1rem; padding: 1rem; }
    </style>
</head>
<body>
    <h1>DRUNA C COLLECTION</h1>
    <div class="product">
        <h2>CYBER DAWN VINYL</h2>
        <p>VINYL • $34.99</p>
    </div>
    <a href="/" accesskey="h">HOME [H]</a>
</body>
</html>""")
    
    # Create placeholder image
    with open('static/images/covers/cyber-dawn.jpg', 'wb') as f:
        f.write(b'')  # Empty file

# 2. CREATE WEB SERVER
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/shop':
            with open('templates/shop.html', 'rb') as f:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(f.read())
        else:
            with open('templates/home.html', 'rb') as f:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(f.read())

# 3. RUN EVERYTHING
if __name__ == '__main__':
    setup_files()
    port = 8000
    print(f"DrunaC Store running at http://localhost:{port}")
    print("Press Ctrl+C to stop")
    server = HTTPServer(('', port), Handler)
    server.serve_forever()
