import os
from datetime import timedelta

class SecurityConfig:
    # Session security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    
    # Rate limiting
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_WINDOW = 300  # 5 minutes in seconds
    LOCKOUT_TIME = 900  # 15 minutes in seconds
    
    # Password policies
    MIN_PASSWORD_LENGTH = 12
    PASSWORD_COMPLEXITY = {
        'min_uppercase': 1,
        'min_lowercase': 1,
        'min_digits': 1,
        'min_special': 1
    }
    
    # File upload restrictions
    MAX_FILE_SIZES = {
        'image': 50 * 1024 * 1024,  # 50MB
        'music': 100 * 1024 * 1024,  # 100MB
        'video': 1024 * 1024 * 1024  # 1GB
    }
    
    # Allowed file extensions
    ALLOWED_EXTENSIONS = {
        'image': {'png', 'jpg', 'jpeg', 'webp'},
        'music': {'mp3', 'wav', 'flac'},
        'video': {'mp4', 'mov', 'avi', 'webm', 'mkv'}
    }
    
    # Content Security Policy
    CSP_DIRECTIVES = {
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net",
        'style-src': "'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://cdn.jsdelivr.net",
        'font-src': "'self' https://fonts.gstatic.com",
        'img-src': "'self' data: blob: https:",
        'media-src': "'self' blob:",
        'frame-ancestors': "'none'",
        'form-action': "'self'",
        'base-uri': "'self'",
        'object-src': "'none'"
    }
    
    # HTTP Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        'Cross-Origin-Embedder-Policy': 'require-corp',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Resource-Policy': 'same-origin'
    }
