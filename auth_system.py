import time
import secrets
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session, request

class AuthSystem:
    def __init__(self):
        self.login_attempts = {}
        self.failed_login_lockout = {}
        self.two_factor_tokens = {}
    
    def generate_csrf_token(self):
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        return session['csrf_token']
    
    def validate_csrf_token(self):
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            return True
        token = request.form.get('csrf_token')
        return token and secrets.compare_digest(token, session.get('csrf_token', ''))
    
    def check_rate_limit(self, ip, endpoint, max_attempts=5, window=300):
        now = time.time()
        key = f"{ip}_{endpoint}"
        
        # Clear old attempts
        if key in self.login_attempts:
            self.login_attempts[key] = [t for t in self.login_attempts[key] if now - t < window]
        
        if key not in self.login_attempts:
            self.login_attempts[key] = []
        
        if len(self.login_attempts[key]) >= max_attempts:
            # Lockout for 15 minutes after too many attempts
            self.failed_login_lockout[key] = now + 900
            return False
            
        self.login_attempts[key].append(now)
        return True
    
    def is_locked_out(self, ip, endpoint):
        key = f"{ip}_{endpoint}"
        if key in self.failed_login_lockout:
            if time.time() < self.failed_login_lockout[key]:
                return True
            else:
                del self.failed_login_lockout[key]
        return False
    
    def generate_2fa_token(self, user_id):
        token = secrets.token_hex(3)  # 6-digit code
        expiry = datetime.now() + timedelta(minutes=10)
        
        self.two_factor_tokens[user_id] = {
            'token': token,
            'expiry': expiry.isoformat()
        }
        return token
    
    def verify_2fa_token(self, user_id, token):
        if user_id not in self.two_factor_tokens:
            return False
            
        token_data = self.two_factor_tokens[user_id]
        expiry = datetime.fromisoformat(token_data['expiry'])
        
        if datetime.now() > expiry:
            self.two_factor_tokens.pop(user_id)
            return False
            
        return secrets.compare_digest(token, token_data['token'])
    
    def is_password_complex(self, password, min_length=12):
        if len(password) < min_length:
            return False, "Password must be at least 12 characters long"
        
        checks = [
            (r'[A-Z]', "uppercase letter"),
            (r'[a-z]', "lowercase letter"),
            (r'[0-9]', "number"),
            (r'[!@#$%^&*(),.?\":{}|<>]', "special character")
        ]
        
        for pattern, requirement in checks:
            if not re.search(pattern, password):
                return False, f"Password must contain at least one {requirement}"
        
        return True, "Password is strong"
