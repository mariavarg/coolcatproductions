import re
import logging
from flask import request, abort
from datetime import datetime

logger = logging.getLogger(__name__)

class SecurityMiddleware:
    def __init__(self, app):
        self.app = app
        self.suspicious_patterns = [
            r'\.\./', r'\/etc\/', r'\/bin\/', r'\/cmd', r';', r'\|', r'`', r'\$\(', r'<%', r'%>'
        ]
        self.suspicious_user_agents = [
            'bot', 'spider', 'crawl', 'scan', 'hack', 'sqlmap', 'nikto', 'wget', 'curl'
        ]
    
    def __call__(self, environ, start_response):
        request_path = environ.get('PATH_INFO', '')
        user_agent = environ.get('HTTP_USER_AGENT', '').lower()
        remote_addr = environ.get('REMOTE_ADDR', '')
        
        # Check for path traversal attacks
        if self.is_malicious_path(request_path):
            self.log_security_event('PATH_TRAVERSAL_ATTEMPT', f'Path: {request_path}', remote_addr)
            return self.deny_request(start_response)
        
        # Check for suspicious user agents
        if self.is_suspicious_user_agent(user_agent):
            self.log_security_event('SUSPICIOUS_USER_AGENT', f'User-Agent: {user_agent}', remote_addr)
        
        return self.app(environ, start_response)
    
    def is_malicious_path(self, path):
        for pattern in self.suspicious_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        return False
    
    def is_suspicious_user_agent(self, user_agent):
        for pattern in self.suspicious_user_agents:
            if pattern in user_agent:
                return True
        return False
    
    def deny_request(self, start_response):
        start_response('403 Forbidden', [('Content-Type', 'text/plain')])
        return [b'Access denied']
    
    def log_security_event(self, event_type, details, ip):
        logger.warning(f"SECURITY: {event_type} - IP: {ip} - {details} - Timestamp: {datetime.now().isoformat()}")
