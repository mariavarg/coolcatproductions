// CSRF Protection
document.addEventListener('DOMContentLoaded', () => {
    // Add CSRF token to all forms
    document.querySelectorAll('form').forEach(form => {
        const token = document.createElement('input');
        token.type = 'hidden';
        token.name = 'csrf_token';
        token.value = '{{ csrf_token() }}'; // Flask-WTF required
        form.appendChild(token);
    });

    // XSS protection for dynamic content
    function sanitize(input) {
        return input.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }
});
