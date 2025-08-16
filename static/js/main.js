/**
 * Main application JavaScript
 * - CSRF protection
 * - Form validation
 */

document.addEventListener('DOMContentLoaded', function() {
    // Add CSRF token to all forms
    const csrfToken = document.createElement('input');
    csrfToken.type = 'hidden';
    csrfToken.name = 'csrf_token';
    csrfToken.value = '{{ csrf_token() }}';  // Requires Flask-WTF
    
    document.querySelectorAll('form').forEach(form => {
        form.appendChild(csrfToken.cloneNode());
    });
    
    // File upload validation
    const fileInput = document.getElementById('fileUpload');
    if (fileInput) {
        fileInput.addEventListener('change', function() {
            const file = this.files[0];
            const maxSize = 8 * 1024 * 1024; // 8MB
            
            if (file.size > maxSize) {
                alert('File too large (max 8MB)');
                this.value = ''; // Clear input
            }
        });
    }
});
