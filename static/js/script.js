document.addEventListener('DOMContentLoaded', () => {
    // Mobile menu toggle
    const menuToggle = document.querySelector('.menu-toggle');
    const nav = document.querySelector('nav');
    
    if (menuToggle && nav) {
        menuToggle.addEventListener('click', () => {
            nav.classList.toggle('active');
            menuToggle.innerHTML = nav.classList.contains('active') 
                ? '<i class="fas fa-times"></i>' 
                : '<i class="fas fa-bars"></i>';
        });
        
        // Close menu when clicking outside
        document.addEventListener('click', (e) => {
            if (!nav.contains(e.target) && !menuToggle.contains(e.target)) {
                nav.classList.remove('active');
                menuToggle.innerHTML = '<i class="fas fa-bars"></i>';
            }
        });
    }
    
    // Flash messages
    document.querySelectorAll('.flash').forEach(flash => {
        setTimeout(() => {
            flash.style.opacity = '0';
            setTimeout(() => flash.remove(), 300);
        }, 5000);
        
        flash.querySelector('.flash-close')?.addEventListener('click', () => {
            flash.remove();
        });
    });
    
    // Tracklist accordion
    document.querySelectorAll('.track-header').forEach(header => {
        const content = header.nextElementSibling;
        const icon = header.querySelector('i');
        
        content.style.display = 'none';
        
        header.addEventListener('click', () => {
            const willShow = content.style.display === 'none';
            content.style.display = willShow ? 'block' : 'none';
            icon.className = willShow ? 'fas fa-chevron-up' : 'fas fa-chevron-down';
        });
    });
});
