/**
 * Music Shop - Main JavaScript File
 * Contains all frontend interactivity
 */

document.addEventListener('DOMContentLoaded', function() {
    // ======================
    // 1. IMAGE UPLOAD PREVIEW
    // ======================
    const imageUpload = document.getElementById('image');
    const imagePreview = document.getElementById('imagePreview');
    
    if (imageUpload && imagePreview) {
        imageUpload.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                
                reader.onload = function(event) {
                    imagePreview.src = event.target.result;
                    imagePreview.classList.remove('d-none');
                }
                
                reader.readAsDataURL(file);
            }
        });
    }

    // ======================
    // 2. FORM VALIDATION
    // ======================
    const forms = document.querySelectorAll('.needs-validation');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }

            form.classList.add('was-validated');
        }, false);
    });

    // ======================
    // 3. SHOPPING CART LOGIC
    // ======================
    const cart = JSON.parse(localStorage.getItem('cart')) || [];
    const cartCount = document.getElementById('cartCount');
    
    function updateCartCount() {
        const count = cart.reduce((total, item) => total + item.quantity, 0);
        cartCount.textContent = count;
        localStorage.setItem('cart', JSON.stringify(cart));
    }
    
    // Add to cart buttons
    document.querySelectorAll('.add-to-cart').forEach(button => {
        button.addEventListener('click', function() {
            const albumId = this.dataset.albumId;
            const albumCard = this.closest('.album-card');
            const album = {
                id: albumId,
                title: albumCard.querySelector('.card-title').textContent,
                artist: albumCard.querySelector('.card-text').textContent,
                price: parseFloat(albumCard.querySelector('.price').textContent.replace('$', '')),
                image: albumCard.querySelector('img').src,
                quantity: 1
            };
            
            const existingItem = cart.find(item => item.id === albumId);
            if (existingItem) {
                existingItem.quantity += 1;
            } else {
                cart.push(album);
            }
            
            updateCartCount();
            showToast('Album added to cart!', 'success');
        });
    });
    
    // ======================
    // 4. TOAST NOTIFICATIONS
    // ======================
    function showToast(message, type = 'info') {
        const toastContainer = document.getElementById('toastContainer') || createToastContainer();
        const toastId = 'toast-' + Date.now();
        
        const toast = document.createElement('div');
        toast.className = `toast align-items-center text-white bg-${type} border-0`;
        toast.setAttribute('role', 'alert');
        toast.setAttribute('aria-live', 'assertive');
        toast.setAttribute('aria-atomic', 'true');
        toast.id = toastId;
        
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;
        
        toastContainer.appendChild(toast);
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
        
        // Remove toast after it hides
        toast.addEventListener('hidden.bs.toast', function() {
            toast.remove();
        });
    }
    
    function createToastContainer() {
        const container = document.createElement('div');
        container.id = 'toastContainer';
        container.className = 'position-fixed bottom-0 end-0 p-3';
        container.style.zIndex = '11';
        document.body.appendChild(container);
        return container;
    }

    // ======================
    // 5. SEARCH FUNCTIONALITY
    // ======================
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            document.querySelectorAll('.album-item').forEach(item => {
                const title = item.dataset.title.toLowerCase();
                const artist = item.dataset.artist.toLowerCase();
                item.style.display = (title.includes(searchTerm) || artist.includes(searchTerm)) ? '' : 'none';
            });
        });
    }

    // ======================
    // 6. PRICE FILTER
    // ======================
    const priceFilter = document.getElementById('priceFilter');
    if (priceFilter) {
        priceFilter.addEventListener('change', function() {
            const maxPrice = parseFloat(this.value);
            document.querySelectorAll('.album-item').forEach(item => {
                const price = parseFloat(item.dataset.price);
                item.style.display = price <= maxPrice ? '' : 'none';
            });
        });
    }

    // Initialize cart count on page load
    updateCartCount();
    
    // Enable Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Enable Bootstrap popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    const popoverList = popoverTriggerList.map(function(popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
});

// ======================
// 7. CART MODAL HANDLING
// ======================
function updateCartModal() {
    const cart = JSON.parse(localStorage.getItem('cart')) || [];
    const cartItems = document.getElementById('cartItems');
    const cartSubtotal = document.getElementById('cartSubtotal');
    
    cartItems.innerHTML = '';
    let subtotal = 0;
    
    cart.forEach(item => {
        const itemTotal = item.price * item.quantity;
        subtotal += itemTotal;
        
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>
                <img src="${item.image}" alt="${item.title}" width="50" class="me-2">
                ${item.title}
            </td>
            <td>${item.artist}</td>
            <td>$${item.price.toFixed(2)}</td>
            <td>
                <div class="input-group" style="width: 120px;">
                    <button class="btn btn-outline-secondary change-quantity" data-id="${item.id}" data-change="-1">-</button>
                    <input type="text" class="form-control text-center quantity-input" value="${item.quantity}" data-id="${item.id}">
                    <button class="btn btn-outline-secondary change-quantity" data-id="${item.id}" data-change="1">+</button>
                </div>
            </td>
            <td>$${itemTotal.toFixed(2)}</td>
            <td>
                <button class="btn btn-danger btn-sm remove-item" data-id="${item.id}">
                    <i class="bi bi-trash"></i>
                </button>
            </td>
        `;
        
        cartItems.appendChild(row);
    });
    
    cartSubtotal.textContent = `$${subtotal.toFixed(2)}`;
}

// Event delegation for dynamic cart elements
document.addEventListener('click', function(e) {
    // Quantity changes
    if (e.target.classList.contains('change-quantity')) {
        const cart = JSON.parse(localStorage.getItem('cart')) || [];
        const item = cart.find(item => item.id === e.target.dataset.id);
        
        if (item) {
            item.quantity += parseInt(e.target.dataset.change);
            if (item.quantity < 1) item.quantity = 1;
            localStorage.setItem('cart', JSON.stringify(cart));
            updateCartModal();
            updateCartCount();
        }
    }
    
    // Remove item
    if (e.target.classList.contains('remove-item') || e.target.closest('.remove-item')) {
        const button = e.target.classList.contains('remove-item') ? e.target : e.target.closest('.remove-item');
        const cart = JSON.parse(localStorage.getItem('cart')) || [];
        const updatedCart = cart.filter(item => item.id !== button.dataset.id);
        
        localStorage.setItem('cart', JSON.stringify(updatedCart));
        updateCartModal();
        updateCartCount();
        showToast('Item removed from cart', 'warning');
    }
});

// Handle manual quantity input changes
document.addEventListener('change', function(e) {
    if (e.target.classList.contains('quantity-input')) {
        const cart = JSON.parse(localStorage.getItem('cart')) || [];
        const item = cart.find(item => item.id === e.target.dataset.id);
        
        if (item) {
            const newQuantity = parseInt(e.target.value) || 1;
            item.quantity = newQuantity;
            localStorage.setItem('cart', JSON.stringify(cart));
            updateCartModal();
            updateCartCount();
        }
    }
});
