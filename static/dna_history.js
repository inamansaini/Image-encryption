document.addEventListener('DOMContentLoaded', () => {

    // --- Modal Logic ---
    const modal = document.getElementById('imageModal');
    const modalImg = document.getElementById('modalImage');
    const closeModal = document.querySelector('.close-modal');

    document.querySelectorAll('.image-item img').forEach(img => {
        img.addEventListener('click', function() {
            modal.style.display = 'block';
            modalImg.src = this.src;
        });
    });

    if (closeModal) {
        closeModal.onclick = () => {
            modal.style.display = 'none';
        }
    }
    
    // Close modal if background is clicked
    window.onclick = (event) => {
        if (event.target == modal) {
            modal.style.display = 'none';
        }
    }

    // --- Toast Notification Logic ---
    let toastTimeout;
    const showToast = (message, type = 'success') => {
        const toast = document.getElementById('toast');
        toast.textContent = message;
        toast.className = 'toast show';
        toast.classList.add(type);

        // Clear previous timeout if it exists
        clearTimeout(toastTimeout);
        
        // Hide the toast after 3 seconds
        toastTimeout = setTimeout(() => {
            toast.className = toast.className.replace('show', '');
        }, 3000);
    };
    
    // --- Copy Key Logic ---
    document.querySelectorAll('.copy-key-btn').forEach(button => {
        button.addEventListener('click', function() {
            const keyInfo = this.closest('.key-info');
            const keyText = keyInfo.querySelector('span').innerText;
            
            navigator.clipboard.writeText(keyText).then(() => {
                showToast('Key copied to clipboard!', 'success');
            }).catch(err => {
                showToast('Failed to copy key.', 'error');
                console.error('Could not copy text: ', err);
            });
        });
    });

    // --- Delete Record Logic ---
    document.querySelectorAll('.delete-btn').forEach(button => {
        button.addEventListener('click', function() {
            const recordId = this.dataset.id;
            const card = document.getElementById(`record-${recordId}`);

            if (confirm('Are you sure you want to permanently delete this record?')) {
                fetch(`/delete_dna_record/${recordId}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Animate card out before removing
                        card.style.transition = 'opacity 0.5s, transform 0.5s';
                        card.style.opacity = '0';
                        card.style.transform = 'scale(0.9)';
                        setTimeout(() => {
                            card.remove();
                            // Check if grid is now empty
                            const grid = document.querySelector('.history-grid');
                            if (grid && grid.children.length === 0) {
                                document.querySelector('.main-container').innerHTML = `
                                    <div class="no-records">
                                        <h2>No History Found</h2>
                                        <p>You haven't performed any DNA-based encryptions yet.</p>
                                        <a href="/dna_based" class="action-btn">
                                            <i class="fas fa-shield-alt"></i> Encrypt an Image Now
                                        </a>
                                    </div>`;
                            }
                        }, 500);
                        showToast('Record deleted successfully!', 'success');
                    } else {
                        showToast(data.error || 'Failed to delete record.', 'error');
                    }
                })
                .catch(error => {
                    showToast('An error occurred.', 'error');
                    console.error('Error:', error);
                });
            }
        });
    });
});