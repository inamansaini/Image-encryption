document.addEventListener('DOMContentLoaded', function() {
    const modal = document.getElementById('imageModal');
    const modalImg = document.getElementById('modalImage');
    const closeBtn = document.querySelector('.modal .close');

    // --- Modal Logic ---
    function openModal(imgSrc) {
        if (modal && modalImg) {
            modal.style.display = 'block';
            modalImg.src = imgSrc;
        }
    }

    function closeModal() {
        if (modal) {
            modal.style.display = 'none';
        }
    }

    // Assign openModal to global scope so onclick can find it
    window.openModal = openModal;
    window.closeModal = closeModal;

    if (closeBtn) {
        closeBtn.onclick = closeModal;
    }
    window.onclick = function(event) {
        if (event.target == modal) {
            closeModal();
        }
    }

    // Attach event listeners to all images with the 'history-img' class
    document.querySelectorAll('.history-img').forEach(img => {
        img.addEventListener('click', () => openModal(img.src));
    });

    // --- Toast Notification ---
    function showToast(message, isSuccess = true) {
        const toast = document.getElementById('toast');
        toast.textContent = message;
        toast.className = 'toast show';
        if (isSuccess) {
            toast.classList.add('success');
        }
        setTimeout(() => {
            toast.className = toast.className.replace('show', '');
        }, 3000);
    }
    window.showToast = showToast; // Make it globally accessible if needed

    // --- Copy Key Logic ---
    function copyKey(keyText) {
        if (!keyText) return;
        navigator.clipboard.writeText(keyText).then(() => {
            showToast('Key copied to clipboard!');
        }).catch(err => {
            console.error('Failed to copy key: ', err);
            showToast('Failed to copy key.', false);
        });
    }
    window.copyKey = copyKey; // Make it globally accessible

    // --- Delete Record Logic ---
    function deleteRecord(recordId) {
        if (confirm('Are you sure you want to delete this record? This action cannot be undone.')) {
            /**
             * **** FIXED: Changed route from /delete_neural_record to /delete_history_record ****
             */
            fetch(`/delete_history_record/${recordId}`, {
                method: 'POST',
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const card = document.getElementById(`record-${recordId}`) || document.querySelector(`[data-record-id="${recordId}"]`);
                    if (card) {
                        card.style.transition = 'opacity 0.5s ease';
                        card.style.opacity = '0';
                        setTimeout(() => {
                            card.remove();
                            if (document.querySelectorAll('.history-card').length === 0) {
                                location.reload(); // Reload to show the "No Records" message
                            }
                        }, 500);
                    }
                    showToast('Record deleted successfully.');
                } else {
                    showToast('Error: ' + data.error, false);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showToast('A critical error occurred.', false);
            });
        }
    }
    window.deleteRecord = deleteRecord; // Make it globally accessible
});

/**
 * **** ADDED: New function to handle downloads from Cloudinary ****
 * Triggers the download of an image from Cloudinary via the backend.
 * @param {string} imageUrl The full Cloudinary URL of the image.
 * @param {string} filename The desired filename for the download.
 */
function downloadImage(imageUrl, filename) {
    const downloadUrl = `/download_image?url=${encodeURIComponent(imageUrl)}&filename=${encodeURIComponent(filename)}`;
    window.location.href = downloadUrl;
}