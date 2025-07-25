document.addEventListener('DOMContentLoaded', () => {
    const copyButtons = document.querySelectorAll('.copy-key-btn');

    copyButtons.forEach(button => {
        button.addEventListener('click', () => {
            const keyToCopy = button.dataset.key;
            copyKey(keyToCopy); 
        });
    });
});

function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = message;
    toast.className = `toast show ${type}`;
    setTimeout(() => {
        toast.className = toast.className.replace('show', '');
    }, 3000);
}

function openModal(imageSrc) {
    const modal = document.getElementById('imageModal');
    const modalImg = document.getElementById('modalImage');
    modal.style.display = "block";
    modalImg.src = imageSrc;
}

function closeModal() {
    const modal = document.getElementById('imageModal');
    modal.style.display = "none";
}

function copyKey(keyText) {
    if (!keyText) return;
    navigator.clipboard.writeText(keyText).then(() => {
        showToast('Key copied to clipboard!', 'success');
    }).catch(err => {
        console.error('Failed to copy key:', err);
        showToast('Failed to copy key.', 'error');
    });
}

/**
 * **** FIXED to call the correct delete route ****
 * Deletes a record from the history.
 * @param {string} recordId The ID of the record to delete.
 */
function deleteRecord(recordId) {
    if (confirm('Are you sure you want to delete this record? This action cannot be undone.')) {
        // Correct endpoint for deleting from the unified history
        fetch(`/delete_history_record/${recordId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const card = document.getElementById(`record-${recordId}`);
                if (card) {
                    card.style.opacity = '0';
                    setTimeout(() => card.remove(), 300);
                }
                showToast('Record deleted successfully', 'success');
            } else {
                showToast('Failed to delete record: ' + (data.error || 'Unknown error'), 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showToast('Failed to delete record', 'error');
        });
    }
}

/**
 * **** FIXED to use the backend download route ****
 * Triggers the download of an image from Cloudinary.
 * @param {string} imageUrl The full Cloudinary URL of the image.
 * @param {string} filename The desired filename for the download.
 */
function downloadImage(imageUrl, filename) {
    // Construct the URL for our new Flask download route
    const downloadUrl = `/download_image?url=${encodeURIComponent(imageUrl)}&filename=${encodeURIComponent(filename)}`;
    
    // Simply navigate to the URL. The browser will handle the download
    // because the server will send the correct headers.
    window.location.href = downloadUrl;
}