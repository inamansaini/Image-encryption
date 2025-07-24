document.addEventListener('DOMContentLoaded', () => {
    // Select all the copy buttons on the page
    const copyButtons = document.querySelectorAll('.copy-key-btn');

    // Add a click event listener to each button
    copyButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Retrieve the key from the button's 'data-key' attribute
            const keyToCopy = button.dataset.key;
            
            // Call the copyKey function with the retrieved key
            copyKey(keyToCopy); 
        });
    });
});

/**
 * Displays a toast notification message.
 * @param {string} message The message to display.
 * @param {string} type The type of toast ('success' or 'error').
 */
function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = message;
    toast.className = `toast show ${type}`;
    setTimeout(() => {
        toast.className = toast.className.replace('show', '');
    }, 3000); // Hide after 3 seconds
}

/**
 * Opens the image preview modal.
 * @param {string} imageSrc The source path of the image to display.
 */
function openModal(imageSrc) {
    const modal = document.getElementById('imageModal');
    const modalImg = document.getElementById('modalImage');
    modal.style.display = "block";
    modalImg.src = imageSrc;
}

/**
 * Closes the image preview modal.
 */
function closeModal() {
    const modal = document.getElementById('imageModal');
    modal.style.display = "none";
}

/**
 * Copies text to the user's clipboard.
 * @param {string} keyText The text (decryption key) to copy.
 */
function copyKey(keyText) {
    if (!keyText) return; // Guard clause for empty keys

    navigator.clipboard.writeText(keyText).then(() => {
        showToast('Key copied to clipboard!', 'success');
    }).catch(err => {
        console.error('Failed to copy key:', err);
        showToast('Failed to copy key.', 'error');
    });
}

/**
 * Deletes a record from the history.
 * @param {number} recordId The ID of the record to delete.
 */
function deleteRecord(recordId) {
    if (confirm('Are you sure you want to delete this record? This action cannot be undone.')) {
        fetch(`/delete_record/${recordId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
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
 * Triggers the download of an image.
 * @param {string} imagePath The path to the image.
 * @param {string} filename The desired filename for the download.
 */
function downloadImage(imagePath, filename) {
    const downloadUrl = `/${imagePath}`;
    console.log('Attempting to download from URL:', downloadUrl);

    fetch(downloadUrl)
        .then(response => {
            if (!response.ok) {
                throw new Error(`Server responded with ${response.status}: ${response.statusText}`);
            }
            return response.blob();
        })
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = filename;
            
            document.body.appendChild(a);
            a.click();
            
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);

            showToast('Image downloaded successfully!', 'success');
        })
        .catch(error => {
            console.error('Download error:', error);
            showToast(`Download failed: ${error.message}`, 'error');
        });
}