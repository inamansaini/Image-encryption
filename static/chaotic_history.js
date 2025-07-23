
    const modal = document.getElementById('imageModal');
    const modalImg = document.getElementById('modalImage');

    function showToast(message, isError = false) {
        const toast = document.getElementById('toast');
        toast.textContent = message;
        toast.className = 'toast show ' + (isError ? 'error' : 'success');
        setTimeout(() => { toast.className = toast.className.replace('show', ''); }, 3000);
    }

    function copyKey(keyText) {
        navigator.clipboard.writeText(keyText).then(() => {
            showToast('Key copied to clipboard!');
        }).catch(err => {
            showToast('Failed to copy key.', true);
        });
    }

    function deleteRecord(recordId) {
        if (!confirm('Are you sure you want to delete this record? This action cannot be undone.')) {
            return;
        }
        fetch(`/delete_chaotic_record/${recordId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const recordElement = document.getElementById(`record-${recordId}`);
                if (recordElement) {
                    recordElement.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                    recordElement.style.opacity = '0';
                    recordElement.style.transform = 'scale(0.95)';
                    setTimeout(() => {
                        recordElement.remove();
                        if (document.querySelectorAll('.history-card').length === 0) {
                            window.location.reload();
                        }
                    }, 500);
                }
                showToast('Record deleted successfully.');
            } else {
                showToast('Error deleting record: ' + data.error, true);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showToast('An unexpected error occurred.', true);
        });
    }

    function openModal(imgSrc) {
        modal.style.display = 'block';
        modalImg.src = imgSrc;
    }

    function closeModal() {
        modal.style.display = 'none';
    }
    
    // === ADDED DOWNLOAD FUNCTION ===
    function downloadImage(imagePath, filename) {
        fetch(`/${imagePath}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Server responded with ${response.status}`);
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

                showToast('Image downloaded successfully!');
            })
            .catch(error => {
                console.error('Download error:', error);
                showToast(`Download failed: ${error.message}`, true);
            });
    }
    