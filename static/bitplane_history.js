function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = message;
    toast.className = `toast show ${type}`;
    setTimeout(() => {
        toast.className = toast.className.replace('show', '');
    }, 3000);
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

function deleteRecord(recordId) {
    if (confirm('Are you sure you want to delete this record? This action cannot be undone.')) {
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

function openModal(imgSrc) {
    const modal = document.getElementById('imageModal');
    const modalImg = document.getElementById('modalImage');
    if (modal && modalImg) {
        modal.style.display = 'block';
        modalImg.src = imgSrc;
    }
}

function closeModal() {
    const modal = document.getElementById('imageModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

function downloadImage(imageUrl, filename) {
    const downloadUrl = `/download_image?url=${encodeURIComponent(imageUrl)}&filename=${encodeURIComponent(filename)}`;
    window.location.href = downloadUrl;
}

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.copy-key-btn').forEach(button => {
        button.addEventListener('click', (e) => {
            const keySpan = e.currentTarget.closest('.key-info').querySelector('span[title="Encryption Key"]');
            if (keySpan) {
                copyKey(keySpan.innerText);
            }
        });
    });
});