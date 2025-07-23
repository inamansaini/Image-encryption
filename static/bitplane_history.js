// --- Modal Functionality ---
const modal = document.getElementById('imageModal');
const modalImg = document.getElementById("modalImage");

function openModal(imgSrc) {
    if (modal && modalImg) {
        modal.style.display = "block";
        modalImg.src = imgSrc;
    }
}

function closeModal() {
    if (modal) {
        modal.style.display = "none";
    }
}

// Close modal if user clicks outside the image
window.onclick = function(event) {
    if (event.target == modal) {
        closeModal();
    }
}

// --- Toast Notification ---
function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    if (toast) {
        toast.textContent = message;
        toast.className = 'toast show';
        toast.classList.add(type); // Add success or error class
        setTimeout(() => {
            toast.className = toast.className.replace('show', '');
        }, 3000);
    }
}

// --- API Calls and Actions ---
function deleteRecord(recordId) {
    if (!confirm('Are you sure you want to delete this record? This action cannot be undone.')) {
        return;
    }
    fetch(`/delete_bitplane_record/${recordId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const recordCard = document.getElementById(`record-${recordId}`);
            if (recordCard) {
                recordCard.style.transition = 'opacity 0.5s ease';
                recordCard.style.opacity = '0';
                setTimeout(() => recordCard.remove(), 500);
            }
            showToast('Record deleted successfully!', 'success');
        } else {
            showToast('Error: ' + data.error, 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showToast('An unexpected error occurred.', 'error');
    });
}

function copyKey(keyText, type = 'Key') {
    navigator.clipboard.writeText(keyText).then(() => {
        showToast(`${type} copied to clipboard!`, 'success');
    }, (err) => {
        console.error('Could not copy text: ', err);
        showToast('Failed to copy key.', 'error');
    });
}