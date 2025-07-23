document.addEventListener('DOMContentLoaded', function() {
    const modal = document.getElementById('imageModal');
    const modalImg = document.getElementById('modalImage');
    const closeBtn = document.querySelector('.modal .close');

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

    document.querySelector('.container').addEventListener('click', function(e) {
        // --- Image Modal Logic ---
        if (e.target.classList.contains('history-img')) {
            modal.style.display = 'block';
            modalImg.src = e.target.src;
        }

        // --- Copy Key Logic ---
        if (e.target.closest('.copy-key-btn')) {
            const button = e.target.closest('.copy-key-btn');
            const keyText = button.nextElementSibling.textContent;
            navigator.clipboard.writeText(keyText).then(() => {
                showToast('Key copied to clipboard!');
            }).catch(err => {
                console.error('Failed to copy key: ', err);
                showToast('Failed to copy key.', false);
            });
        }

        // --- Delete Record Logic ---
        if (e.target.closest('.delete-btn')) {
            const button = e.target.closest('.delete-btn');
            const card = button.closest('.history-card');
            const recordId = card.dataset.recordId;

            if (confirm('Are you sure you want to delete this record? This action cannot be undone.')) {
                fetch(`/delete_neural_record/${recordId}`, {
                    method: 'POST',
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        card.style.transition = 'opacity 0.5s ease';
                        card.style.opacity = '0';
                        setTimeout(() => {
                            card.remove();
                             if (document.querySelectorAll('.history-card').length === 0) {
                                location.reload(); // Reload to show the "No Records" message
                            }
                        }, 500);
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
    });

    // --- Close Modal Logic ---
    if (closeBtn) {
        closeBtn.onclick = function() {
            modal.style.display = 'none';
        }
    }

    window.onclick = function(event) {
        if (event.target == modal) {
            modal.style.display = 'none';
        }
    }
});