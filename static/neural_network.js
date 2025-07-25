document.addEventListener('DOMContentLoaded', function() {
    function setButtonProcessing(button, originalContent, isProcessing) {
        if (isProcessing) {
            button.disabled = true;
            button.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Processing...`;
        } else {
            button.disabled = false;
            button.innerHTML = originalContent;
        }
    }

    function setStatus(elementId, message, isError = false) {
        const statusEl = document.getElementById(elementId);
        if (statusEl) {
            statusEl.textContent = message;
            statusEl.className = `status-message ${isError ? 'status-error' : 'status-success'}`;
        }
    }
    
    function setupImagePreview(inputId, previewContainerId, previewImgId, filenameDisplayId) {
        const fileInput = document.getElementById(inputId);
        const previewContainer = document.getElementById(previewContainerId);
        const previewImage = document.getElementById(previewImgId);
        const filenameDisplay = document.getElementById(filenameDisplayId);
        
        fileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file && file.type.startsWith('image/')) {
                filenameDisplay.textContent = file.name;
                const reader = new FileReader();
                reader.onload = function(event) {
                    previewImage.src = event.target.result;
                    previewContainer.classList.add('has-image');
                };
                reader.readAsDataURL(file);
            }
        });
    }

    // --- ENCRYPTION LOGIC ---
    setupImagePreview('nnOriginalImage', 'nnOriginalImage-preview-container', 'nnOriginalImagePreview', 'nn-original-filename');

    document.getElementById('nnEncryptBtn').addEventListener('click', function() {
        const button = this;
        const originalBtnContent = button.innerHTML;
        const fileInput = document.getElementById('nnOriginalImage');
        const keyInput = document.getElementById('nnKey');

        if (!fileInput.files[0]) {
            alert('Please select an image to encrypt.');
            return;
        }

        const formData = new FormData();
        formData.append('image', fileInput.files[0]);
        formData.append('key', keyInput.value);

        setButtonProcessing(button, originalBtnContent, true);
        setStatus('encryptStatus', 'Initializing AI model and encrypting image...');

        fetch('/neural_network_encrypt', { method: 'POST', body: formData })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    setStatus('encryptStatus', 'Encryption successful!');
                    keyInput.value = data.key; 
                    document.getElementById('nnEncryptedImage').src = data.encrypted_image + '?' + new Date().getTime();
                    
                    const downloadBtn = document.getElementById('nnDownloadBtn');
                    const downloadUrl = `/download_image?url=${encodeURIComponent(data.encrypted_image)}&filename=nn_encrypted.png`;
                    downloadBtn.href = downloadUrl;
                    
                    document.getElementById('nnEncryptedSection').classList.remove('hidden');
                } else {
                    setStatus('encryptStatus', 'Error: ' + data.error, true);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                setStatus('encryptStatus', 'A critical error occurred.', true);
            })
            .finally(() => {
                setButtonProcessing(button, originalBtnContent, false);
            });
    });
    
    document.getElementById('copyKeyBtn').addEventListener('click', function() {
        const keyInput = document.getElementById('nnKey');
        if (keyInput.value) {
            navigator.clipboard.writeText(keyInput.value).then(() => {
                alert('Encryption key copied to clipboard!');
            });
        }
    });

    // --- DECRYPTION LOGIC ---
    setupImagePreview('nnEncryptedImageInput', 'nnEncryptedImageInput-preview-container', 'nnEncryptedImageInputPreview', 'nn-encrypted-filename');

    document.getElementById('nnDecryptBtn').addEventListener('click', function() {
        const button = this;
        const originalBtnContent = button.innerHTML;
        const fileInput = document.getElementById('nnEncryptedImageInput');
        const keyInput = document.getElementById('nnDecryptKey');

        if (!fileInput.files[0]) {
            alert('Please select an encrypted image to decrypt.');
            return;
        }
        if (!keyInput.value.trim()) {
            alert('Please enter the decryption key.');
            return;
        }

        const formData = new FormData();
        formData.append('image', fileInput.files[0]);
        formData.append('key', keyInput.value.trim());

        setButtonProcessing(button, originalBtnContent, true);
        setStatus('decryptStatus', 'Initializing AI model and decrypting image...');
        document.getElementById('nnDecryptedSection').classList.add('hidden');

        fetch('/neural_network_decrypt', { method: 'POST', body: formData })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    setStatus('decryptStatus', 'Decryption successful!');
                    document.getElementById('nnDecryptedImage').src = data.decrypted_image + '?' + new Date().getTime();
                    
                    const downloadBtn = document.getElementById('nnDownloadDecryptedBtn');
                    const downloadUrl = `/download_image?url=${encodeURIComponent(data.decrypted_image)}&filename=nn_decrypted.png`;
                    downloadBtn.href = downloadUrl;

                    document.getElementById('nnDecryptedSection').classList.remove('hidden');
                } else {
                    setStatus('decryptStatus', 'Error: ' + data.error, true);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                setStatus('decryptStatus', 'A critical error occurred.', true);
            })
            .finally(() => {
                setButtonProcessing(button, originalBtnContent, false);
            });
    });
});