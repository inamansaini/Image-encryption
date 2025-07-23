document.addEventListener('DOMContentLoaded', function() {
    function setButtonProcessing(buttonId, originalContent, isProcessing) {
        const button = document.getElementById(buttonId);
        if (button) {
            if (isProcessing) {
                button.disabled = true;
                button.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Processing...`;
            } else {
                button.disabled = false;
                button.innerHTML = originalContent;
            }
        }
    }

    function setStatus(elementId, message, isError = false) {
        const statusEl = document.getElementById(elementId);
        if (statusEl) {
            statusEl.textContent = message;
            statusEl.className = 'status-message';
            statusEl.classList.add(isError ? 'status-error' : 'status-success');
            statusEl.style.display = 'block';
        }
    }
    
    function setupFileNameDisplay(inputId, displayId) {
        const fileInput = document.getElementById(inputId);
        const display = document.getElementById(displayId);
        if (fileInput && display) {
            fileInput.addEventListener('change', function(e) {
                const file = e.target.files[0];
                if (file) {
                    display.textContent = file.name;
                }
            });
        }
    }

    // ##### FIX: Corrected function to find preview elements based on ID #####
    function setupImagePreview(inputId) {
        const fileInput = document.getElementById(inputId);
        const previewContainer = document.getElementById(inputId + '-preview-container');
        const previewImage = document.getElementById(inputId + 'Preview');
        
        if(fileInput && previewContainer && previewImage) {
            fileInput.addEventListener('change', function(e) {
                const file = e.target.files[0];
                if (file && file.type.startsWith('image/')) {
                    const reader = new FileReader();
                    reader.onload = function(event) {
                        previewImage.src = event.target.result;
                        previewContainer.classList.add('has-image');
                    };
                    reader.readAsDataURL(file);
                }
            });
        }
    }

    // Setup for original image upload
    setupImagePreview('nnOriginalImage');
    setupFileNameDisplay('nnOriginalImage', 'nn-original-filename');

    // Setup for encrypted image upload name display
    setupFileNameDisplay('nnEncryptedImageUpload', 'nn-encrypted-filename-display');


    document.getElementById('nnEncryptBtn').addEventListener('click', function() {
        const button = this;
        const originalBtnContent = button.innerHTML;
        const fileInput = document.getElementById('nnOriginalImage');
        const keyInput = document.getElementById('nnKey');

        if (!fileInput.files[0]) {
            alert('Please select an image to encrypt.');
            return;
        }

        // ##### FIX: Random key generation using browser's crypto API #####
        if (!keyInput.value.trim()) {
            const array = new Uint8Array(16);
            window.crypto.getRandomValues(array);
            const randomKey = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
            keyInput.value = randomKey;
            setStatus('encryptStatus', `A random key was generated for you.`);
        }

        const formData = new FormData();
        formData.append('image', fileInput.files[0]);
        formData.append('key', keyInput.value);

        setButtonProcessing(button.id, originalBtnContent, true);
        setStatus('encryptStatus', 'Initializing AI model and encrypting image... This may take a moment.');

        fetch('/neural_network_encrypt', { method: 'POST', body: formData })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    setStatus('encryptStatus', 'Encryption successful!');
                    document.getElementById('nnKey').value = data.key; // Update key field if it was random
                    document.getElementById('nnEncryptedImage').src = data.preview_image + '?' + new Date().getTime();
                    const downloadBtn = document.getElementById('nnDownloadBtn');
                    downloadBtn.href = data.download_file;
                    document.getElementById('nnEncryptedSection').classList.remove('hidden');
                } else {
                    setStatus('encryptStatus', 'Error: ' + data.error, true);
                    document.getElementById('nnEncryptedSection').classList.add('hidden');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                setStatus('encryptStatus', 'A critical error occurred. See console for details.', true);
                document.getElementById('nnEncryptedSection').classList.add('hidden');
            })
            .finally(() => {
                setButtonProcessing(button.id, originalBtnContent, false);
            });
    });
    
    // ##### FIX: Added copy key button functionality #####
    document.getElementById('copyKeyBtn').addEventListener('click', function() {
        const keyInput = document.getElementById('nnKey');
        if (keyInput.value) {
            navigator.clipboard.writeText(keyInput.value).then(() => {
                alert('Encryption key copied to clipboard!');
            });
        }
    });

    document.getElementById('nnDecryptBtn').addEventListener('click', function() {
        const button = this;
        const originalBtnContent = button.innerHTML;
        const fileInput = document.getElementById('nnEncryptedImageUpload');
        const keyInput = document.getElementById('nnDecryptKey');

        if (!fileInput.files[0]) {
            alert('Please select the encrypted .png data file to decrypt.');
            return;
        }
        if (!keyInput.value.trim()) {
            alert('Please enter the decryption key.');
            return;
        }
        
        const formData = new FormData();
        formData.append('image', fileInput.files[0]);
        formData.append('key', keyInput.value);

        setButtonProcessing(button.id, originalBtnContent, true);
        setStatus('decryptStatus', 'Reconstructing AI model and decrypting image...');

        fetch('/neural_network_decrypt', { method: 'POST', body: formData })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    setStatus('decryptStatus', 'Decryption successful!');
                    document.getElementById('nnDecryptedImage').src = data.decrypted_image + '?' + new Date().getTime();
                    document.getElementById('nnDownloadDecryptedBtn').href = data.decrypted_image;
                    document.getElementById('nnDecryptedSection').classList.remove('hidden');
                } else {
                    setStatus('decryptStatus', 'Error: ' + data.error, true);
                    document.getElementById('nnDecryptedSection').classList.add('hidden');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                setStatus('decryptStatus', 'A critical error occurred. The key may be wrong or the file is invalid.', true);
                document.getElementById('nnDecryptedSection').classList.add('hidden');
            })
            .finally(() => {
                setButtonProcessing(button.id, originalBtnContent, false);
            });
    });
});