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

    function setupImagePreview(inputId, previewId) {
        document.getElementById(inputId).addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = function(event) {
                    const preview = document.getElementById(previewId);
                    preview.src = event.target.result;
                    preview.style.display = 'block';
                };
                reader.readAsDataURL(file);
            }
        });
    }

    setupImagePreview('bpOriginalImage', 'bpOriginalPreview');
    setupImagePreview('bpEncryptedImageUpload', 'bpEncryptedPreview');

    document.getElementById('bpEncryptBtn').addEventListener('click', function() {
        const button = this;
        const originalBtnContent = button.innerHTML;

        const fileInput = document.getElementById('bpOriginalImage');
        const algorithm = document.getElementById('bpAlgorithm').value;
        const bpKey = document.getElementById('bpKey').value;
        const selectedPlanes = Array.from(document.querySelectorAll('input[name="bpPlanesEncrypt"]:checked')).map(el => el.value);

        if (!fileInput.files[0]) {
            alert('Please select an image to encrypt');
            return;
        }
        if (selectedPlanes.length === 0) {
            alert('Please select at least one bit plane to encrypt');
            return;
        }

        const formData = new FormData();
        formData.append('image', fileInput.files[0]);
        formData.append('algorithm', algorithm);
        formData.append('planes', selectedPlanes.join(','));
        if (bpKey) formData.append('key', bpKey);

        setButtonProcessing(button.id, originalBtnContent, true);

        fetch('/bitplane_encrypt', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                document.getElementById('bpEncryptedImage').src = data.encrypted_image + '?' + new Date().getTime();
                document.getElementById('bpKeyDisplay').textContent = data.key;
                document.getElementById('bpEncryptedSection').classList.remove('hidden');
                document.getElementById('bpDownloadBtn').href = data.encrypted_image;
                
                document.getElementById('bpCopyKeyBtn').onclick = function() {
                    navigator.clipboard.writeText(data.key).then(() => {
                        alert('Key copied to clipboard!');
                    });
                };
            } else {
                alert('Error: ' + data.error);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred during encryption.');
        })
        .finally(() => {
            setButtonProcessing(button.id, originalBtnContent, false);
        });
    });

    document.getElementById('bpDecryptBtn').addEventListener('click', function() {
        const button = this;
        const originalBtnContent = button.innerHTML;
        
        const fileInput = document.getElementById('bpEncryptedImageUpload');
        const algorithm = document.getElementById('bpDecryptAlgorithm').value;
        const decryptKey = document.getElementById('bpDecryptKey').value;
        const selectedPlanes = Array.from(document.querySelectorAll('input[name="bpPlanesDecrypt"]:checked')).map(el => el.value);

        if (!fileInput.files[0]) {
            alert('Please select an encrypted image');
            return;
        }
        if (!decryptKey) {
            alert('Please enter the decryption key');
            return;
        }
        if (selectedPlanes.length === 0) {
            alert('Please select the bit planes that were encrypted');
            return;
        }

        const formData = new FormData();
        formData.append('image', fileInput.files[0]);
        formData.append('algorithm', algorithm);
        formData.append('key', decryptKey);
        formData.append('planes', selectedPlanes.join(','));

        setButtonProcessing(button.id, originalBtnContent, true);

        fetch('/bitplane_decrypt', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                document.getElementById('bpDecryptedImage').src = data.decrypted_image + '?' + new Date().getTime();
                document.getElementById('bpDecryptedSection').classList.remove('hidden');
                document.getElementById('bpDownloadDecryptedBtn').href = data.decrypted_image;
            } else {
                alert('Error: ' + data.error);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred during decryption.');
        })
        .finally(() => {
            setButtonProcessing(button.id, originalBtnContent, false);
        });
    });
});