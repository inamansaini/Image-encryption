document.addEventListener('DOMContentLoaded', function() {
    const encryptBtn = document.getElementById('encryptBtn');
    const decryptBtn = document.getElementById('decryptBtn');
    const copyKeyBtn = document.getElementById('copyKeyBtn');

    const originalEncryptBtnHTML = encryptBtn.innerHTML;
    const originalDecryptBtnHTML = decryptBtn.innerHTML;

    document.getElementById('originalImage').addEventListener('change', function(e) {
        const file = e.target.files[0];
        if (file) {
            document.getElementById('original-filename').textContent = file.name;
            
            const reader = new FileReader();
            reader.onload = function(event) {
                document.getElementById('originalPreview').src = event.target.result;
                document.getElementById('original-preview-container').classList.add('has-image');
            };
            reader.readAsDataURL(file);
        }
    });

    document.getElementById('encryptedImageUpload').addEventListener('change', function(e) {
        const file = e.target.files[0];
        if (file) {
            document.getElementById('encrypted-filename').textContent = file.name;
            
            const reader = new FileReader();
            reader.onload = function(event) {
                document.getElementById('encryptedPreview').src = event.target.result;
                document.getElementById('encrypted-preview-container').classList.add('has-image');
            };
            reader.readAsDataURL(file);
        }
    });

    copyKeyBtn.addEventListener('click', function() {
        const keyToCopy = document.getElementById('keyDisplay').textContent;
        if (keyToCopy) {
            navigator.clipboard.writeText(keyToCopy).then(() => {
                alert('Key copied to clipboard!');
            }).catch(err => {
                console.error('Failed to copy key: ', err);
                alert('Failed to copy key.');
            });
        }
    });

    encryptBtn.addEventListener('click', function() {
        const fileInput = document.getElementById('originalImage');
        const chaosType = document.getElementById('chaosType').value;
        const chaosKey = document.getElementById('chaosKey').value;

        if (!fileInput.files[0]) {
            alert('Please select an image to encrypt');
            return;
        }

        const formData = new FormData();
        formData.append('image', fileInput.files[0]);
        formData.append('algorithm', chaosType);
        if (chaosKey) formData.append('key', chaosKey);

        encryptBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        encryptBtn.disabled = true;

        fetch('/chaotic_encrypt', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                document.getElementById('encryptedImage').src = data.encrypted_image + '?' + new Date().getTime();
                document.getElementById('keyDisplay').textContent = data.key;
                document.getElementById('encryptedSection').classList.remove('hidden');
                document.getElementById('downloadBtn').href = data.encrypted_image;
            } else {
                alert('Error: ' + data.error);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred during encryption');
        })
        .finally(() => {
            encryptBtn.innerHTML = originalEncryptBtnHTML;
            encryptBtn.disabled = false;
        });
    });

    decryptBtn.addEventListener('click', function() {
        const fileInput = document.getElementById('encryptedImageUpload');
        const decryptChaosType = document.getElementById('decryptChaosType').value;
        const decryptKey = document.getElementById('decryptKey').value;

        if (!fileInput.files[0]) {
            alert('Please select an encrypted image');
            return;
        }
        if (!decryptKey) {
            alert('Please enter the decryption key');
            return;
        }

        const formData = new FormData();
        formData.append('image', fileInput.files[0]);
        formData.append('algorithm', decryptChaosType);
        formData.append('key', decryptKey);

        decryptBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        decryptBtn.disabled = true;

        fetch('/chaotic_decrypt', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                document.getElementById('decryptedImage').src = data.decrypted_image + '?' + new Date().getTime();
                document.getElementById('decryptedSection').classList.remove('hidden');
                document.getElementById('downloadDecryptedBtn').href = data.decrypted_image;
            } else {
                alert('Error: ' + data.error);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred during decryption');
        })
        .finally(() => {
            decryptBtn.innerHTML = originalDecryptBtnHTML;
            decryptBtn.disabled = false;
        });
    });
});
