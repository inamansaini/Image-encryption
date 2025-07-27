document.addEventListener('DOMContentLoaded', function () {
    const encryptForm = document.getElementById('encryptForm');
    const decryptForm = document.getElementById('decryptForm');

    function setupFileDropArea(form) {
        const fileInput = form.querySelector('input[type="file"]');
        const fileLabel = form.querySelector('.file-label');
        const dropArea = form.querySelector('.file-drop-area');
        const preview = form.querySelector('.image-preview');
        const dropAreaText = dropArea.querySelector('p');

        fileLabel.addEventListener('click', (e) => {
            e.stopPropagation();
        });

        const handleFileChange = (event) => {
            const file = event.target.files[0];
            if (file && file.type.startsWith('image/')) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    preview.src = e.target.result;
                    preview.style.display = 'block';
                    dropAreaText.textContent = file.name;
                };
                reader.readAsDataURL(file);
            }
        };

        dropArea.addEventListener('click', () => fileInput.click());
        dropArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropArea.classList.add('active');
        });
        dropArea.addEventListener('dragleave', () => dropArea.classList.remove('active'));
        dropArea.addEventListener('drop', (e) => {
            e.preventDefault();
            dropArea.classList.remove('active');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files;
                handleFileChange({ target: fileInput });
            }
        });

        fileInput.addEventListener('change', handleFileChange);
    }

    setupFileDropArea(encryptForm);
    setupFileDropArea(decryptForm);

    encryptForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const formData = new FormData(this);
        const resultArea = document.getElementById('encryptResult');
        const submitButton = this.querySelector('.btn-submit');
        handleFormSubmit('/dna_encrypt', formData, resultArea, submitButton, true);
    });

    decryptForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const formData = new FormData(this);
        const resultArea = document.getElementById('decryptResult');
        const submitButton = this.querySelector('.btn-submit');
        handleFormSubmit('/dna_decrypt', formData, resultArea, submitButton, false);
    });
});

async function handleFormSubmit(url, formData, resultArea, button, isEncrypt) {
    const originalButtonHtml = button.innerHTML;
    button.disabled = true;
    button.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Processing...`;

    resultArea.style.display = 'none';
    resultArea.innerHTML = '';
    resultArea.classList.remove('error', 'success');

    try {
        const response = await fetch(url, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) throw new Error(`Server error: ${response.statusText}`);
        
        const data = await response.json();

        if (data.success) {
            resultArea.classList.add('success');
            let content = '';
            const cacheBuster = `?t=${new Date().getTime()}`;

            if (isEncrypt) {
                content = `
                        <h4><i class="fas fa-check-circle"></i> Encryption Successful!</h4>
                        <div class="key-container">
                            <p><strong>Your Key:</strong></p>
                            <div class="key-display-wrapper">
                                <span id="encryptionKeyText" class="key-display">${data.key}</span>
                                <button type="button" id="copyKeyBtn" class="btn-copy-key" title="Copy key">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                        </div>
                        <div class="result-image-container">
                            <img src="${data.encrypted_image}${cacheBuster}" alt="Encrypted Image" class="result-image">
                        </div>
                        <a href="${data.encrypted_image}" download="encrypted_dna_${Date.now()}.png" class="btn-download">
                            <i class="fas fa-download"></i> Download Encrypted Image
                        </a>`;
            } else {
                content = `
                        <h4><i class="fas fa-check-circle"></i> Decryption Successful!</h4>
                        <div class="result-image-container">
                            <img src="${data.decrypted_image}${cacheBuster}" alt="Decrypted Image" class="result-image">
                        </div>
                        <a href="${data.decrypted_image}" download="decrypted_dna_${Date.now()}.png" class="btn-download">
                            <i class="fas fa-download"></i> Download Decrypted Image
                        </a>`;
            }
            resultArea.innerHTML = content;

            if (isEncrypt) {
                const copyBtn = document.getElementById('copyKeyBtn');
                const keyText = document.getElementById('encryptionKeyText');
                
                if (copyBtn && keyText) {
                    copyBtn.addEventListener('click', () => {
                        if (copyBtn.classList.contains('copied')) return;

                        navigator.clipboard.writeText(keyText.innerText).then(() => {
                            const originalIcon = copyBtn.innerHTML;
                            copyBtn.classList.add('copied');
                            copyBtn.innerHTML = '<i class="fas fa-check"></i> Copied';
                            
                            setTimeout(() => {
                                copyBtn.classList.remove('copied');
                                copyBtn.innerHTML = originalIcon;
                            }, 2000);

                        }).catch(err => {
                            console.error('Failed to copy text: ', err);
                            copyBtn.title = 'Failed to copy';
                        });
                    });
                }
            }

        } else {
            throw new Error(data.error || 'An unknown error occurred.');
        }
    } catch (error) {
        resultArea.classList.add('error');
        resultArea.innerHTML = `<h4><i class="fas fa-exclamation-triangle"></i> Error</h4><p>${error.message}</p>`;
    } finally {
        button.disabled = false;
        button.innerHTML = originalButtonHtml;
        resultArea.style.display = 'block';
    }
}
