document.addEventListener('DOMContentLoaded', function() {
    // Get all elements from the DOM
    const coverImage = document.getElementById('coverImage');
    const secretImage = document.getElementById('secretImage');
    const hiddenImageUpload = document.getElementById('hiddenImageUpload');
    const coverPreview = document.getElementById('coverPreview');
    const secretPreview = document.getElementById('secretPreview');
    const hiddenPreview = document.getElementById('hiddenPreview');
    const hideBtn = document.getElementById('hideBtn');
    const resultSection = document.getElementById('resultSection');
    const hiddenImage = document.getElementById('hiddenImage');
    const keyDisplay = document.getElementById('keyDisplay');
    const downloadBtn = document.getElementById('downloadBtn');
    const copyKeyBtn = document.getElementById('copyKeyBtn');
    const decryptBtn = document.getElementById('decryptBtn');
    const keyInput = document.getElementById('keyInput');
    const decryptedSection = document.getElementById('decryptedSection');
    const decryptedImage = document.getElementById('decryptedImage');
    const downloadDecryptedBtn = document.getElementById('downloadDecryptedBtn');

    function setupFileInputProxy(inputId) {
        const fileInput = document.getElementById(inputId);
        if (fileInput) {
            const fileButton = fileInput.nextElementSibling;
            if (fileButton && fileButton.classList.contains('file-input-button')) {
                fileButton.addEventListener('click', () => {
                    fileInput.click();
                });
            }
        }
    }
    setupFileInputProxy('coverImage');
    setupFileInputProxy('secretImage');
    setupFileInputProxy('hiddenImageUpload');

    // Preview images when selected
    if (coverImage && coverPreview) {
        coverImage.addEventListener('change', function(e) {
            previewImage(e.target, coverPreview);
        });
    }
    
    if (secretImage && secretPreview) {
        secretImage.addEventListener('change', function(e) {
            previewImage(e.target, secretPreview);
        });
    }
    
    if (hiddenImageUpload && hiddenPreview) {
        hiddenImageUpload.addEventListener('change', function(e) {
            previewImage(e.target, hiddenPreview);
        });
    }

    // Hide image button functionality
    if (hideBtn) {
        hideBtn.addEventListener('click', async function() {
            const coverFile = coverImage?.files[0];
            const secretFile = secretImage?.files[0];
            
            if (resultSection) resultSection.classList.add('hidden');
            if (coverImage) coverImage.classList.remove('error-border');
            if (secretImage) secretImage.classList.remove('error-border');
            
            if (!coverFile || !secretFile) {
                alert('Please upload both cover and secret images!');
                if (!coverFile && coverImage) coverImage.classList.add('error-border');
                if (!secretFile && secretImage) secretImage.classList.add('error-border');
                return;
            }

            const originalBtnText = hideBtn.innerHTML;
            hideBtn.disabled = true;
            hideBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
            
            try {
                const formData = new FormData();
                formData.append('cover', coverFile);
                formData.append('secret', secretFile);

                const response = await fetch('/hide', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    if (hiddenImage) hiddenImage.src = result.hidden_image;
                    if (keyDisplay) keyDisplay.textContent = result.key;
                    if (resultSection) resultSection.classList.remove('hidden');
                    
                    // --- MODIFIED: Use the /download_image route ---
                    if (downloadBtn) {
                        downloadBtn.href = `/download_image?url=${encodeURIComponent(result.hidden_image)}&filename=hidden_image.png`;
                    }
                    
                    if (result.message) {
                        alert(`Success! ${result.message}`);
                    }
                    
                    if (resultSection) {
                        resultSection.scrollIntoView({ behavior: 'smooth' });
                    }
                } else {
                    alert(result.error); 
                }
            } catch (error) {
                console.error('Error:', error);
                alert(`Network error: ${error.message}\n\nPlease check your connection and try again.`);
            } finally {
                hideBtn.disabled = false;
                hideBtn.innerHTML = originalBtnText;
            }
        });
    }

    // Decrypt button functionality
    if (decryptBtn) {
        decryptBtn.addEventListener('click', async function() {
            const hiddenFile = hiddenImageUpload?.files[0];
            const key = keyInput?.value.trim();
            
            if (!hiddenFile || !key) {
                alert('Please upload a hidden image and enter the decryption key!');
                return;
            }

            if (decryptedSection) decryptedSection.classList.add('hidden');

            const originalBtnText = decryptBtn.innerHTML;
            decryptBtn.disabled = true;
            decryptBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Decrypting...';
            
            try {
                const formData = new FormData();
                formData.append('hidden', hiddenFile);
                formData.append('key', key);

                const response = await fetch('/decrypt', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    if (decryptedImage) {
                        decryptedImage.src = result.decrypted_image;
                        decryptedImage.onload = function() {
                            if (decryptedSection) decryptedSection.classList.remove('hidden');
                            if (decryptedSection) {
                                decryptedSection.scrollIntoView({ behavior: 'smooth' });
                            }
                        };
                    }
                    // --- MODIFIED: Use the /download_image route ---
                    if (downloadDecryptedBtn) {
                        downloadDecryptedBtn.href = `/download_image?url=${encodeURIComponent(result.decrypted_image)}&filename=revealed_image.png`;
                    }
                } else {
                    alert(result.error);
                }
            } catch (error) {
                console.error('Network error:', error);
                alert(`Network error: ${error.message}\nPlease check your connection and try again.`);
            } finally {
                decryptBtn.disabled = false;
                decryptBtn.innerHTML = originalBtnText;
            }
        });
    }

    // Copy key button functionality
    if (copyKeyBtn && keyDisplay) {
        copyKeyBtn.addEventListener('click', function() {
            const key = keyDisplay.textContent;
            navigator.clipboard.writeText(key).then(() => {
                alert('Key copied to clipboard!');
            }).catch(err => {
                console.error('Failed to copy key:', err);
            });
        });
    }

    // Helper function to preview images
    function previewImage(input, previewElement) {
        const file = input?.files[0];
        if (!file || !previewElement) return;

        if (!file.type.startsWith('image/')) {
            alert('Please select a valid image file.');
            input.value = ''; // Clear the invalid input
            return;
        }

        const reader = new FileReader();
        reader.onload = function(e) {
            previewElement.src = e.target.result;
            previewElement.parentElement.classList.add('has-image');
        };
        reader.readAsDataURL(file);
    }
});