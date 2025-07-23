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

    // --- FIX: BUTTON CLICK HANDLING ---
    // This new section makes the styled buttons trigger the hidden file inputs.
    function setupFileInputProxy(inputId) {
        const fileInput = document.getElementById(inputId);
        if (fileInput) {
            // The button is the next element sibling in the user's HTML
            const fileButton = fileInput.nextElementSibling;
            if (fileButton && fileButton.classList.contains('file-input-button')) {
                fileButton.addEventListener('click', () => {
                    fileInput.click(); // Programmatically click the hidden file input
                });
            }
        }
    }
    // Set up the click proxy for all three file inputs
    setupFileInputProxy('coverImage');
    setupFileInputProxy('secretImage');
    setupFileInputProxy('hiddenImageUpload');
    // --- END OF FIX ---


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
            
            // Clear previous results and errors
            if (resultSection) resultSection.classList.add('hidden');
            if (coverImage) coverImage.classList.remove('error-border');
            if (secretImage) secretImage.classList.remove('error-border');
            
            if (!coverFile || !secretFile) {
                alert('Please upload both cover and secret images!');
                if (!coverFile && coverImage) coverImage.classList.add('error-border');
                if (!secretFile && secretImage) secretImage.classList.add('error-border');
                return;
            }

            // Show loading state
            const originalBtnText = hideBtn.textContent;
            hideBtn.disabled = true;
            hideBtn.textContent = 'Processing...';
            
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
                    // Display results
                    if (hiddenImage) hiddenImage.src = result.hidden_image;
                    if (keyDisplay) keyDisplay.textContent = result.key;
                    if (resultSection) resultSection.classList.remove('hidden');
                    if (downloadBtn) downloadBtn.href = result.hidden_image;
                    
                    // Show additional info if available
                    if (result.message) {
                        alert(`Success! ${result.message}`);
                    }
                    
                    // Scroll to results
                    if (resultSection) {
                        resultSection.scrollIntoView({
                            behavior: 'smooth'
                        });
                    }
                } else {
                    // Enhanced error display
                    let errorMsg = result.error;
                    if (result.secret_size_kb && result.cover_capacity_kb) {
                        errorMsg += `\n\n• Secret Size: ${result.secret_size_kb} KB\n• Cover Capacity: ${result.cover_capacity_kb} KB`;
                        
                        // Highlight problematic inputs
                        if (coverImage) coverImage.classList.add('error-border');
                        if (secretImage) secretImage.classList.add('error-border');
                    }
                    
                    alert(errorMsg); 
                }
            } catch (error) {
                console.error('Error:', error);
                alert(`Network error: ${error.message}\n\nPlease check your connection and try again.`);
            } finally {
                // Restore button state
                hideBtn.disabled = false;
                hideBtn.textContent = originalBtnText;
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
                if (!hiddenFile && hiddenImageUpload) hiddenImageUpload.classList.add('error-border');
                if (!key && keyInput) keyInput.classList.add('error-border');
                return;
            }

            // Clear previous errors
            if (hiddenImageUpload) hiddenImageUpload.classList.remove('error-border');
            if (keyInput) keyInput.classList.remove('error-border');
            if (decryptedSection) decryptedSection.classList.add('hidden');

            // Show loading state
            const originalBtnText = decryptBtn.textContent;
            decryptBtn.disabled = true;
            decryptBtn.textContent = 'Decrypting...';
            
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
                    // Display results
                    if (decryptedImage) {
                        decryptedImage.src = result.decrypted_image;
                        // Add onload handler to ensure image loads
                        decryptedImage.onload = function() {
                            if (decryptedSection) decryptedSection.classList.remove('hidden');
                            // Scroll to results
                            if (decryptedSection) {
                                decryptedSection.scrollIntoView({
                                    behavior: 'smooth'
                                });
                            }
                        };
                        decryptedImage.onerror = function() {
                            alert('Error loading decrypted image. Please try again.');
                        };
                    }
                    if (downloadDecryptedBtn) downloadDecryptedBtn.href = result.decrypted_image;
                } else {
                    // Show detailed error message
                    alert(result.error);
                    console.error('Decryption failed:', result.error);
                }
            } catch (error) {
                console.error('Network error:', error);
                alert(`Network error: ${error.message}\nPlease check your connection and try again.`);
            } finally {
                // Restore button state
                decryptBtn.disabled = false;
                decryptBtn.textContent = originalBtnText;
            }
        });
    }

    // Copy key button functionality
    if (copyKeyBtn && keyDisplay) {
        copyKeyBtn.addEventListener('click', function() {
            const key = keyDisplay.textContent;
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(key).then(() => {
                    alert('Key copied to clipboard!');
                }).catch(err => {
                    console.error('Failed to copy key:', err);
                    fallbackCopyTextToClipboard(key);
                });
            } else {
                fallbackCopyTextToClipboard(key);
            }
        });
    }

    // Fallback copy function for older browsers
    function fallbackCopyTextToClipboard(text) {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.position = "fixed";
        textArea.style.left = "-999999px";
        textArea.style.top = "-999999px";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            const successful = document.execCommand('copy');
            if (successful) {
                alert('Key copied to clipboard!');
            } else {
                alert('Failed to copy key. Please copy it manually.');
            }
        } catch (err) {
            console.error('Fallback copy failed:', err);
            alert('Failed to copy key. Please copy it manually.');
        }
        
        document.body.removeChild(textArea);
    }

    // Helper function to preview images
    function previewImage(input, previewElement) {
        const file = input?.files[0];
        if (!file || !previewElement) return;

        // Validate file type
        if (!file.type.startsWith('image/')) {
            alert('Please select a valid image file.');
            return;
        }

        // CHANGE: Validate file size (64MB limit) and update alert message
        if (file.size > 64 * 1024 * 1024) {
            alert('Image file is too large. Please select a file smaller than 64MB.');
            return;
        }

        const reader = new FileReader();
        reader.onload = function(e) {
            previewElement.src = e.target.result;
            
            // Apply consistent preview sizing
            previewElement.onload = function() {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                const MAX_SIZE = 300;
                
                // Calculate new dimensions
                let width = previewElement.naturalWidth;
                let height = previewElement.naturalHeight;
                
                if (width > height) {
                    if (width > MAX_SIZE) {
                        height *= MAX_SIZE / width;
                        width = MAX_SIZE;
                    }
                } else {
                    if (height > MAX_SIZE) {
                        width *= MAX_SIZE / height;
                        height = MAX_SIZE;
                    }
                }
                
                // Resize canvas
                canvas.width = width;
                canvas.height = height;
                ctx.drawImage(previewElement, 0, 0, width, height);
                
                // Update preview
                previewElement.src = canvas.toDataURL('image/png');
            };
        };
        reader.onerror = function() {
            alert('Error reading the image file.');
        };
        reader.readAsDataURL(file);
    }
});