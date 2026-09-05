document.addEventListener('DOMContentLoaded', function() {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const form = document.getElementById('upload-form');
    const loading = document.getElementById('loading');
    const analyzeBtn = document.getElementById('analyze-btn');
    const progressContainer = document.getElementById('progress-container');
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');

    if (dropZone) {
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('dragover');
        });
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files;
                updateFileDisplay(files[0].name);
            }
        });
        dropZone.addEventListener('click', () => {
            fileInput.click();
        });
    }
    if (fileInput) {
        fileInput.addEventListener('change', function() {
            if (this.files.length > 0) {
                updateFileDisplay(this.files[0].name);
            } else {
                removeFileDisplay();
            }
        });
    }

    function updateFileDisplay(filename) {
        removeFileDisplay();
        const nameSpan = document.createElement('p');
        nameSpan.textContent = `📎 Selected: ${filename}`;
        nameSpan.className = 'file-name';
        nameSpan.style.color = '#4a90d9';
        nameSpan.style.fontWeight = 'bold';
        nameSpan.style.marginTop = '0.5rem';
        dropZone.appendChild(nameSpan);
    }
    
    function removeFileDisplay() {
        const old = dropZone.querySelector('.file-name');
        if (old) old.remove();
    }
    if (form) {
        form.addEventListener('submit', function(e) {
            if (!fileInput || fileInput.files.length === 0) {
                e.preventDefault();
                alert('Please select a .eml file to analyze.');
                return;
            }
            const filename = fileInput.files[0].name;
            if (!filename.toLowerCase().endsWith('.eml')) {
                e.preventDefault();
                alert('Please upload a valid .eml file.');
                return;
            }
            if (progressContainer) {
                progressContainer.style.display = 'block';
                progressBar.style.width = '0%';
                progressText.textContent = 'Analyzing... 0%';
            }            
            if (analyzeBtn) {
                analyzeBtn.disabled = true;
                analyzeBtn.textContent = '⏳ Analyzing...';
            }
            let progress = 0;
            const interval = setInterval(() => {
                progress += 10;
                if (progress > 90) {
                    clearInterval(interval);
                    progress = 90;
                }
                if (progressBar) {
                    progressBar.style.width = progress + '%';
                }
                if (progressText) {
                    progressText.textContent = `Analyzing... ${progress}%`;
                }
            }, 200);
        });
    }
    if (window.location.pathname === '/analyze' && progressContainer) {
        progressBar.style.width = '100%';
        progressText.textContent = '✅ Analysis Complete!';
        setTimeout(() => {
            progressContainer.style.display = 'none';
        }, 2000);
    }
});