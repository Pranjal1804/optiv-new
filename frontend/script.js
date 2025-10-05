// filepath: frontend/script.js
document.addEventListener('DOMContentLoaded', () => {
    const uploadForm = document.getElementById('upload-form');
    const fileInput = document.getElementById('file-input');
    const fileNameSpan = document.getElementById('file-name');
    const submitButton = document.getElementById('submit-button');
    const spinner = document.getElementById('spinner');
    const uploadContainer = document.getElementById('upload-container');
    const resultsContainer = document.getElementById('results-container');
    const errorContainer = document.getElementById('error-container');
    const errorMessage = document.getElementById('error-message');
    const resetButton = document.getElementById('reset-button');
    const fileLabel = document.querySelector('.file-label');

    // Function to reset the UI to its initial state
    const resetUI = () => {
        uploadContainer.style.display = 'block';
        resultsContainer.style.display = 'none';
        errorContainer.style.display = 'none';
        fileInput.value = '';
        fileNameSpan.textContent = 'Click to select a file or drag and drop';
        submitButton.disabled = false;
        spinner.style.display = 'none';
    };

    // Handle file selection
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            fileNameSpan.textContent = fileInput.files[0].name;
        } else {
            fileNameSpan.textContent = 'Click to select a file or drag and drop';
        }
    });

    // Handle drag and drop
    fileLabel.addEventListener('dragover', (e) => {
        e.preventDefault();
        fileLabel.classList.add('dragover');
    });
    fileLabel.addEventListener('dragleave', () => {
        fileLabel.classList.remove('dragover');
    });
    fileLabel.addEventListener('drop', (e) => {
        e.preventDefault();
        fileLabel.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            fileInput.files = e.dataTransfer.files;
            fileNameSpan.textContent = fileInput.files[0].name;
        }
    });

    // Handle form submission
    uploadForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (!fileInput.files[0]) {
            alert('Please select a file first.');
            return;
        }

        submitButton.disabled = true;
        spinner.style.display = 'block';
        uploadContainer.style.display = 'block'; // Keep upload container visible
        resultsContainer.style.display = 'none';
        errorContainer.style.display = 'none';

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);

        try {
            const response = await fetch('/process-file/', {
                method: 'POST',
                body: formData,
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            displayResults(result);

        } catch (error) {
            displayError(error.message);
        } finally {
            spinner.style.display = 'none';
            submitButton.disabled = false;
        }
    });

    // Reset button functionality
    resetButton.addEventListener('click', resetUI);

    function displayError(message) {
        errorMessage.textContent = message;
        errorContainer.style.display = 'block';
        uploadContainer.style.display = 'none';
        resultsContainer.style.display = 'none';
    }

    function displayResults(data) {
        const { analysis, redacted_file_path } = data;

        // Simple Markdown-to-HTML parser for the analysis text
        const descriptionMatch = analysis.match(/\*\*File Description\*\*:\s*([\s\S]*?)(?=\*\*Key Findings\*\*|$)/);
        const findingsMatch = analysis.match(/\*\*Key Findings\*\*:\s*([\s\S]*)/);

        const description = descriptionMatch ? descriptionMatch[1].trim() : 'Not available.';
        const findings = findingsMatch ? findingsMatch[1].trim() : '';

        const findingsHtml = '<ul>' + findings.split('*').slice(1).map(item => `<li>${item.trim()}</li>`).join('') + '</ul>';

        document.getElementById('file-description').textContent = description;
        document.getElementById('key-findings').innerHTML = findingsHtml;
        document.getElementById('download-button').href = redacted_file_path;

        uploadContainer.style.display = 'none';
        resultsContainer.style.display = 'block';
    }

    // Initialize UI on page load
    resetUI();
});