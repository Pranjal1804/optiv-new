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
        uploadContainer.style.display = 'block';
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
        const { analysis, html_analysis, redacted_file_path, original_filename } = data;
        
        console.log('Received data:', data); // Debug log

        // Check if we have HTML table format
        if (html_analysis && html_analysis.includes('<table')) {
            // Display HTML table format
            displayTableResults(html_analysis, analysis, redacted_file_path, original_filename);
        } else if (analysis) {
            // Fall back to markdown parsing
            displayMarkdownResults(analysis, redacted_file_path, original_filename);
        } else {
            // Fallback for no analysis
            document.getElementById('file-description').textContent = 'File processed successfully';
            document.getElementById('key-findings').innerHTML = '<p>No detailed analysis available</p>';
            if (redacted_file_path) {
                document.getElementById('download-button').href = redacted_file_path;
                document.getElementById('download-button').download = `redacted_${original_filename}`;
            }
        }

        uploadContainer.style.display = 'none';
        resultsContainer.style.display = 'block';
    }

    function displayTableResults(htmlTable, markdownAnalysis, redactedPath, originalName) {
        // Parse the HTML table to extract description and findings
        const parser = new DOMParser();
        const doc = parser.parseFromString(htmlTable, 'text/html');
        const table = doc.querySelector('table');
        
        if (table) {
            const cells = table.querySelectorAll('tbody td');
            if (cells.length >= 4) {
                // Extract description (3rd cell - index 2)
                const description = cells[2].textContent.trim();
                
                // Extract findings (4th cell - index 3, should contain a <ul>)
                const findingsList = cells[3].querySelector('ul');
                const findingsHtml = findingsList ? findingsList.outerHTML : 
                                     cells[3].innerHTML.includes('<br>') ? 
                                     '<ul>' + cells[3].innerHTML.split('<br>').map(f => f.trim() ? `<li>${f.replace('•', '').trim()}</li>` : '').join('') + '</ul>' :
                                     '<ul><li>Analysis completed successfully</li></ul>';
                
                document.getElementById('file-description').textContent = description;
                document.getElementById('key-findings').innerHTML = findingsHtml;
            } else {
                // Fallback if table structure is different
                console.log('Table structure unexpected, cells found:', cells.length);
                document.getElementById('file-description').textContent = 'Analysis completed successfully';
                document.getElementById('key-findings').innerHTML = '<ul><li>File processed and analyzed</li><li>Content extracted successfully</li></ul>';
            }
        } else {
            // No table found, try to extract from raw HTML or markdown
            console.log('No table found in HTML, trying markdown parsing...');
            if (markdownAnalysis) {
                displayMarkdownResults(markdownAnalysis, redactedPath, originalName);
                return;
            } else {
                document.getElementById('file-description').textContent = 'Analysis completed';
                document.getElementById('key-findings').innerHTML = '<ul><li>File processed successfully</li></ul>';
            }
        }

        // Set download link
        if (redactedPath) {
            document.getElementById('download-button').href = redactedPath;
            document.getElementById('download-button').download = `redacted_${originalName}`;
            document.getElementById('download-button').style.display = 'inline-block';
        } else {
            document.getElementById('download-button').style.display = 'none';
        }
        
        // Add view modes section
        addViewModes(htmlTable, markdownAnalysis);
    }

    function displayMarkdownResults(analysis, redactedPath, originalName) {
        console.log('Parsing markdown analysis:', analysis.substring(0, 200));
        
        // Try to parse markdown table
        const lines = analysis.split('\n').filter(line => line.trim());
        let description = 'Analysis completed successfully';
        let findings = ['File processed and analyzed'];
        
        // Look for table structure
        const tableLines = lines.filter(line => line.includes('|'));
        if (tableLines.length > 0) {
            // Find the data row (not header or separator)
            const dataRow = tableLines.find(line => 
                line.includes('|') && 
                !line.includes('File Name') && 
                !line.includes('---')
            );
            
            if (dataRow) {
                const cells = dataRow.split('|').map(cell => cell.trim()).filter(cell => cell);
                if (cells.length >= 4) {
                    description = cells[2]; // File Description
                    
                    // Parse findings from the 4th column
                    const findingsText = cells[3];
                    if (findingsText.includes('<br>')) {
                        findings = findingsText.split('<br>')
                            .map(f => f.replace('•', '').trim())
                            .filter(f => f);
                    } else if (findingsText.includes('•')) {
                        findings = findingsText.split('•')
                            .map(f => f.trim())
                            .filter(f => f);
                    }
                }
            }
        } else {
            // No table found, use the raw text
            const sentences = analysis.split('.').filter(s => s.trim().length > 10);
            if (sentences.length > 0) {
                description = sentences[0].trim() + '.';
                findings = sentences.slice(1, 4).map(s => s.trim()).filter(s => s);
            }
        }
        
        // Ensure we have at least some findings
        if (findings.length === 0) {
            findings = ['Content processed successfully'];
        }
        
        document.getElementById('file-description').textContent = description;
        document.getElementById('key-findings').innerHTML = 
            '<ul>' + findings.map(finding => `<li>${finding}</li>`).join('') + '</ul>';

        // Set download link
        if (redactedPath) {
            document.getElementById('download-button').href = redactedPath;
            document.getElementById('download-button').download = `redacted_${originalName}`;
            document.getElementById('download-button').style.display = 'inline-block';
        } else {
            document.getElementById('download-button').style.display = 'none';
        }

        // Add view modes
        addViewModes('<p>Table view not available</p>', analysis);
    }

    function addViewModes(htmlTable, markdownText) {
        // Check if view modes already exist
        if (document.getElementById('view-modes')) return;

        // Create view mode toggle
        const viewModesDiv = document.createElement('div');
        viewModesDiv.id = 'view-modes';
        viewModesDiv.className = 'view-modes';
        viewModesDiv.innerHTML = `
            <div class="view-toggle">
                <button class="view-btn active" data-view="summary">Summary View</button>
                <button class="view-btn" data-view="table">Table View</button>
                <button class="view-btn" data-view="raw">Raw Text</button>
            </div>
            <div class="view-content">
                <div id="summary-view" class="view-panel active">
                    <!-- Summary is shown by default in file-description and key-findings -->
                </div>
                <div id="table-view" class="view-panel" style="display:none;">
                    ${htmlTable}
                </div>
                <div id="raw-view" class="view-panel" style="display:none;">
                    <pre>${escapeHtml(markdownText)}</pre>
                </div>
            </div>
        `;

        // Insert after key findings
        const keyFindingsCard = document.getElementById('key-findings').closest('.result-card');
        keyFindingsCard.insertAdjacentElement('afterend', viewModesDiv);

        // Add event listeners for view switching
        document.querySelectorAll('.view-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const view = e.target.dataset.view;
                
                // Update active button
                document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                
                // Show selected view
                document.querySelectorAll('.view-panel').forEach(panel => {
                    panel.style.display = 'none';
                });
                
                if (view === 'summary') {
                    // Show the original summary cards
                    document.querySelector('#file-description').closest('.result-card').style.display = 'block';
                    document.querySelector('#key-findings').closest('.result-card').style.display = 'block';
                } else {
                    // Hide summary cards, show selected panel
                    document.querySelector('#file-description').closest('.result-card').style.display = 'none';
                    document.querySelector('#key-findings').closest('.result-card').style.display = 'none';
                    document.getElementById(`${view}-view`).style.display = 'block';
                }
            });
        });
    }

    function escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }

    // Initialize UI on page load
    resetUI();
});