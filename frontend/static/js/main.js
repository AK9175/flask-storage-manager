// Token refresh interceptor for Axios
function setupTokenRefreshInterceptor() {
    if (typeof axios === 'undefined') return;
    
    axios.interceptors.response.use(
        response => response,
        async error => {
            const originalRequest = error.config;
            
            // If 401 and we haven't retried yet
            if (error.response?.status === 401 && !originalRequest._retry) {
                originalRequest._retry = true;
                
                const refreshToken = localStorage.getItem('refresh_token');
                if (!refreshToken) {
                    // No refresh token, redirect to login
                    window.location.href = '/auth/admin/login';
                    return Promise.reject(error);
                }
                
                try {
                    // Call refresh endpoint
                    const refreshResponse = await axios.post('/auth/refresh-token', {
                        refresh_token: refreshToken
                    });
                    
                    // Store new tokens
                    const { access_token, id_token } = refreshResponse.data;
                    localStorage.setItem('access_token', access_token);
                    localStorage.setItem('id_token', id_token);
                    
                    // Update Authorization header
                    axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
                    originalRequest.headers['Authorization'] = `Bearer ${access_token}`;
                    
                    // Retry original request
                    return axios(originalRequest);
                } catch (refreshError) {
                    // Refresh failed, redirect to login
                    console.error('Token refresh failed:', refreshError);
                    localStorage.removeItem('access_token');
                    localStorage.removeItem('id_token');
                    localStorage.removeItem('refresh_token');
                    window.location.href = '/auth/admin/login';
                    return Promise.reject(refreshError);
                }
            }
            
            return Promise.reject(error);
        }
    );
}

// Initialize token refresh interceptor on page load
if (typeof axios !== 'undefined') {
    setupTokenRefreshInterceptor();
    
    // Set up initial Authorization header from localStorage
    const accessToken = localStorage.getItem('access_token');
    if (accessToken) {
        axios.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const selectButton = document.getElementById('selectButton');
    const fileList = document.getElementById('fileList');
    const preview = document.getElementById('preview');
    const currentPath = document.getElementById('currentPath');
    const newFolderBtn = document.getElementById('newFolderBtn');
    const toggleVisibilityBtn = document.getElementById('toggleVisibility');
    let currentPathValue = '';
    let showHiddenFiles = false;
    let hiddenFiles = new Set();

    // Get CSRF token from meta tag
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

    // Initialize file list
    listFiles(currentPathValue);

    // File upload handling
    selectButton.addEventListener('click', () => {
        fileInput.click();
    });

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('border-blue-500', 'bg-blue-50');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('border-blue-500', 'bg-blue-50');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('border-blue-500', 'bg-blue-50');
        const files = e.dataTransfer.files;
        handleFiles(files);
    });

    fileInput.addEventListener('change', () => {
        handleFiles(fileInput.files);
    });

    toggleVisibilityBtn.addEventListener('click', () => {
        showHiddenFiles = !showHiddenFiles;
        listFiles(currentPathValue);
    });

    function handleFiles(files) {
        if (files.length === 0) return;
        
        // Clear previous upload progress
        const uploadProgress = document.getElementById('uploadProgress');
        if (uploadProgress) {
            uploadProgress.innerHTML = '';
        }
        
        // Show initial message
        showMessage(`Preparing to upload ${files.length} file(s)...`, 'info');
        
        // Upload each file
        Array.from(files).forEach(uploadFile);
    }

    function createProgressBar(filename) {
        const progressBarContainer = document.createElement('div');
        progressBarContainer.className = 'bg-white rounded-lg p-3 border border-gray-200';
        progressBarContainer.innerHTML = `
            <div class="flex items-center mb-2">
                <div class="flex-shrink-0 mr-3">
                    <div class="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-600"></div>
                </div>
                <div class="flex-grow">
                    <div class="flex justify-between items-center mb-1">
                        <span class="text-sm font-medium text-gray-700 truncate" style="max-width: 200px;">${filename}</span>
                        <span class="text-sm text-gray-500 progress-percentage">0%</span>
                    </div>
                    <div class="w-full bg-gray-200 rounded-full h-2">
                        <div class="bg-blue-600 h-2 rounded-full transition-all duration-300" style="width: 0%"></div>
                    </div>
                </div>
            </div>
        `;
        
        const uploadProgress = document.getElementById('uploadProgress');
        if (uploadProgress) {
            uploadProgress.appendChild(progressBarContainer);
        }
        return progressBarContainer;
    }

    function updateProgressBar(container, percentage) {
        const progressBar = container.querySelector('.bg-blue-600');
        const percentageText = container.querySelector('.progress-percentage');
        const spinner = container.querySelector('.animate-spin');
        
        if (progressBar && percentageText) {
            progressBar.style.width = `${percentage}%`;
            percentageText.textContent = `${Math.round(percentage)}%`;
            
            if (percentage === 100 && spinner) {
                spinner.classList.remove('animate-spin', 'border-b-2', 'border-blue-600');
                spinner.innerHTML = `
                    <svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                    </svg>
                `;
            }
        }
    }

    async function uploadFile(file) {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('folder', currentPathValue);
        if (csrfToken) {
            formData.append('csrf_token', csrfToken);
        }

        const progressBarContainer = createProgressBar(file.name);

        try {
            const response = await fetch('/upload', {
                method: 'POST',
                headers: {
                    'X-CSRFToken': csrfToken
                },
                body: formData
            });

            const data = await response.json();
            if (!response.ok) {
                showMessage(data.error || `Failed to upload ${file.name}`, 'error');
                progressBarContainer.querySelector('.animate-spin').innerHTML = `
                    <svg class="w-5 h-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                `;
                return;
            }

            updateProgressBar(progressBarContainer, 100);
            setTimeout(() => {
                progressBarContainer.classList.add('opacity-0', 'transition-opacity', 'duration-500');
                setTimeout(() => progressBarContainer.remove(), 500);
                showMessage(`${file.name} uploaded successfully`, 'success');
            }, 1000);
            listFiles(currentPathValue);
        } catch (error) {
            console.error('Upload error:', error);
            showMessage(`Failed to upload ${file.name}`, 'error');
            progressBarContainer.querySelector('.animate-spin').innerHTML = `
                <svg class="w-5 h-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                </svg>
            `;
        }
    }

    function getFileIcon(mimeType) {
        const baseClass = 'w-5 h-5 mr-3';
        if (!mimeType) {
            return `<svg class="${baseClass} text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/>
            </svg>`;
        }
        if (mimeType.startsWith('image/')) {
            return `<svg class="${baseClass} text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/>
            </svg>`;
        }
        if (mimeType.startsWith('video/')) {
            return `<svg class="${baseClass} text-pink-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"/>
            </svg>`;
        }
        if (mimeType === 'application/pdf') {
            return `<svg class="${baseClass} text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/>
            </svg>`;
        }
        return `<svg class="${baseClass} text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/>
        </svg>`;
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async function listFiles(path = '') {
        try {
            const response = await fetch(`/list?prefix=${encodeURIComponent(path)}`);
            const data = await response.json();

            if (!fileList) {
                console.error('File list element not found');
                return;
            }

            if (data.error) {
                fileList.innerHTML = `<div class="text-red-600 p-4">${data.error}</div>`;
                return;
            }

            if (!data.files || data.files.length === 0) {
                fileList.innerHTML = '<div class="text-gray-500 p-4">No files found</div>';
                return;
            }

            const files = data.files.map(file => {
                if (!showHiddenFiles && hiddenFiles.has(file.name)) return '';

                const isImage = file.mime_type && file.mime_type.startsWith('image/');
                const isPDF = file.mime_type === 'application/pdf';
                const isVideo = file.mime_type && file.mime_type.startsWith('video/');
                const fileIcon = getFileIcon(file.mime_type);
                const fileSize = formatFileSize(file.size || 0);
                const isHidden = hiddenFiles.has(file.name);

                return `
                    <div class="flex items-center justify-between p-3 hover:bg-gray-50 rounded-lg transition-colors ${isHidden ? 'opacity-50' : ''}">
                        <div class="flex items-center flex-grow">
                            ${fileIcon}
                            <div class="min-w-0">
                                <div class="text-sm font-medium text-gray-900 truncate">${file.name}</div>
                                <div class="text-sm text-gray-500">${fileSize}</div>
                            </div>
                        </div>
                        <div class="flex items-center space-x-2">
                            ${(isImage || isPDF || isVideo) ? 
                                `<button onclick="showPreview('${file.preview_url}', '${file.mime_type}')" 
                                    class="p-1 hover:bg-blue-100 rounded-full" title="Preview">
                                    <svg class="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                                    </svg>
                                </button>` : ''}
                            <button onclick="shareFile('${file.name}')"
                                class="p-1 hover:bg-purple-100 rounded-full" title="Share">
                                <svg class="w-5 h-5 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z"/>
                                </svg>
                            </button>
                            <a href="/download/${encodeURIComponent(file.name)}" 
                                class="p-1 hover:bg-green-100 rounded-full" title="Download">
                                <svg class="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                                </svg>
                            </a>
                            <button onclick="deleteFile('${file.name}')"
                                class="p-1 hover:bg-red-100 rounded-full" title="Delete">
                                <svg class="w-5 h-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                                </svg>
                            </button>
                            <button onclick="toggleFileVisibility('${file.name}')"
                                class="p-1 hover:bg-gray-100 rounded-full" title="Toggle visibility">
                                <svg class="w-5 h-5 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${isHidden ? 
                                        'M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21' :
                                        'M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z'}"/>
                                </svg>
                            </button>
                        </div>
                    </div>
                `;
            }).join('');

            fileList.innerHTML = files;
        } catch (error) {
            console.error('Error listing files:', error);
            if (fileList) {
                fileList.innerHTML = '<div class="text-red-600 p-4">Error loading files</div>';
            }
        }
    }

    window.toggleFileVisibility = function(filename) {
        if (hiddenFiles.has(filename)) {
            hiddenFiles.delete(filename);
        } else {
            hiddenFiles.add(filename);
        }
        listFiles(currentPathValue);
    };

    function showMessage(message, type = 'info') {
        const messageDiv = document.createElement('div');
        messageDiv.className = `fixed bottom-4 right-4 p-4 rounded-lg ${
            type === 'error' ? 'bg-red-500' : 'bg-green-500'
        } text-white`;
        messageDiv.textContent = message;
        document.body.appendChild(messageDiv);
        setTimeout(() => messageDiv.remove(), 3000);
    }

    window.showPreview = function(url, mimeType) {
        if (!preview) return;

        if (mimeType.startsWith('image/')) {
            preview.innerHTML = `<img src="${url}" class="max-w-full h-auto" alt="Preview">`;
        } else if (mimeType === 'application/pdf') {
            preview.innerHTML = `<iframe src="${url}" class="w-full h-[500px]"></iframe>`;
        } else if (mimeType.startsWith('video/')) {
            preview.innerHTML = `<video src="${url}" controls class="max-w-full h-auto">Your browser does not support the video tag.</video>`;
        } else {
            preview.innerHTML = '<div class="text-gray-500">Preview not available for this file type</div>';
        }
    };

    window.deleteFile = async function(filename) {
        if (!confirm('Are you sure you want to delete this file?')) return;

        try {
            const response = await fetch(`/delete/${encodeURIComponent(filename)}`, {
                method: 'DELETE',
                headers: {
                    'X-CSRFToken': csrfToken
                }
            });

            if (!response.ok) {
                const data = await response.json();
                showMessage(data.error || 'Delete failed', 'error');
                return;
            }

            showMessage('File deleted successfully', 'success');
            listFiles(currentPathValue);
        } catch (error) {
            console.error('Delete error:', error);
            showMessage('Delete failed', 'error');
        }
    };

    newFolderBtn.addEventListener('click', () => {
        const folderName = prompt('Enter folder name:');
        if (folderName) {
            createFolder(folderName);
        }
    });

    async function createFolder(folderName) {
        try {
            const response = await fetch('/create_folder', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({
                    folder_name: currentPathValue + folderName + '/'
                })
            });

            const data = await response.json();
            if (!response.ok) {
                showMessage(data.error || 'Failed to create folder', 'error');
                return;
            }

            showMessage('Folder created successfully', 'success');
            listFiles(currentPathValue);
        } catch (error) {
            console.error('Error creating folder:', error);
            showMessage('Failed to create folder', 'error');
        }
    }

    window.shareFile = async function(filename) {
        try {
            const response = await fetch(`/share/${encodeURIComponent(filename)}`, {
                headers: {
                    'X-CSRFToken': csrfToken
                }
            });
            
            if (!response.ok) {
                throw new Error('Failed to generate share link');
            }
            
            const data = await response.json();
            
            // Create a temporary input to copy the URL
            const input = document.createElement('input');
            input.value = data.url;
            document.body.appendChild(input);
            input.select();
            document.execCommand('copy');
            document.body.removeChild(input);
            
            showMessage('Share link copied to clipboard!', 'success');
        } catch (error) {
            console.error('Share error:', error);
            showMessage('Failed to generate share link', 'error');
        }
    };
});