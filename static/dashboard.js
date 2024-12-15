const dropArea = document.getElementById('dropArea');
const imageInput = document.getElementById('imageInput');
const contentField = document.getElementById('content');

// Show file input when clicking the drop area
dropArea.addEventListener('click', () => {
    imageInput.click();
});

// Highlight drop area when dragging files
dropArea.addEventListener('dragover', (event) => {
    event.preventDefault();
    dropArea.classList.add('dragging');
});

dropArea.addEventListener('dragleave', () => {
    dropArea.classList.remove('dragging');
});

// Handle file drop
dropArea.addEventListener('drop', (event) => {
    event.preventDefault();
    dropArea.classList.remove('dragging');

    const file = event.dataTransfer.files[0];
    if (file) {
        handleImageUpload(file);
    }
});

// Handle file selection via input
imageInput.addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (file) {
        handleImageUpload(file);
    }
});

// Handle image upload and embed in the textarea
function handleImageUpload(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
        const imageUrl = e.target.result;
        contentField.value += `\n![Image](${imageUrl})\n`; // Markdown-style embedding
    };
    reader.readAsDataURL(file);
}
