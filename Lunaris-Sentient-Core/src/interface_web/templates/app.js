const UPLOAD_URL = '/analyze';
const STARTING_MESSAGE = 'Starting analysis...';
const ERROR_MESSAGE = 'An error occurred during the analysis:';

document.addEventListener('DOMContentLoaded', () => {
    const formElement = document.getElementById('file-upload-form');
    const fileInputElement = document.getElementById('file-selector');
    const progressContainerElement = document.getElementById('progress-wrapper');
    const progressBarElement = document.getElementById('progress-indicator');
    const progressTextElement = document.getElementById('progress-status');
    const resultElement = document.getElementById('analysis-result');

    formElement.addEventListener('submit', async (event) => {
        event.preventDefault();
        const formData = new FormData(formElement);
        displayProgress(true, STARTING_MESSAGE, progressContainerElement, resultElement, progressBarElement, progressTextElement);

        try {
            const response = await fetch(UPLOAD_URL, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error(ERROR_MESSAGE + ' ' + response.statusText);
            }

            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let jsonString = '';

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                jsonString += decoder.decode(value, { stream: true });

                const lines = jsonString.split('\n');
                jsonString = lines.pop(); // Keep the last partial line

                for (const line of lines) {
                    if (line.trim()) {
                        const data = JSON.parse(line);
                        handleData(data, progressBarElement, progressTextElement, resultElement);
                    }
                }
            }

            if (jsonString.trim()) {
                const data = JSON.parse(jsonString);
                handleData(data, progressBarElement, progressTextElement, resultElement);
            }

        } catch (error) {
            handleError(error.message, resultElement);
        }
    });
});

function displayProgress(show, message, progressContainer, resultElement, progressBar = null, progressText = null) {
    progressContainer.classList.toggle('hidden', !show);
    resultElement.classList.add('hidden');
    if (show && progressBar && progressText) {
        progressBar.style.width = '0%';
        progressText.textContent = message;
    }
}

function handleData(data, progressBar, progressText, resultElement) {
    if (data.type === 'progress') {
        progressBar.style.width = `${data.percentage}%`;
        progressText.textContent = data.message;
    } else if (data.type === 'result') {
        resultElement.classList.remove('hidden');
        resultElement.textContent = data.message;
    }
}

function handleError(message, resultElement) {
    resultElement.classList.remove('hidden');
    resultElement.textContent = message;
}