# Lunaris Sentient Core

Lunaris Sentient Core is a machine learning-based malware detection system. It allows for the training of malware detection models and the scanning of files to identify potential threats.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation Steps

1. Clone the repository:

    ```sh
    git clone https://github.com/Moon-Cloud-Services/lunaris-sentient-core.git
    cd lunaris-sentient-core\lunaris-sentient-core-main
    ```

2. Create a virtual environment:

    ```sh
    python -m venv venv
    ```

3. Install dependencies:

    ```sh
    pip install -r requirements.txt
    ```

4. Configure environment variables:

    Create a `.env` file at the root of the project and add the following variables:

    ```env
    SECRET_KEY=your_secret_key
    ```

## Usage

### Running the Server

To start the Flask server, run:

```sh
cd lunaris-sentient-core\lunaris-sentient-core-main\lunaris-system\lunaris-core
python main.py
```

### Accessing the Application

Open your browser and go to `http://127.0.0.1:5000/`.

### Training the Model

1. Go to the upload page at `http://127.0.0.1:5000/upload_page`.
2. Upload malware and non-malware files for training.
3. Click the "Train Model" button to train the model.

### Scanning Files

1. Go to the upload page at `http://127.0.0.1:5000/upload_page`.
2. Upload a file for scanning.
3. The scan result will be displayed on the page.

### Training Data Folder Structure

To train the model, it is important to add files to the `training_data` folder with the following subfolders:
- `1` for malware files
- `0` for non-malware files

Create the `training_data` folder and add three files in each subfolder (`0` and `1`):

```sh
cd lunaris-sentient-core\lunaris-sentient-core-main\lunaris-system\lunaris-core\training_data
```
