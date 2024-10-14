import os
import sys
import threading
import logging
import requests
import zipfile
import io
import time
import json
from rich.logging import RichHandler
from rich.progress import track, Progress
from flask import Flask, request, jsonify, render_template, send_from_directory, Response, stream_with_context
from ai.training import load_and_preprocess_data, train_model

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from malware_analysis.analyzer import analyze_malware

# Basic logging configuration with rich
logging.basicConfig(level=logging.DEBUG, handlers=[RichHandler()])
logger = logging.getLogger("main")

# URLs and directories
MODEL_REPO_URL = "https://github.com/Moon-Cloud-Services/models-lunaris/archive/refs/heads/main.zip"
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'model_trained')
BACKUP_DIR = os.path.join(MODEL_DIR, 'backup')
TRAINING_FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'training_files')
UPLOADS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')

# Flask configuration
app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), 'interface_web/templates')
)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']
    file_path = os.path.join(TRAINING_FILES_DIR, file.filename)
    file.save(file_path)
    results = []
    for progress in analyze_malware(file_path):
        if isinstance(progress, tuple):
            results.append({"progress": progress[0], "message": progress[1]})
        else:
            results.append({"result": progress})
    return jsonify(results)

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']
    file_path = os.path.join(TRAINING_FILES_DIR, file.filename)
    file.save(file_path)

    def generate():
        yield json.dumps({"type": "progress", "percentage": 0, "message": "Starting analysis..."}) + '\n'
        for progress in analyze_malware(file_path):
            if isinstance(progress, tuple):
                percentage, message = progress
                yield json.dumps({"type": "progress", "percentage": percentage, "message": message}) + '\n'
            else:
                yield json.dumps({"type": "result", "message": progress}) + '\n'
        yield json.dumps({"type": "progress", "percentage": 100, "message": "Analysis completed"}) + '\n'

    return Response(stream_with_context(generate()), content_type='application/json')

@app.route('/templates/<path:filename>')
def serve_template_files(filename):
    return send_from_directory(app.template_folder, filename)

@app.route('/<path:filename>')
def serve_static_files(filename):
    return send_from_directory(os.path.join(app.template_folder), filename)

def download_models():
    logger.info("Downloading trained models from GitHub...")
    os.makedirs(MODEL_DIR, exist_ok=True)
    try:
        with requests.get(MODEL_REPO_URL) as response:
            if (response.status_code == 200):
                with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                    z.extractall(MODEL_DIR)
                logger.info("Models downloaded and extracted successfully.")
            else:
                logger.error("Failed to download models from GitHub.")
    except requests.RequestException as e:
        logger.error(f"Error during download: {e}")

def check_for_new_files():
    new_files = False
    for folder in ['0', 'amas_reports']:
        folder_path = os.path.join(TRAINING_FILES_DIR, folder)
        logger.info(f"Checking files in directory: {folder_path}")
        if os.path.exists(folder_path):
            files = os.listdir(folder_path)
            logger.info(f"Files found in directory {folder_path}: {files}")
            if files:
                new_files = True
                break
        else:
            logger.warning(f"The directory {folder_path} does not exist.")
    return new_files

def start_web_interface():
    logger.info("Starting the web interface...")
    app.run(debug=True, use_reloader=False)

def start_training():
    logger.info("Starting data preprocessing...")
    X_train, X_test, y_train, y_test = load_and_preprocess_data()
    if X_train is not None and X_test is not None and y_train is not None and y_test is not None:
        logger.info("Starting model training...")
        train_model(X_train, X_test, y_train, y_test)

def backup_existing_models():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    for file in os.listdir(MODEL_DIR):
        if file.endswith('.keras'):
            os.rename(os.path.join(MODEL_DIR, file), os.path.join(BACKUP_DIR, file))

def handle_user_choice(user_choice):
    if user_choice == '1':
        download_models()
    elif user_choice == '2':
        if check_for_new_files():
            train_choice = input("New files found. Do you want to train the model with these files? (y/n) ")
            if train_choice.lower() == 'y':
                backup_existing_models()
                start_training()
        else:
            logger.info("No new files found for training.")
    else:
        logger.error("Invalid choice. Exiting the program.")
        sys.exit(1)

def initialize_lunaris():
    logger.info("Initializing Lunaris Critical Systems...")
    with Progress() as progress:
        task = progress.add_task("[green]Initializing...", total=100)
        for _ in range(10):
            progress.update(task, advance=10)
            time.sleep(1)
    logger.info("Lunaris Critical Systems Successfully Initialized!")

if __name__ == '__main__':
    try:
        initialize_lunaris()
        user_choice = input("Do you want to download the trained models from GitHub (1) or train locally (2)? ")
        handle_user_choice(user_choice)
        logger.info("Starting the web interface...")
        start_web_interface()
    except KeyboardInterrupt:
        logger.info("User interruption. Exiting the program.")
    except Exception as e:
        logger.error(f"An error occurred: {e}")