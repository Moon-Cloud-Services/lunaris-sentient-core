from flask import Flask, request, jsonify
from app.controllers import malware_controller
from app.utils.encryption import Encryption
import logging
import os
import time
from tqdm import tqdm
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from colorama import init, Fore, Style

init(autoreset=True)

console = Console()

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console)]
    )
    return logging.getLogger("lunaris")

logger = setup_logging()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['UPLOAD_FOLDER'] = 'uploads/'

encryption = Encryption(app.config['SECRET_KEY'])

@app.route("/")
def home():
    logger.info("Home endpoint accessed")
    return {"message": "Lunaris Sentient Core is running"}

@app.route('/scan_file', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        logger.error('No file found in the request')
        return jsonify({"error": "No file found in the request"}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        logger.error('No file selected')
        return jsonify({"error": "No file selected"}), 400
    
    logger.info(f'Receiving file for scanning: {file.filename}')
    filedata = file.read()
    prediction = malware_controller.malware_service.scan_malware(filedata)
    
    return jsonify({"prediction": prediction})

@app.route('/train_model', methods=['POST'])
def train_model():
    logger.info("Starting model training via endpoint")
    malware_controller.malware_service.train_model()
    logger.info("Model trained successfully")
    return jsonify({"message": "Model trained successfully"})

app.register_blueprint(malware_controller.bp)

def initialize_lunaris():
    console.print(Panel(Text("Lunaris Sentient Core", justify="center", style="bold magenta"), title="[cyan]" + "=" * 50 + "[/cyan]", subtitle="[yellow]Powered by Moon Cloud Services❤️[/yellow]"))
    
    logger.info("Starting Lunaris Sentient Core")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[green]Initializing systems...", total=5)
        for _ in range(5):
            time.sleep(0.5)
            progress.update(task, advance=1)
    
    if not malware_controller.malware_service.model_trained:
        logger.info("Model not trained. Starting initial training.")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[green]Training initial model...", total=1)
            malware_controller.malware_service.train_model()
            progress.update(task, advance=1)
        logger.info("Initial training completed")
    else:
        logger.info("Model already trained. Ready for use.")
    
    console.print(Panel(Text("Lunaris Sentient Core is ready!", justify="center", style="bold green"), title="[cyan]" + "=" * 50 + "[/cyan]"))

if __name__ == "__main__":
    initialize_lunaris()
    logger.info("Starting Flask server")
    app.run(debug=True)
