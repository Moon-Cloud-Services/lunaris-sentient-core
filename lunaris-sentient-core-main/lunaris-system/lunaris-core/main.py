from flask import Flask, request, jsonify
from app.controllers import malware_controller
from app.utils.encryption import Encryption
import logging
import os
import time
from tqdm import tqdm
from colorama import init, Fore, Style

# Initialize colorama for console colors
init(autoreset=True)

# Configure logging
def setup_logging():
    log_format = f"{Fore.CYAN}%(asctime)s{Style.RESET_ALL} - {Fore.YELLOW}%(name)s{Style.RESET_ALL} - {Fore.GREEN}%(levelname)s{Style.RESET_ALL} - %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler("lunaris.log"),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

# Create a Flask instance
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['UPLOAD_FOLDER'] = 'uploads/'

# Initialize encryption
encryption = Encryption(app.config['SECRET_KEY'])

@app.route("/")
def home():
    logger.info("Home endpoint accessed")
    return {"message": "Lunaris Sentient Core is running"}

@app.route('/scan_file', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        logger.error(f'{Fore.RED}No file found in the request{Style.RESET_ALL}')
        return jsonify({"error": "No file found in the request"}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        logger.error(f'{Fore.RED}No file selected{Style.RESET_ALL}')
        return jsonify({"error": "No file selected"}), 400
    
    logger.info(f'{Fore.GREEN}Receiving file for scanning: {file.filename}{Style.RESET_ALL}')
    filedata = file.read()
    prediction = malware_controller.malware_service.scan_malware(filedata)
    
    return jsonify({"prediction": prediction})

@app.route('/train_model', methods=['POST'])
def train_model():
    logger.info(f"{Fore.YELLOW}Starting model training via endpoint{Style.RESET_ALL}")
    malware_controller.malware_service.train_model()
    logger.info(f"{Fore.GREEN}Model trained successfully{Style.RESET_ALL}")
    return jsonify({"message": "Model trained successfully"})

# Register the malware controller blueprint
app.register_blueprint(malware_controller.bp)

def initialize_lunaris():
    print(f"\n{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}Lunaris Sentient Core{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Powered by Moon Cloud Services❤️{Style.RESET_ALL}\n")
    
    logger.info("Starting Lunaris Sentient Core")
    
    for i in tqdm(range(5), desc=f"{Fore.GREEN}Initializing systems{Style.RESET_ALL}", ncols=70):
        time.sleep(0.5)
    
    if not malware_controller.malware_service.model_trained:
        logger.info(f"{Fore.YELLOW}Model not trained. Starting initial training.{Style.RESET_ALL}")
        for _ in tqdm(range(1), desc=f"{Fore.GREEN}Training initial model{Style.RESET_ALL}", ncols=70):
            malware_controller.malware_service.train_model()
        logger.info(f"{Fore.GREEN}Initial training completed{Style.RESET_ALL}")
    else:
        logger.info(f"{Fore.GREEN}Model already trained. Ready for use.{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Lunaris Sentient Core is ready!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}\n")

if __name__ == "__main__":
    initialize_lunaris()
    logger.info(f"{Fore.YELLOW}Starting Flask server{Style.RESET_ALL}")
    app.run(debug=True)