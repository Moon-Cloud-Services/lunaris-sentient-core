import sys
import os
from flask import Flask
from app.controllers import malware_controller
from app.utils.encryption import Encryption
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['UPLOAD_FOLDER'] = 'uploads/'

encryption = Encryption(app.config['SECRET_KEY'])

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route("/")
def home():
    logger.info("Home endpoint accessed")
    return {"message": "Lunaris Sentient Core is running"}

app.register_blueprint(malware_controller.bp)

if __name__ == "__main__":
    app.run(debug=True)
