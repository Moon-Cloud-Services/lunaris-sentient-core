import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask
from app.controllers import traffic_controller, malware_controller
from app.utils.encryption import Encryption

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'

encryption = Encryption(app.config['SECRET_KEY'])

@app.route("/")
def home():
    return {"message": "Lunaris Sentient Core is running"}

app.register_blueprint(traffic_controller.bp)
app.register_blueprint(malware_controller.bp)

if __name__ == "__main__":
    app.run(debug=True)
