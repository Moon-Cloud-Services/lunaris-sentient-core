from flask import Flask
from app.controllers import traffic_controller, malware_controller
from app.utils.encryption import Encryption
from config.config import Config

app = Flask(__name__)
app.config.from_object(Config)

encryption = Encryption(app.config['SECRET_KEY'])

app.register_blueprint(traffic_controller.bp)
app.register_blueprint(malware_controller.bp)

if __name__ == "__main__":
    app.run(debug=app.config['DEBUG'], host=app.config['HOST'], port=app.config['PORT'])