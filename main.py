from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from app.api.v1 import endpoints
from app.utils.encryption import Encryption
from app.utils.logger import setup_logger
from config.config import Config

app = Flask(__name__)
app.config.from_object(Config)

# Setup logging
logger = setup_logger()

# Setup rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

encryption = Encryption(app.config['SECRET_KEY'])

app.register_blueprint(endpoints.bp, url_prefix='/api/v1')

if __name__ == "__main__":
    app.run(debug=app.config['DEBUG'], host=app.config['HOST'], port=app.config['PORT'])
