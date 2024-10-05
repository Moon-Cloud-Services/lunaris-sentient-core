## Lunaris Sentient Core

Lunaris Sentient Core is an advanced cybersecurity system that utilizes artificial intelligence for traffic anomaly detection and malware protection.

## Features

* Network traffic analysis using anomaly detection
* Malware detection using deep learning
* Secure communication with encryption

## Installation

**1. Clone the Repository:**

```bash
git clone https://github.com/Moon-Cloud-Services/lunaris-sentient-core.git
cd lunaris-sentient-core
```

**2. Install Dependencies:**

```bash
pip install -r requirements.txt
```

**3. Configure the Environment (Optional):**

You can configure the environment variables directly or use a `.env` file. The following are the environment variables and their default values:

* `DEBUG`: Set to `True` for debugging information (default: `False`)
* `HOST`: The host interface on which the application listens (default: `0.0.0.0`)
* `PORT`: The port on which the application listens (default: `5000`)
* `SECRET_KEY`: A secret key used for encryption (**required**)

**Example with environment variables:**

```bash
export DEBUG=False
export HOST=0.0.0.0
export PORT=5000
export SECRET_KEY=your-secret-key
```

**Example with a `.env` file (create a file named `.env` in the project root):**

```
DEBUG=False
HOST=0.0.0.0
PORT=5000
SECRET_KEY=your-secret-key
```

**4. Run the Application:**

```bash
python -m app.main
```

## Usage

### Traffic Analysis

To analyze traffic, make a POST request to `/analyze_traffic` with encrypted traffic data:

```python
import requests
from app.utils.encryption import Encryption

encryption = Encryption("your_secret_key_here")
traffic_data = [...]  # Your traffic data here
encrypted_data = encryption.encrypt_message(str(traffic_data))

response = requests.post('http://localhost:5000/analyze_traffic', json={'data': encrypted_data})
encrypted_result = response.json()['result']
result = encryption.decrypt_message(encrypted_result)
print(result)
```

### Malware Detection

To scan for malware, make a POST request to `/scan_malware` with encrypted file data:

```python
import requests
from app.utils.encryption import Encryption

encryption = Encryption("your_secret_key_here")
file_data = [...]  # Your file data here
encrypted_data = encryption.encrypt_message(str(file_data))

response = requests.post('http://localhost:5000/scan_malware', json={'data': encrypted_data})
encrypted_result = response.json()['result']
result = encryption.decrypt_message(encrypted_result)
print(result)
```

## Common Errors and Troubleshooting

**ModuleNotFoundError: No module named 'app'**

Ensure that you're running the script from the root directory of the project and that your PYTHONPATH is set correctly.

**ValueError: Fernet key must be 32 url-safe base64-encoded bytes**

Make sure you are initializing the encryption class with the correct key.

**TypeError: Encryption.init() missing 1 required positional argument: 'key'**

Ensure you pass the key when creating an instance of the Encryption class.

## Tests

Run the tests with:

```bash
pytest
```

## Deployment with Docker

**Build the Docker image:**

```bash
docker build -t lunaris-sentient-core .
```

**Run the container:**

```bash
docker run -p 5000:5000 -e SECRET_KEY=your-secret-key lunaris-sentient-core
```
