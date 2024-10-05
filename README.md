# Lunaris Sentient Core

Lunaris Sentient Core is an advanced cybersecurity system that utilizes artificial intelligence for traffic anomaly detection and malware protection.

## Features

- Network traffic analysis using anomaly detection
- Malware detection using deep learning
- Secure communication with encryption

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/your-username/lunaris-sentient-core.git
   cd lunaris-sentient-core
   ```

2. Install the dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Configure the environment variables (or use a .env file):
   ```
   export DEBUG=False
   export HOST=0.0.0.0
   export PORT=5000
   export SECRET_KEY=your-secret-key
   ```

4. Run the application:
   ```
   python app/main.py
   ```

## Usage

### Traffic Analysis

To analyze traffic, make a POST request to `/analyze_traffic` with encrypted traffic data:

```python
import requests
from app.utils.encryption import Encryption

encryption = Encryption()
traffic_data = [...]  # Your traffic data here
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

encryption = Encryption()
file_data = [...]  # Your file data here
encrypted_data = encryption.encrypt_message(str(file_data))

response = requests.post('http://localhost:5000/scan_malware', json={'data': encrypted_data})
encrypted_result = response.json()['result']
result = encryption.decrypt_message(encrypted_result)
print(result)
```

## Tests

Run the tests with:

```
pytest
```

## Deployment with Docker

1. Build the Docker image:
   ```
   docker build -t lunaris-sentient-core .
   ```

2. Run the container:
   ```
   docker run -p 5000:5000 -e SECRET_KEY=your-secret-key lunaris-sentient-core
   ```
