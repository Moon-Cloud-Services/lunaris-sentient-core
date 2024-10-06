# Lunaris Sentient Core

## About the Project

Lunaris is a powerful AI security tool designed to protect servers against cyberattacks and malware. It offers advanced features for analyzing files, detecting anomalies in network traffic, and continuously self-training, becoming smarter with each file it checks.

## Features

1. **Anomaly Detection**:
   - Monitors network traffic to identify suspicious or unusual behaviors.
   - Uses machine learning models to detect anomalies in real-time.

2. **Malware Detection**:
   - Continuous monitoring of files on the server.
   - Analyzes newly downloaded files to detect potential malware.
   - Self-trains based on newly verified files.

3. **Automatic Training**:
   - Continuously self-trains based on newly verified files.
   - Optional labels for auto-detection of previously submitted malware patterns.

4. **User Interface**:
   - User-friendly upload page for submitting files for training and scanning.
   - Supports multiple file types, including `.exe`, `.csv`, and `.json`.

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/Moon-Cloud-Services/lunaris-sentient-core.git
   cd lunaris-sentient-core

**2. Install Dependencies:**

```bash
pip install flask tensorflow scikit-learn pandas pefile
```

**3. Run the Application:**

```bash
python -m app.main
```

## Uso

**4. Interface Web Acesse a página de upload:**

```bash
Abra o navegador e vá para http://127.0.0.1:5000/upload_page
```

 ## Treinamento de Modelo
```bash
Arquivos Seguros: Envie arquivos seguros e defina o label como 0.
Arquivos Maliciosos: Envie arquivos maliciosos e defina o label como 1.
Labels Opcionais: Deixe o campo de labels vazio para auto-detecção.
```
## Escaneamento de Arquivos:

Envie um arquivo para escaneamento e veja os resultados.

# Treinamento do Modelo:

Utilize o script lunaris_cli.py para treinar o modelo com os arquivos renomeados:
```
python lunaris_cli.py caminho/para/seu/arquivo.exe
```
