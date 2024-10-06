import argparse
from app.services.malware_service import MalwareService

def main():
    parser = argparse.ArgumentParser(description="Lunaris Antivirus CLI")
    parser.add_argument("file_path", help="Path to the file to be scanned")
    args = parser.parse_args()

    input_shape = (3,)  # Ajustar conforme necessário
    malware_service = MalwareService(input_shape)

    with open(args.file_path, 'rb') as file:
        file_content = file.read()

    result = malware_service.scan_malware(file_content)
    print("Resultado do Escaneamento:", result)

if __name__ == "__main__":
    main()
