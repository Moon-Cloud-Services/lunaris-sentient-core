import pefile
import hashlib
import logging
import os

logger = logging.getLogger(__name__)

def extract_features(file_path):
    logger.info("Iniciando extração de features do arquivo: %s", file_path)
    try:
        # Verifique o tamanho do arquivo antes de processá-lo
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            raise pefile.PEFormatError('O arquivo está vazio')
        
        logger.info("Tamanho do arquivo: %d bytes", file_size)

        pe = pefile.PE(file_path)
        features = {
            'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'image_base': pe.OPTIONAL_HEADER.ImageBase,
            'checksum': pe.OPTIONAL_HEADER.CheckSum,
            # Adicione mais features conforme necessário
        }
        logger.info("Features extraídas com sucesso: %s", features)
        return features
    except pefile.PEFormatError as e:
        logger.error("Erro ao extrair features do arquivo: %s", str(e))
        raise

def hash_file(file_path):
    BUF_SIZE = 65536
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()
