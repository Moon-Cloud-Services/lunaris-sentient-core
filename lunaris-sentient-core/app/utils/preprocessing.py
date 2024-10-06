import pefile
import hashlib
import logging
import os

logger = logging.getLogger(__name__)

def extract_features(file_path):
    logger.info("Starting to extract features from the file: %s", file_path)
    try:
        # Check the file size before processing it
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            raise pefile.PEFormatError('The file is empty')
        
        logger.info("File size: %d bytes", file_size)

        pe = pefile.PE(file_path)
        features = {
            'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'image_base': pe.OPTIONAL_HEADER.ImageBase,
            'checksum': pe.OPTIONAL_HEADER.CheckSum,
            # Add more features as needed
        }
        logger.info("Successfully extracted features: %s", features)
        return features
    except pefile.PEFormatError as e:
        logger.error("Error extracting features from file: %s", str(e))
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
