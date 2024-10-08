from sklearn.preprocessing import StandardScaler
import pefile
import logging

logger = logging.getLogger(__name__)

def extract_features(filedata):
    """
    Extracts features from a malware file.
    """
    try:
        pe = pefile.PE(data=filedata)
        features = [
            len(pe.sections),
            pe.OPTIONAL_HEADER.SizeOfCode,
            pe.OPTIONAL_HEADER.SizeOfInitializedData,
            pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            pe.OPTIONAL_HEADER.BaseOfCode,
            pe.OPTIONAL_HEADER.ImageBase,
            pe.FILE_HEADER.NumberOfSymbols,
            pe.FILE_HEADER.TimeDateStamp,
            pe.OPTIONAL_HEADER.CheckSum
        ]
        return features
    except pefile.PEFormatError as e:
        logger.error(f"Error extracting features: {e}")
        return None

def preprocess_malware_data(features):
    """
    Scales the features using StandardScaler.
    """
    scaler = StandardScaler()
    return scaler.fit_transform(features)
