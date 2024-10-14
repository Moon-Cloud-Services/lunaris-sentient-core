import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.feature_selection import VarianceThreshold
from sklearn.decomposition import PCA
import pefile
import hashlib
from rich.progress import Progress, track
from rich.logging import RichHandler
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s", handlers=[RichHandler()])
logger = logging.getLogger("preprocessor")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAINING_FILES_DIR = os.path.join(BASE_DIR, 'training_files')
PROCESSED_DATA_DIR = os.path.join(BASE_DIR, 'processed_data')

logger.info(f"TRAINING_FILES_DIR: {TRAINING_FILES_DIR}")

def extract_features_from_exe(file_path):
    try:
        pe = pefile.PE(file_path)
        features = {
            'Machine': pe.FILE_HEADER.Machine,
            'NumberOfSections': pe.FILE_HEADER.NumberOfSections,
            'TimeDateStamp': pe.FILE_HEADER.TimeDateStamp,
            'PointerToSymbolTable': pe.FILE_HEADER.PointerToSymbolTable,
            'NumberOfSymbols': pe.FILE_HEADER.NumberOfSymbols,
            'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
            'Characteristics': pe.FILE_HEADER.Characteristics,
            'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
            'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
            'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
            'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
            'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
            'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
            'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
            'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
            'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
            'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
            'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'SizeOfStackCommit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
            'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
            'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
            'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
            'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        }
        
        for section in pe.sections:
            section_name = section.Name.decode().rstrip('\x00')
            features[f'{section_name}_VirtualSize'] = section.Misc_VirtualSize
            features[f'{section_name}_VirtualAddress'] = section.VirtualAddress
            features[f'{section_name}_SizeOfRawData'] = section.SizeOfRawData
            features[f'{section_name}_Characteristics'] = section.Characteristics

        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        features['SHA256'] = file_hash

        return features
    except Exception as e:
        logger.error(f"Error extracting features from the file {file_path}: {e}")
        return None

def extract_features_from_log(file_path):
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        features = {
            'FileSize': len(content),
            'ErrorCount': content.count('error'),
            'WarningCount': content.count('warning'),
            'CriticalCount': content.count('critical'),
            'APICallCount': content.count('API:'),
            'RegistryAccessCount': content.count('Registry:'),
            'FileAccessCount': content.count('File:'),
            'NetworkAccessCount': content.count('Network:'),
            'ProcessCreationCount': content.count('Process:'),
            'UniqueFunctionCalls': len(set(content.split())),
        }
        return features
    except Exception as e:
        logger.error(f"Error extracting features from the file{file_path}: {e}")
        return None

def preprocess_data():
    benign_files = os.path.join(TRAINING_FILES_DIR, '0')
    malware_files = os.path.join(TRAINING_FILES_DIR, 'amas_reports')
    
    logger.info(f"benign_files: {benign_files}")
    logger.info(f"malware_files: {malware_files}")

    benign_data = []
    malware_data = []
    
    benign_files_list = os.listdir(benign_files)
    malware_files_list = os.listdir(malware_files)
    
    logger.info(f"Benign files found: {benign_files_list}")
    logger.info(f"Malware files found: {malware_files_list}")

    for file in track(benign_files_list, description="Processing benign files..."):
        logger.info(f"Processing benign file: {file}")
        if file.endswith('.exe'):
            features = extract_features_from_exe(os.path.join(benign_files, file))
            if features:
                benign_data.append(features)
    
    for file in track(malware_files_list, description="Processing malware files..."):
        logger.info(f"Processing malware file: {file}")
        if file.endswith('.vir.log'):
            features = extract_features_from_log(os.path.join(malware_files, file))
            if features:
                malware_data.append(features)

    data = benign_data + malware_data
    labels = [0] * len(benign_data) + [1] * len(malware_data)
    
    df = pd.DataFrame(data)
    labels = np.array(labels)
    
    logger.info(f"Total samples: {len(df)}")
    logger.info(f"Benign Faces: {sum(labels == 0)}")
    logger.info(f"Malware Displays: {sum(labels == 1)}")
    
    return df, labels

def preprocess_data_pipeline(df, labels):
    logger.info("Starting pre-processing the data...")
    
    logger.info("Removing features with zero variance...")
    selector = VarianceThreshold()
    df_selected = selector.fit_transform(df)
    selected_features = df.columns[selector.get_support()].tolist()
    df = pd.DataFrame(df_selected, columns=selected_features)
    
    logger.info("Handling missing values...")
    imputer = SimpleImputer(strategy='mean')
    df_imputed = imputer.fit_transform(df)
    df = pd.DataFrame(df_imputed, columns=df.columns)
    
    logger.info("Normalizing the data...")
    scaler = StandardScaler()
    df_scaled = scaler.fit_transform(df)
    df = pd.DataFrame(df_scaled, columns=df.columns)
    
    logger.info("Applying PCA for dimensionality reduction...")
    pca = PCA(n_components=0.95)  
    df_pca = pca.fit_transform(df)
    
    logger.info(f"Original dimensions: {df.shape[1]}")
    logger.info(f"Dimensions after PCA: {df_pca.shape[1]}")
    
    return df_pca, labels

def save_processed_data(X, y):
    os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)
    np.save(os.path.join(PROCESSED_DATA_DIR, 'X.npy'), X)
    np.save(os.path.join(PROCESSED_DATA_DIR, 'y.npy'), y)
    logger.info(f"Processed data saved in {PROCESSED_DATA_DIR}")

def main():
    df, labels = preprocess_data()
    if df is not None and not df.empty:
        X, y = preprocess_data_pipeline(df, labels)
        save_processed_data(X, y)
    else:
        logger.error("Error processing the data. The preprocessing pipeline will not run.")

if __name__ == "__main__":
    main()