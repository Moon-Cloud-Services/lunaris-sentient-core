import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.feature_selection import VarianceThreshold
from sklearn.decomposition import PCA
from sklearn.metrics import classification_report, confusion_matrix
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping
import logging
from rich.logging import RichHandler
from rich.progress import track
import pefile
import hashlib

# Logging configuration
logging.basicConfig(level=logging.INFO, format="%(message)s", handlers=[RichHandler()])
logger = logging.getLogger("training")

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAINING_FILES_DIR = os.path.join(BASE_DIR, 'training_files')
MODEL_SAVE_DIR = os.path.join(BASE_DIR, 'model_trained')
MODEL_PATH = os.path.join(MODEL_SAVE_DIR, 'final_model.keras')

logger.info(f"TRAINING_FILES_DIR: {TRAINING_FILES_DIR}")
logger.info(f"MODEL_SAVE_DIR: {MODEL_SAVE_DIR}")

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
        logger.info(f"SHA256 file hash {file_path}: {file_hash}")

        return features
    except Exception as e:
        logger.error(f"Error extracting features from the file {file_path}: {e}")
        return None

def extract_features_from_log(file_path):
    try:

        with open(file_path, 'r') as f:
            log_data = f.read()
        features = {
            'log_length': len(log_data),
            'num_lines': log_data.count('\n')
        }
        return features
    except Exception as e:
        logger.error(f"Error extracting features from the file {file_path}: {e}")
        return None

def load_and_preprocess_data():
    benign_files = os.path.join(TRAINING_FILES_DIR, '0')
    malware_files = os.path.join(TRAINING_FILES_DIR, 'amas_reports')
    
    logger.info(f"benign_files: {benign_files}")
    logger.info(f"malware_files: {malware_files}")

    benign_data = []
    malware_data = []
    
    if not os.path.exists(benign_files):
        logger.error(f"The directory {benign_files} it does not exist.")
        return None, None, None, None
    if not os.path.exists(malware_files):
        logger.error(f"The directory {malware_files} it does not exist.")
        return None, None, None, None
    
    benign_files_list = os.listdir(benign_files)
    malware_files_list = os.listdir(malware_files)
    
    logger.info(f"Benign files found: {benign_files_list}")
    logger.info(f"Malware files found: {malware_files_list}")

    for file in track(benign_files_list, description="Processing benign files..."):
        logger.info(f"Processing benign file: {file}")
        if file.endswith('.exe'):
            file_path = os.path.join(benign_files, file)
            logger.info(f"Reading benign file: {file_path}")
            features = extract_features_from_exe(file_path)
            if features:
                benign_data.append(features)
                logger.info(f"Characteristics extracted for the benign file: {file}")
            else:
                logger.warning(f"Unextracted traits for the benign file: {file}")
    
    for file in track(malware_files_list, description="Processing malware files..."):
        logger.info(f"Processing malware file: {file}")
        if file.endswith('.vir.log'):
            file_path = os.path.join(malware_files, file)
            logger.info(f"Reading malware file: {file_path}")
            features = extract_features_from_log(file_path)
            if features:
                malware_data.append(features)
                logger.info(f"Characteristics extracted for the malware file: {file}")
            else:
                logger.warning(f"Unextracted characteristics for the malware file: {file}")

    benign_labels = [0] * len(benign_data)
    malware_labels = [1] * len(malware_data)
    
    data = benign_data + malware_data
    labels = benign_labels + malware_labels
    
    if not data:
        logger.error("No data was processed.")
        return None, None, None, None
    
    df = pd.DataFrame(data)
    df['label'] = labels
    
    if df.empty:
        logger.error("The DataFrame is empty after the data is combined.")
        return None, None, None, None
    
    X = df.drop('label', axis=1)
    y = df['label']
    
    if X.empty or y.empty:
        logger.error("The input data (X) or labels (y) are empty.")
        return None, None, None, None
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    return train_test_split(X_scaled, y, test_size=0.2, random_state=42)

def build_model(input_dim):
    model = Sequential()
    model.add(Dense(64, input_dim=input_dim, activation='relu'))
    model.add(Dropout(0.5))
    model.add(Dense(32, activation='relu'))
    model.add(Dropout(0.5))
    model.add(Dense(1, activation='sigmoid'))
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model

def train_model(X_train, X_test, y_train, y_test):
    model = build_model(X_train.shape[1])
    
    early_stopping = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)
    
    model.fit(X_train, y_train, validation_data=(X_test, y_test), epochs=50, batch_size=32, callbacks=[early_stopping])
    
    y_pred = (model.predict(X_test) > 0.5).astype("int32")
    
    logger.info("Classification Report:")
    logger.info(classification_report(y_test, y_pred))
    
    logger.info("Confusion Matrix:")
    logger.info(confusion_matrix(y_test, y_pred))
    
    model.save(MODEL_PATH)
    logger.info(f"Model saved in {MODEL_PATH}")

if __name__ == '__main__':
    X_train, X_test, y_train, y_test = load_and_preprocess_data()
    if X_train is not None and X_test is not None and y_train is not None and y_test is not None:
        train_model(X_train, X_test, y_train, y_test)
    else:
        logger.error("Error loading and pre-processing the data. Training will not start.")