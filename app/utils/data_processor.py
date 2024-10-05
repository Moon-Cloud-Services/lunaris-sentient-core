import numpy as np
from sklearn.preprocessing import StandardScaler

def preprocess_traffic_data(data):
    # Convert to numpy array if not already
    data = np.array(data)
    
    # Normalize numerical features
    scaler = StandardScaler()
    normalized_data = scaler.fit_transform(data)
    
    return normalized_data

def preprocess_malware_data(data):
    # Convert to numpy array if not already
    data = np.array(data)
    
    # Normalize numerical features
    scaler = StandardScaler()
    normalized_data = scaler.fit_transform(data)
    
    return normalized_data