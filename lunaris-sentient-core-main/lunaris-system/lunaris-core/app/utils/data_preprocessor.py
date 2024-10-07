import numpy as np
from sklearn.preprocessing import StandardScaler

def preprocess_malware_data(data):
    # Convert to numpy array if not already
    data = np.array(data)
    
    # Check if the data has the correct shape
    if data.ndim == 1:
        data = data.reshape(1, -1)
    
    # Normalize numerical features
    scaler = StandardScaler()
    normalized_data = scaler.fit_transform(data)
    
    return normalized_data