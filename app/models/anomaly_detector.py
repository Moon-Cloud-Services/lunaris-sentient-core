import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class AnomalyDetector:
    def __init__(self, contamination=0.1):
        self.model = IsolationForest(contamination=contamination)
        self.scaler = StandardScaler()

    def train(self, data):
        scaled_data = self.scaler.fit_transform(data)
        self.model.fit(scaled_data)

    def detect(self, new_data):
        scaled_data = self.scaler.transform(new_data)
        predictions = self.model.predict(scaled_data)
        return np.where(predictions == -1)[0]  # Return indices of anomalies