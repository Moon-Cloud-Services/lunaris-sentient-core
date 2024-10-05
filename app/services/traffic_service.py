from app.models.anomaly_detector import AnomalyDetector
from app.utils.data_preprocessor import preprocess_traffic_data

class TrafficService:
    def __init__(self):
        self.anomaly_detector = AnomalyDetector()

    def train_model(self, training_data):
        preprocessed_data = preprocess_traffic_data(training_data)
        self.anomaly_detector.train(preprocessed_data)

    def analyze_traffic(self, data):
        preprocessed_data = preprocess_traffic_data(data)
        anomalies = self.anomaly_detector.detect(preprocessed_data)
        return {"anomalies": anomalies.tolist()}
