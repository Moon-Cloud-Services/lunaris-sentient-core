import pandas as pd
import io
import logging
from sklearn.preprocessing import StandardScaler
from app.models.anomaly_detector import AnomalyDetector
from sklearn.exceptions import NotFittedError

class TrafficService:
    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.scaler = StandardScaler()
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def fit_scaler(self, processed_data):
        self.logger.info("Fitting the StandardScaler with data")
        self.scaler.fit(processed_data)
        self.logger.info("StandardScaler fitted successfully: mean_=%s, var_=%s", self.scaler.mean_, self.scaler.var_)

    def fit_and_scale(self, data):
        self.logger.info("Starting the adjustment and transformation of the data")
        processed_data = self.preprocess_data(data)
        self.logger.info("Data processed: %s", processed_data)
        self.fit_scaler(processed_data)
        return self.scaler.transform(processed_data)

    def analyze_traffic(self, data):
        self.logger.info("Starting Traffic Analysis")
        processed_data = self.preprocess_data(data)
        self.logger.info("Form of data processed: %s", processed_data.shape)
        
        try:
            scaled_data = self.scaler.transform(processed_data)
        except NotFittedError:
            self.logger.info("Untuned scaler, starting tuning")
            self.fit_scaler(processed_data)
            scaled_data = self.scaler.transform(processed_data)
        
        self.logger.info("Scaled data: %s", scaled_data)
        anomalies = self.anomaly_detector.detect(scaled_data)
        result = {"anomalies": anomalies.tolist()}
        self.logger.info("Result of the analysis: %s", result)
        return result

    def preprocess_data(self, data):
        self.logger.info("Starting Data Preprocessing")
        try:
            df = pd.read_csv(io.BytesIO(data))
            self.logger.info("Data read as CSV")
            return df.values
        except pd.errors.ParserError:
            self.logger.info("Error reading CSV, trying JSON")
            try:
                df = pd.read_json(io.BytesIO(data))
                self.logger.info("Data read as JSON")
                return df.values
            except ValueError:
                self.logger.error("Error reading the file, neither CSV nor JSON")
                raise ValueError("The provided file is neither a valid CSV nor JSON.")
