from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1)

    def train(self, data):
        self.model.fit(data)

    def detect(self, data):
        # Make sure the template has been adjusted
        if not hasattr(self.model, 'estimators_'):
            self.train(data)
        return self.model.predict(data)
