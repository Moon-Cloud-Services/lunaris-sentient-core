import pytest
import numpy as np
from app.services.traffic_service import TrafficService

@pytest.fixture
def traffic_service():
    return TrafficService()

def test_traffic_analysis(traffic_service):
    # Generate mock data
    mock_data = np.random.rand(100, 10)
    
    # Train the model
    traffic_service.train_model(mock_data)
    
    # Test data
    test_data = np.random.rand(10, 10)
    
    result = traffic_service.analyze_traffic(test_data)
    assert 'anomalies' in result
    assert isinstance(result['anomalies'], list)
