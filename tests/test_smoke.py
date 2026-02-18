"""
Smoke tests - Basic sanity checks that don't require GPU/Kafka
"""
import pytest
import sys


def test_python_version():
    """Test Python version is 3.10+"""
    assert sys.version_info >= (3, 10), "Python 3.10+ required"


def test_required_imports():
    """Test that required packages can be imported"""
    try:
        import numpy
        assert hasattr(numpy, '__version__')
    except ImportError:
        pytest.skip("NumPy not installed")
    
    try:
        import pandas
        assert hasattr(pandas, '__version__')
    except ImportError:
        pytest.skip("Pandas not installed")
    
    try:
        import sklearn
        assert hasattr(sklearn, '__version__')
    except ImportError:
        pytest.skip("scikit-learn not installed")


@pytest.mark.skipif(
    'torch' not in sys.modules,
    reason="PyTorch not installed"
)
def test_pytorch_import():
    """Test PyTorch imports correctly"""
    import torch
    assert hasattr(torch, '__version__')


@pytest.mark.skipif(
    'confluent_kafka' not in sys.modules,
    reason="confluent-kafka not installed"
)
def test_kafka_import():
    """Test Kafka client imports correctly"""
    from confluent_kafka import Consumer, Producer
    assert Consumer is not None
    assert Producer is not None


def test_basic_numpy_operations():
    """Test basic NumPy operations work"""
    import numpy as np
    
    arr = np.array([1, 2, 3, 4, 5])
    assert arr.mean() == 3.0
    assert arr.std() > 0
    
    # Test NaN handling
    arr_with_nan = np.array([1, 2, np.nan, 4, 5])
    clean = arr_with_nan[np.isfinite(arr_with_nan)]
    assert len(clean) == 4


def test_feature_sanitization_logic():
    """Test basic sanitization logic without imports"""
    
    def safe_float(val, default=0.0):
        if val is None:
            return default
        try:
            return float(val)
        except (ValueError, TypeError):
            return default
    
    # Test None handling
    assert safe_float(None) == 0.0
    assert safe_float(None, -1.0) == -1.0
    
    # Test valid values
    assert safe_float(3.14) == 3.14
    assert safe_float("2.5") == 2.5
    assert safe_float(10) == 10.0
    
    # Test invalid values
    assert safe_float("invalid") == 0.0
    assert safe_float([1, 2, 3]) == 0.0


def test_anomaly_scoring_logic():
    """Test anomaly scoring logic without dependencies"""
    
    def compute_combined_score(individual, peer, w_ind=0.6, w_peer=0.4):
        return w_ind * individual + w_peer * peer
    
    def is_anomaly(individual, peer, combined):
        return (
            combined > 0.7 or
            (individual > 0.8 and peer > 0.5) or
            (individual > 0.5 and peer > 0.8)
        )
    
    # Test case 1: High combined
    ind, peer = 0.6, 0.8
    combined = compute_combined_score(ind, peer)
    assert combined > 0.7
    assert is_anomaly(ind, peer, combined) == True
    
    # Test case 2: High individual + moderate peer
    ind, peer = 0.85, 0.6
    combined = compute_combined_score(ind, peer)
    assert is_anomaly(ind, peer, combined) == True
    
    # Test case 3: Both low
    ind, peer = 0.3, 0.4
    combined = compute_combined_score(ind, peer)
    assert is_anomaly(ind, peer, combined) == False


def test_z_score_calculation():
    """Test Z-score calculation for peer comparison"""
    
    def calculate_z_score(value, mean, std):
        if std < 1e-6:
            return 0.0 if abs(value - mean) < 1e-6 else 1.0
        return abs((value - mean) / std)
    
    # Normal case
    assert calculate_z_score(110, 100, 10) == 1.0  # 1 std dev away
    assert calculate_z_score(130, 100, 10) == 3.0  # 3 std devs away
    
    # Constant feature (std = 0)
    assert calculate_z_score(100, 100, 0) == 0.0  # Same value
    assert calculate_z_score(110, 100, 0) == 1.0  # Different value
    
    # Edge case: very small std
    assert calculate_z_score(100.001, 100, 1e-10) == 1.0


def test_entity_limiting_logic():
    """Test entity limiting prevents memory exhaustion"""
    
    max_entities = 1000
    entity_count = 0
    min_messages = 10
    
    entity_messages = {
        'new_entity': 5,
        'active_entity': 50
    }
    
    # Should NOT accept new entity with too few messages
    if entity_count >= max_entities:
        if entity_messages['new_entity'] < min_messages:
            accept_new = False
        else:
            accept_new = True
    else:
        accept_new = True
    
    assert accept_new == True  # Under limit
    
    # Simulate at max capacity
    entity_count = 1000
    if entity_count >= max_entities:
        accept_new = entity_messages['new_entity'] >= min_messages
    
    assert accept_new == False  # New entity has only 5 messages