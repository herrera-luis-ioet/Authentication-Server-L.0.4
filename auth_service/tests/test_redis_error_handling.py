import pytest
import redis
import time
from datetime import datetime, timedelta, timezone
import jwt
from src.config import Config
from unittest.mock import Mock, patch

@pytest.fixture
def mock_redis_client(monkeypatch, auth_service):
    """Fixture to create a mock Redis client with controlled failure scenarios."""
    mock_client = Mock()
    monkeypatch.setattr(auth_service, "redis_client", mock_client)
    return mock_client

def test_redis_connection_timeout(mock_redis_client, auth_service):
    """Test handling of Redis connection timeout."""
    mock_redis_client.exists.side_effect = redis.TimeoutError("Connection timeout")
    
    test_token = auth_service._generate_token("testuser")
    result = auth_service.verify_token(test_token)
    
    assert "error" in result
    assert result["error"] == "Service temporarily unavailable"
    mock_redis_client.exists.assert_called_once()

def test_redis_service_unavailable(mock_redis_client, auth_service):
    """Test handling of Redis service being completely unavailable."""
    mock_redis_client.exists.side_effect = redis.ConnectionError("Could not connect to Redis")
    mock_redis_client.setex.side_effect = redis.ConnectionError("Could not connect to Redis")
    
    # Test token verification
    test_token = auth_service._generate_token("testuser")
    result = auth_service.verify_token(test_token)
    assert result["error"] == "Service temporarily unavailable"
    
    # Test token invalidation
    with pytest.raises(Exception) as exc_info:
        auth_service.invalidate_token(test_token)
    assert "Failed to invalidate token" in str(exc_info.value)

def test_redis_connection_lost_during_operation(mock_redis_client, auth_service):
    """Test handling of Redis connection lost during operation."""
    # Mock connection working initially then failing
    call_count = 0
    def side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count > 1:
            raise redis.ConnectionError("Connection lost during operation")
        return False
    
    mock_redis_client.exists.side_effect = side_effect
    
    # First call should succeed
    test_token = auth_service._generate_token("testuser")
    result = auth_service.verify_token(test_token)
    assert "error" not in result
    
    # Second call should fail with connection error
    result = auth_service.verify_token(test_token)
    assert result["error"] == "Service temporarily unavailable"

def test_redis_memory_limit_exceeded(mock_redis_client, auth_service):
    """Test handling of Redis memory limit exceeded error."""
    mock_redis_client.setex.side_effect = redis.ResponseError("OOM command not allowed when used memory > 'maxmemory'")
    
    test_token = auth_service._generate_token("testuser")
    with pytest.raises(Exception) as exc_info:
        auth_service.invalidate_token(test_token)
    assert "Failed to invalidate token" in str(exc_info.value)

def test_redis_cluster_failover(mock_redis_client, auth_service):
    """Test handling of Redis cluster failover scenario."""
    # Simulate cluster failover by having operations fail temporarily
    failover_complete = False
    def side_effect(*args, **kwargs):
        nonlocal failover_complete
        if not failover_complete:
            failover_complete = True
            raise redis.ConnectionError("Cluster failover in progress")
        return False
    
    mock_redis_client.exists.side_effect = side_effect
    
    # First attempt during failover
    test_token = auth_service._generate_token("testuser")
    result = auth_service.verify_token(test_token)
    assert result["error"] == "Service temporarily unavailable"
    
    # Second attempt after failover
    result = auth_service.verify_token(test_token)
    assert "error" not in result

def test_redis_error_during_token_refresh(mock_redis_client, auth_service):
    """Test handling of Redis errors during token refresh operation."""
    # Mock successful token verification but failed invalidation
    mock_redis_client.exists.return_value = False
    mock_redis_client.setex.side_effect = redis.ConnectionError("Connection lost")
    
    test_token = auth_service._generate_token("testuser")
    result = auth_service.refresh_token(test_token)
    
    assert "error" in result
    assert result["error"] == "Service temporarily unavailable"

def test_redis_error_recovery(mock_redis_client, auth_service):
    """Test system recovery after Redis errors."""
    # Simulate Redis service recovering after failures
    error_count = 0
    def side_effect(*args, **kwargs):
        nonlocal error_count
        if error_count < 2:
            error_count += 1
            raise redis.ConnectionError("Service temporarily down")
        return False
    
    mock_redis_client.exists.side_effect = side_effect
    
    test_token = auth_service._generate_token("testuser")
    
    # First two attempts fail
    for _ in range(2):
        result = auth_service.verify_token(test_token)
        assert result["error"] == "Service temporarily unavailable"
    
    # Third attempt succeeds after recovery
    result = auth_service.verify_token(test_token)
    assert "error" not in result

def test_redis_bulk_operations_error_handling(mock_redis_client, auth_service):
    """Test handling of errors during bulk operations."""
    # Generate multiple tokens
    tokens = [auth_service._generate_token(f"user{i}") for i in range(5)]
    
    # Simulate intermittent failures during bulk operations
    fail_count = 0
    def side_effect(*args, **kwargs):
        nonlocal fail_count
        fail_count += 1
        if fail_count % 2 == 0:  # Fail every second operation
            raise redis.ConnectionError("Intermittent connection error")
        return True
    
    mock_redis_client.setex.side_effect = side_effect
    
    # Attempt to invalidate all tokens
    failed_tokens = []
    for token in tokens:
        try:
            auth_service.invalidate_token(token)
        except Exception:
            failed_tokens.append(token)
    
    # Verify that some operations failed
    assert len(failed_tokens) > 0
    assert len(failed_tokens) < len(tokens)  # Not all operations should fail