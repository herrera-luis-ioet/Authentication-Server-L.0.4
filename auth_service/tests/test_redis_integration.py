import pytest
import time
from datetime import datetime, timedelta, timezone
import jwt
from src.config import Config

def test_redis_connection(redis_client):
    """Test Redis connection and basic operations."""
    # Test set and get operations
    redis_client.set("test_key", "test_value")
    assert redis_client.get("test_key") == "test_value"
    
    # Test key expiration
    redis_client.setex("expiring_key", 1, "expiring_value")
    assert redis_client.get("expiring_key") == "expiring_value"
    time.sleep(1.1)  # Wait for key to expire
    assert redis_client.get("expiring_key") is None

def test_token_blacklist_persistence(auth_service):
    """Test token blacklist persistence in Redis."""
    # Generate a test token
    test_token = auth_service._generate_token("testuser")
    
    # Invalidate the token
    auth_service.invalidate_token(test_token)
    
    # Verify token is blacklisted
    blacklist_key = f"{Config.TOKEN_BLACKLIST_PREFIX}{test_token}"
    assert auth_service.redis_client.exists(blacklist_key)
    
    # Verify token verification fails
    result = auth_service.verify_token(test_token)
    assert "error" in result
    assert result["error"] == "Token has been invalidated"

def test_automatic_token_expiration(auth_service):
    """Test automatic expiration of blacklisted tokens."""
    # Create a token that expires in 2 seconds
    payload = {
        "username": "testuser",
        "exp": datetime.now(timezone.utc) + timedelta(seconds=2),
        "iat": int(time.time())
    }
    test_token = jwt.encode(payload, auth_service.secret_key, algorithm="HS256")
    
    # Blacklist the token
    auth_service.invalidate_token(test_token)
    
    # Verify token is blacklisted
    blacklist_key = f"{Config.TOKEN_BLACKLIST_PREFIX}{test_token}"
    assert auth_service.redis_client.exists(blacklist_key)
    
    # Wait for token to expire
    time.sleep(2.1)
    
    # Verify blacklist entry has been automatically removed
    assert not auth_service.redis_client.exists(blacklist_key)

def test_redis_error_handling(auth_service, monkeypatch):
    """Test handling of Redis connection errors."""
    def mock_redis_error(*args, **kwargs):
        raise redis.RedisError("Connection failed")
    
    # Mock Redis operations to simulate errors
    monkeypatch.setattr(auth_service.redis_client, "exists", mock_redis_error)
    
    # Test token verification with Redis error
    test_token = auth_service._generate_token("testuser")
    result = auth_service.verify_token(test_token)
    assert "error" in result
    assert result["error"] == "Service temporarily unavailable"

def test_concurrent_token_operations(auth_service):
    """Test multiple concurrent token operations."""
    # Generate multiple tokens
    tokens = [auth_service._generate_token(f"user{i}") for i in range(5)]
    
    # Blacklist all tokens
    for token in tokens:
        auth_service.invalidate_token(token)
    
    # Verify all tokens are blacklisted
    for token in tokens:
        blacklist_key = f"{Config.TOKEN_BLACKLIST_PREFIX}{token}"
        assert auth_service.redis_client.exists(blacklist_key)
        
        result = auth_service.verify_token(token)
        assert "error" in result
        assert result["error"] == "Token has been invalidated"

def test_token_refresh_with_blacklist(auth_service):
    """Test token refresh functionality with blacklist integration."""
    # Generate initial token
    initial_token = auth_service._generate_token("testuser")
    
    # Refresh the token
    refresh_result = auth_service.refresh_token(initial_token)
    assert "token" in refresh_result
    new_token = refresh_result["token"]
    
    # Verify old token is blacklisted
    blacklist_key = f"{Config.TOKEN_BLACKLIST_PREFIX}{initial_token}"
    assert auth_service.redis_client.exists(blacklist_key)
    
    # Verify old token is invalid
    old_token_result = auth_service.verify_token(initial_token)
    assert "error" in old_token_result
    assert old_token_result["error"] == "Token has been invalidated"
    
    # Verify new token is valid
    new_token_result = auth_service.verify_token(new_token)
    assert "error" not in new_token_result
    assert new_token_result["user"]["username"] == "testuser"