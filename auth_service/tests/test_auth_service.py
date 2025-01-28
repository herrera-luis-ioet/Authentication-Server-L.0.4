import pytest
import jwt
from datetime import datetime, timedelta, timezone
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.services.auth_service import AuthService
from werkzeug.security import check_password_hash

@pytest.fixture
def auth_service():
    return AuthService()

def test_register_user_success(auth_service):
    """Test successful user registration"""
    result = auth_service.register_user('testuser', 'password123')
    assert 'message' in result
    assert result['message'] == 'User registered successfully'
    assert 'testuser' in auth_service.users
    assert check_password_hash(auth_service.users['testuser']['password'], 'password123')

def test_register_duplicate_user(auth_service):
    """Test registration with duplicate username"""
    auth_service.register_user('testuser', 'password123')
    result = auth_service.register_user('testuser', 'newpassword')
    assert 'error' in result
    assert result['error'] == 'Username already exists'

def test_authenticate_user_success(auth_service):
    """Test successful user authentication"""
    auth_service.register_user('authuser', 'password123')
    result = auth_service.authenticate_user('authuser', 'password123')
    assert 'token' in result
    # Verify token structure
    token = result['token']
    payload = jwt.decode(token, auth_service.secret_key, algorithms=['HS256'])
    assert 'username' in payload
    assert payload['username'] == 'authuser'
    assert 'exp' in payload

def test_authenticate_user_invalid_credentials(auth_service):
    """Test authentication with invalid credentials"""
    auth_service.register_user('authuser', 'password123')
    result = auth_service.authenticate_user('authuser', 'wrongpassword')
    assert 'error' in result
    assert result['error'] == 'Invalid credentials'

def test_verify_token_success(auth_service):
    """Test successful token verification"""
    auth_service.register_user('tokenuser', 'password123')
    token = auth_service.authenticate_user('tokenuser', 'password123')['token']
    result = auth_service.verify_token(token)
    assert 'user' in result
    assert result['user']['username'] == 'tokenuser'

def test_verify_token_expired(auth_service):
    """Test verification of expired token"""
    # Create an expired token
    payload = {
        'username': 'expireduser',
        'exp': datetime.now(timezone.utc) - timedelta(hours=1)
    }
    expired_token = jwt.encode(payload, auth_service.secret_key, algorithm='HS256')
    result = auth_service.verify_token(expired_token)
    assert 'error' in result
    assert result['error'] == 'Token has expired'

def test_verify_token_invalid(auth_service):
    """Test verification of invalid token"""
    result = auth_service.verify_token('invalid.token.here')
    assert 'error' in result
    assert result['error'] == 'Invalid token'

def test_verify_token_blacklisted(auth_service):
    """Test verification of blacklisted token"""
    auth_service.register_user('blacklistuser', 'password123')
    token = auth_service.authenticate_user('blacklistuser', 'password123')['token']
    auth_service.invalidate_token(token)
    result = auth_service.verify_token(token)
    assert 'error' in result
    assert result['error'] == 'Token has been invalidated'

def test_refresh_token_success(auth_service):
    """Test successful token refresh"""
    auth_service.register_user('refreshuser', 'password123')
    old_token = auth_service.authenticate_user('refreshuser', 'password123')['token']
    # Add a small delay to ensure different iat values
    import time
    time.sleep(0.1)
    result = auth_service.refresh_token(old_token)
    assert 'token' in result
    assert result['token'] != old_token
    # Verify old token is blacklisted
    assert old_token in auth_service.blacklisted_tokens

def test_refresh_token_invalid(auth_service):
    """Test refresh with invalid token"""
    result = auth_service.refresh_token('invalid.token.here')
    assert 'error' in result
    assert result['error'] == 'Invalid token'

def test_invalidate_token(auth_service):
    """Test token invalidation"""
    auth_service.register_user('invalidateuser', 'password123')
    token = auth_service.authenticate_user('invalidateuser', 'password123')['token']
    auth_service.invalidate_token(token)
    assert token in auth_service.blacklisted_tokens
    # Verify token can't be used anymore
    result = auth_service.verify_token(token)
    assert 'error' in result
    assert result['error'] == 'Token has been invalidated'

def test_generate_token_expiration(auth_service):
    """Test token expiration time"""
    auth_service.register_user('expireuser', 'password123')
    token = auth_service._generate_token('expireuser')
    payload = jwt.decode(token, auth_service.secret_key, algorithms=['HS256'])
    exp_time = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
    # Token should expire in 1 hour
    assert (exp_time - datetime.now(timezone.utc)).total_seconds() < 3600
    assert (exp_time - datetime.now(timezone.utc)).total_seconds() > 3500

def test_verify_token_nonexistent_user(auth_service):
    """Test verification of token with non-existent user"""
    payload = {
        'username': 'nonexistentuser',
        'exp': datetime.now(timezone.utc) + timedelta(hours=1)
    }
    token = jwt.encode(payload, auth_service.secret_key, algorithm='HS256')
    result = auth_service.verify_token(token)
    assert 'error' in result
    assert result['error'] == 'User not found'

def test_refresh_token_blacklisted(auth_service):
    """Test refresh with blacklisted token"""
    auth_service.register_user('blacklistrefresh', 'password123')
    token = auth_service.authenticate_user('blacklistrefresh', 'password123')['token']
    auth_service.invalidate_token(token)
    result = auth_service.refresh_token(token)
    assert 'error' in result
    assert result['error'] == 'Token has been invalidated'

def test_multiple_token_invalidation(auth_service):
    """Test invalidating multiple tokens for the same user"""
    auth_service.register_user('multitoken', 'password123')
    token1 = auth_service.authenticate_user('multitoken', 'password123')['token']
    token2 = auth_service.authenticate_user('multitoken', 'password123')['token']
    
    # Invalidate both tokens
    auth_service.invalidate_token(token1)
    auth_service.invalidate_token(token2)
    
    # Verify both tokens are invalid
    assert token1 in auth_service.blacklisted_tokens
    assert token2 in auth_service.blacklisted_tokens
    assert auth_service.verify_token(token1)['error'] == 'Token has been invalidated'
    assert auth_service.verify_token(token2)['error'] == 'Token has been invalidated'

def test_token_unique_per_generation(auth_service):
    """Test that each generated token is unique"""
    auth_service.register_user('uniquetoken', 'password123')
    token1 = auth_service._generate_token('uniquetoken')
    token2 = auth_service._generate_token('uniquetoken')
    assert token1 != token2
    
    # Verify both tokens are valid and have different JTIs
    payload1 = jwt.decode(token1, auth_service.secret_key, algorithms=['HS256'])
    payload2 = jwt.decode(token2, auth_service.secret_key, algorithms=['HS256'])
    assert payload1['jti'] != payload2['jti']
    assert isinstance(payload1['iat'], int)
    assert isinstance(payload2['iat'], int)
