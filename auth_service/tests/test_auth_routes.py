import pytest
import json
import sys
import os
from unittest.mock import patch
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.app import app
from src.services.auth_service import AuthService
from src.utils.logging import log_auth_event

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture
def auth_service():
    return AuthService()

def test_register_success(client):
    """Test successful user registration"""
    response = client.post('/auth/register', 
                         json={'username': 'testuser', 'password': 'testpass'})
    assert response.status_code == 201
    assert b'User registered successfully' in response.data

def test_register_duplicate_user(client):
    """Test registration with existing username"""
    # First registration
    client.post('/auth/register', json={'username': 'testuser2', 'password': 'testpass'})
    # Duplicate registration
    response = client.post('/auth/register', 
                         json={'username': 'testuser2', 'password': 'testpass'})
    assert response.status_code == 409
    assert b'Username already exists' in response.data

def test_register_missing_data(client):
    """Test registration with missing data"""
    response = client.post('/auth/register', json={'username': 'testuser3'})
    assert response.status_code == 400
    assert b'Missing username or password' in response.data

def test_login_success(client):
    """Test successful login"""
    # Register user first
    client.post('/auth/register', json={'username': 'loginuser', 'password': 'testpass'})
    # Try to login
    response = client.post('/auth/login', 
                         json={'username': 'loginuser', 'password': 'testpass'})
    assert response.status_code == 200
    assert b'Login successful' in response.data
    assert 'token' in json.loads(response.data)

def test_login_invalid_credentials(client):
    """Test login with invalid credentials"""
    response = client.post('/auth/login', 
                         json={'username': 'nonexistent', 'password': 'wrongpass'})
    assert response.status_code == 401
    assert b'Invalid credentials' in response.data

def test_token_verification(client):
    """Test token verification"""
    # Register and login to get token
    client.post('/auth/register', json={'username': 'tokenuser', 'password': 'testpass'})
    login_response = client.post('/auth/login', 
                              json={'username': 'tokenuser', 'password': 'testpass'})
    token = json.loads(login_response.data)['token']
    
    # Verify token
    response = client.get('/auth/verify-token', 
                        headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert b'Token is valid' in response.data

def test_token_refresh(client):
    """Test token refresh"""
    # Register and login to get token
    client.post('/auth/register', json={'username': 'refreshuser', 'password': 'testpass'})
    login_response = client.post('/auth/login', 
                              json={'username': 'refreshuser', 'password': 'testpass'})
    token = json.loads(login_response.data)['token']
    
    # Refresh token
    response = client.post('/auth/refresh-token', 
                         headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert b'Token refreshed successfully' in response.data
    assert 'token' in json.loads(response.data)

def test_logout(client):
    """Test logout functionality"""
    # Register and login to get token
    client.post('/auth/register', json={'username': 'logoutuser', 'password': 'testpass'})
    login_response = client.post('/auth/login', 
                              json={'username': 'logoutuser', 'password': 'testpass'})
    token = json.loads(login_response.data)['token']
    
    # Logout
    response = client.post('/auth/logout', 
                         headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert b'Logged out successfully' in response.data
    
    # Verify token is invalidated
    verify_response = client.get('/auth/verify-token', 
                              headers={'Authorization': f'Bearer {token}'})
    assert verify_response.status_code == 401
    assert b'Token has been invalidated' in verify_response.data

def test_missing_token(client):
    """Test endpoints that require token without providing one"""
    response = client.get('/auth/verify-token')
    assert response.status_code == 401
    assert b'Token is missing' in response.data

def test_invalid_token_format(client):
    """Test endpoints with invalid token format"""
    response = client.get('/auth/verify-token', 
                        headers={'Authorization': 'InvalidToken'})
    assert response.status_code == 401

def test_auth_logging_registration(client):
    """Test logging during registration"""
    with patch('src.utils.logging.log_auth_event') as mock_log:
        response = client.post('/auth/register', 
                             json={'username': 'loguser', 'password': 'testpass'})
        
        # Verify logging was called with correct parameters
        mock_log.assert_called_with(
            event_type='user_registration',
            status='success' if response.status_code == 201 else 'failure',
            details={
                'status_code': response.status_code,
                'username': 'loguser'
            }
        )

def test_auth_logging_login(client):
    """Test logging during login"""
    # Register user first
    client.post('/auth/register', json={'username': 'loguser2', 'password': 'testpass'})
    
    with patch('src.utils.logging.log_auth_event') as mock_log:
        response = client.post('/auth/login', 
                             json={'username': 'loguser2', 'password': 'testpass'})
        
        # Verify logging was called with correct parameters
        mock_log.assert_called_with(
            event_type='user_login',
            status='success' if response.status_code == 200 else 'failure',
            details={
                'status_code': response.status_code,
                'username': 'loguser2'
            }
        )

def test_auth_logging_failed_login(client):
    """Test logging during failed login attempt"""
    with patch('src.utils.logging.log_auth_event') as mock_log:
        response = client.post('/auth/login', 
                             json={'username': 'nonexistent', 'password': 'wrongpass'})
        
        # Verify logging was called with correct parameters
        mock_log.assert_called_with(
            event_type='user_login',
            status='failure',
            details={
                'status_code': response.status_code,
                'username': 'nonexistent'
            }
        )

def test_auth_logging_logout(client):
    """Test logging during logout"""
    # Register and login to get token
    client.post('/auth/register', json={'username': 'logoutloguser', 'password': 'testpass'})
    login_response = client.post('/auth/login', 
                               json={'username': 'logoutloguser', 'password': 'testpass'})
    token = json.loads(login_response.data)['token']
    
    with patch('src.utils.logging.log_auth_event') as mock_log:
        response = client.post('/auth/logout', 
                             headers={'Authorization': f'Bearer {token}'})
        
        # Verify logging was called with correct parameters
        mock_log.assert_called_with(
            event_type='user_logout',
            status='success' if response.status_code == 200 else 'failure',
            details={
                'status_code': response.status_code,
                'username': None  # Username not in request body for logout
            }
        )

def test_auth_logging_token_refresh(client):
    """Test logging during token refresh"""
    # Register and login to get token
    client.post('/auth/register', json={'username': 'refreshloguser', 'password': 'testpass'})
    login_response = client.post('/auth/login', 
                               json={'username': 'refreshloguser', 'password': 'testpass'})
    token = json.loads(login_response.data)['token']
    
    with patch('src.utils.logging.log_auth_event') as mock_log:
        response = client.post('/auth/refresh-token', 
                             headers={'Authorization': f'Bearer {token}'})
        
        # Verify logging was called with correct parameters
        mock_log.assert_called_with(
            event_type='token_refresh',
            status='success' if response.status_code == 200 else 'failure',
            details={
                'status_code': response.status_code,
                'username': None  # Username not in request body for token refresh
            }
        )
