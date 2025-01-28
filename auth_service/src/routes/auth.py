from flask import Blueprint, request, jsonify
from src.services.auth_service import AuthService
from http import HTTPStatus
from functools import wraps
from src.utils.logging import audit_log_decorator, log_auth_event
from src.utils.rate_limit import rate_limit

auth_bp = Blueprint('auth', __name__)
auth_service = AuthService()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), HTTPStatus.UNAUTHORIZED
            
        try:
            token = token.split('Bearer ')[1]
            auth_service.verify_token(token)
        except Exception as e:
            return jsonify({'error': str(e)}), HTTPStatus.UNAUTHORIZED
            
        return f(*args, **kwargs)
    return decorated

# PUBLIC_INTERFACE
@auth_bp.route('/register', methods=['POST'])
@rate_limit(endpoint_name='register')  # Use config-based rate limiting
@audit_log_decorator('user_registration')
def register():
    """
    Register a new user.
    
    Expected JSON payload:
    {
        "username": "string",
        "password": "string"
    }
    
    Returns:
    - 201: User created successfully
    - 400: Invalid request data
    - 409: Username already exists
    """
    try:
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Missing username or password'}), HTTPStatus.BAD_REQUEST
            
        result = auth_service.register_user(data['username'], data['password'])
        
        if result.get('error'):
            return jsonify({'error': result['error']}), HTTPStatus.CONFLICT
            
        return jsonify({'message': 'User registered successfully'}), HTTPStatus.CREATED
        
    except Exception as e:
        return jsonify({'error': str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

# PUBLIC_INTERFACE
@auth_bp.route('/logout', methods=['POST'])
@token_required
@rate_limit(endpoint_name='logout', user_based=True)  # Add user-based rate limiting
@audit_log_decorator('user_logout')
def logout():
    """
    Invalidate the current user's token.
    
    Required header:
    Authorization: Bearer <token>
    
    Returns:
    - 200: Logout successful
    - 401: Invalid or missing token
    """
    try:
        token = request.headers.get('Authorization').split('Bearer ')[1]
        auth_service.invalidate_token(token)
        return jsonify({'message': 'Logged out successfully'}), HTTPStatus.OK
    except Exception as e:
        return jsonify({'error': str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

# PUBLIC_INTERFACE
@auth_bp.route('/refresh-token', methods=['POST'])
@token_required
@rate_limit(endpoint_name='refresh_token', user_based=True)  # Add user-based rate limiting
@audit_log_decorator('token_refresh')
def refresh_token():
    """
    Generate a new token using the current valid token.
    
    Required header:
    Authorization: Bearer <token>
    
    Returns:
    - 200: New token generated successfully
    - 401: Invalid or missing token
    """
    try:
        current_token = request.headers.get('Authorization').split('Bearer ')[1]
        result = auth_service.refresh_token(current_token)
        
        if result.get('error'):
            return jsonify({'error': result['error']}), HTTPStatus.UNAUTHORIZED
            
        return jsonify({
            'message': 'Token refreshed successfully',
            'token': result['token']
        }), HTTPStatus.OK
    except Exception as e:
        return jsonify({'error': str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

# PUBLIC_INTERFACE
@auth_bp.route('/verify-token', methods=['GET'])
@token_required
@rate_limit(endpoint_name='verify_token', user_based=True)  # Add user-based rate limiting
@audit_log_decorator('token_verification')
def verify_token():
    """
    Verify if the provided token is valid.
    
    Required header:
    Authorization: Bearer <token>
    
    Returns:
    - 200: Token is valid
    - 401: Invalid or missing token
    """
    try:
        token = request.headers.get('Authorization').split('Bearer ')[1]
        result = auth_service.verify_token(token)
        
        if result.get('error'):
            return jsonify({'error': result['error']}), HTTPStatus.UNAUTHORIZED
            
        return jsonify({
            'message': 'Token is valid',
            'user': result.get('user')
        }), HTTPStatus.OK
    except Exception as e:
        return jsonify({'error': str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

# PUBLIC_INTERFACE
@auth_bp.route('/login', methods=['POST'])
@rate_limit(endpoint_name='login')  # Use config-based rate limiting
@audit_log_decorator('user_login')
def login():
    """
    Authenticate a user and return a JWT token.
    
    Expected JSON payload:
    {
        "username": "string",
        "password": "string"
    }
    
    Returns:
    - 200: Login successful, returns JWT token
    - 400: Invalid request data
    - 401: Invalid credentials
    """
    try:
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Missing username or password'}), HTTPStatus.BAD_REQUEST
            
        result = auth_service.authenticate_user(data['username'], data['password'])
        
        if result.get('error'):
            return jsonify({'error': result['error']}), HTTPStatus.UNAUTHORIZED
            
        return jsonify({
            'message': 'Login successful',
            'token': result['token']
        }), HTTPStatus.OK
        
    except Exception as e:
        return jsonify({'error': str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR
