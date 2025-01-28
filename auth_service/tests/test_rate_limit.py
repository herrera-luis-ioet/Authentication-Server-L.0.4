import time
import pytest
import fakeredis
import redis
from flask import Flask, jsonify, g
from http import HTTPStatus
from src.utils.rate_limit import rate_limit, redis_client, RateLimiter
from src.config import Config

@pytest.fixture
def test_app():
    app = Flask(__name__)
    app.config['TESTING'] = True
    
    # Configure test-specific rate limits
    Config.RATE_LIMITS.update({
        'test': {
            'requests': 2,
            'window': 5
        },
        'test-custom': {
            'requests': 5,
            'window': 10
        },
        'test-user': {
            'requests': 3,
            'window': 5
        },
        'test-combined': {
            'requests': 3,
            'window': 5
        },
        'test-burst': {
            'requests': 3,
            'window': 5
        }
    })
    
    # Configure rate limiting
    Config.RATE_LIMIT_ENABLED = True
    Config.IP_RATE_LIMIT['enabled'] = False  # Disable IP-based rate limiting for most tests
    Config.USER_RATE_LIMIT['enabled'] = False  # Disable user-based rate limiting for most tests
    Config.BURST_HANDLING['enabled'] = True
    
    # Test endpoint with rate limiting
    @app.route('/test')
    @rate_limit(endpoint_name='test')
    def test_endpoint():
        return jsonify({'message': 'success'})
    
    # Test endpoint with different rate limit configuration
    @app.route('/test-custom')
    @rate_limit(endpoint_name='test-custom')
    def test_custom_endpoint():
        return jsonify({'message': 'success'})
    
    # Test endpoint with user-based rate limiting
    @app.route('/test-user')
    @rate_limit(endpoint_name='test-user', user_based=True)
    def test_user_endpoint():
        return jsonify({'message': 'success'})
    
    # Test endpoint with both IP and user-based rate limiting
    @app.route('/test-combined')
    @rate_limit(endpoint_name='test-combined', user_based=True)
    def test_combined_endpoint():
        return jsonify({'message': 'success'})
    
    # Test endpoint for burst handling
    @app.route('/test-burst')
    @rate_limit(endpoint_name='test-burst')
    def test_burst_endpoint():
        return jsonify({'message': 'success'})
    
    return app

@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    """Replace Redis client with fakeredis and reset between tests"""
    fake_client = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr('src.utils.rate_limit.redis_client', fake_client)
    yield fake_client
    fake_client.flushall()

@pytest.fixture
def authenticated_user():
    """Simulate an authenticated user"""
    return {'user_id': 'test_user_123'}

@pytest.fixture
def mock_user_context(authenticated_user, test_app):
    """Set up user context for testing"""
    ctx = test_app.app_context()
    ctx.push()
    g.user_id = authenticated_user['user_id']
    yield
    ctx.pop()

def test_rate_limit_under_limit(test_app, fake_redis):
    """Test requests under rate limit are allowed"""
    with test_app.test_client() as client:
        # First request
        response = client.get('/test')
        assert response.status_code == HTTPStatus.OK
        assert response.json == {'message': 'success'}
        
        # Second request
        response = client.get('/test')
        assert response.status_code == HTTPStatus.OK
        assert response.json == {'message': 'success'}

def test_rate_limit_exceeded(test_app, fake_redis):
    """Test rate limit enforcement"""
    with test_app.test_client() as client:
        # Make requests up to the limit
        for _ in range(2):
            response = client.get('/test')
            assert response.status_code == HTTPStatus.OK
        
        # Request exceeding the limit
        response = client.get('/test')
        assert response.status_code == HTTPStatus.TOO_MANY_REQUESTS
        assert 'error' in response.json
        assert 'retry_after' in response.json
        assert response.json['error'] == 'Rate limit exceeded for this endpoint'

def test_rate_limit_window_reset(test_app, fake_redis):
    """Test rate limit reset after window expiration"""
    with test_app.test_client() as client:
        # Make requests up to the limit
        for _ in range(2):
            response = client.get('/test')
            assert response.status_code == HTTPStatus.OK
        
        # Wait for the window to expire
        time.sleep(5)
        
        # Should be able to make requests again
        response = client.get('/test')
        assert response.status_code == HTTPStatus.OK

def test_different_endpoints_separate_limits(test_app, fake_redis):
    """Test that different endpoints have separate rate limits"""
    with test_app.test_client() as client:
        # Exhaust limit for first endpoint
        for _ in range(2):
            response = client.get('/test')
            assert response.status_code == HTTPStatus.OK
        
        # Should still be able to access second endpoint
        response = client.get('/test-custom')
        assert response.status_code == HTTPStatus.OK

def test_different_clients_separate_limits(test_app, fake_redis):
    """Test that different clients have separate rate limits"""
    # Disable endpoint-specific rate limiting by setting high limits
    Config.RATE_LIMITS['test']['requests'] = 1000
    Config.RATE_LIMITS['test']['window'] = 3600
    
    # Enable IP-based rate limiting with low limits
    Config.IP_RATE_LIMIT['enabled'] = True
    Config.IP_RATE_LIMIT['requests'] = 2
    Config.IP_RATE_LIMIT['window'] = 5
    
    with test_app.test_client() as client1:
        with test_app.test_client() as client2:
            # Set different IP addresses for clients
            client1.environ_base['REMOTE_ADDR'] = '1.1.1.1'
            client2.environ_base['REMOTE_ADDR'] = '2.2.2.2'
            
            # Exhaust limit for first client
            for _ in range(2):
                response = client1.get('/test')
                assert response.status_code == HTTPStatus.OK
            
            # First client should be rate limited
            response = client1.get('/test')
            assert response.status_code == HTTPStatus.TOO_MANY_REQUESTS
            
            # Second client should still be able to make requests
            response = client2.get('/test')
            assert response.status_code == HTTPStatus.OK

def test_redis_error_handling(test_app, monkeypatch):
    """Test graceful handling of Redis errors"""
    def mock_zadd(*args, **kwargs):
        raise redis.RedisError("Test Redis error")
    
    with test_app.test_client() as client:
        # Mock Redis error
        fake_client = fakeredis.FakeRedis(decode_responses=True)
        monkeypatch.setattr(fake_client, 'zadd', mock_zadd)
        monkeypatch.setattr('src.utils.rate_limit.redis_client', fake_client)
        
        # Request should still succeed when Redis fails
        response = client.get('/test')
        assert response.status_code == HTTPStatus.OK

def test_sliding_window_accuracy(test_app, fake_redis):
    """Test sliding window algorithm accuracy"""
    with test_app.test_client() as client:
        # Make initial request
        response = client.get('/test-custom')
        assert response.status_code == HTTPStatus.OK
        
        # Wait for half the window
        time.sleep(5)
        
        # Make more requests
        for _ in range(4):
            response = client.get('/test-custom')
            assert response.status_code == HTTPStatus.OK
        
        # Next request should be rate limited
        response = client.get('/test-custom')
        assert response.status_code == HTTPStatus.TOO_MANY_REQUESTS

def test_rate_limit_headers(test_app, fake_redis):
    """Test rate limit response headers"""
    with test_app.test_client() as client:
        # Make requests up to the limit
        for _ in range(2):
            response = client.get('/test')
            assert response.status_code == HTTPStatus.OK
            assert 'X-RateLimit-Limit' in response.headers
            assert 'X-RateLimit-Remaining' in response.headers
            assert 'X-RateLimit-Reset' in response.headers
        
        # Request exceeding the limit
        response = client.get('/test')
        assert response.status_code == HTTPStatus.TOO_MANY_REQUESTS
        assert 'retry_after' in response.json
        retry_after = response.json['retry_after']
        assert isinstance(retry_after, (int, float))
        assert retry_after > 0

def test_ip_based_rate_limiting(test_app, fake_redis):
    """Test IP-based rate limiting"""
    # Configure rate limits
    Config.RATE_LIMITS.update({
        'test': {
            'requests': 10,  # High limit to avoid endpoint-specific rate limiting
            'window': 60
        }
    })
    
    Config.IP_RATE_LIMIT['enabled'] = True
    Config.IP_RATE_LIMIT['requests'] = 3
    Config.IP_RATE_LIMIT['window'] = 5
    Config.USER_RATE_LIMIT['enabled'] = False  # Disable user-based rate limiting
    
    # Create a new app for IP-based rate limiting test
    app = Flask(__name__)
    app.config['TESTING'] = True
    
    @app.route('/test')
    @rate_limit(endpoint_name='test')
    def test_endpoint():
        return jsonify({'message': 'success'})
    
    # Reset Redis before test
    fake_redis.flushall()
    
    with app.test_client() as client:
        client.environ_base['REMOTE_ADDR'] = '192.168.1.1'
        
        # Make requests up to IP limit
        for i in range(Config.IP_RATE_LIMIT['requests']):
            response = client.get('/test')
            assert response.status_code == HTTPStatus.OK, f"Request {i+1} failed with status {response.status_code}"
        
        # Next request should be rate limited
        response = client.get('/test')
        assert response.status_code == HTTPStatus.TOO_MANY_REQUESTS
        assert response.json['error'] == 'IP-based rate limit exceeded'

def test_user_based_rate_limiting(test_app, fake_redis):
    """Test user-based rate limiting"""
    # Configure rate limits
    Config.RATE_LIMITS.update({
        'test-user': {
            'requests': 10,  # High limit to avoid endpoint-specific rate limiting
            'window': 60
        }
    })
    
    Config.USER_RATE_LIMIT['enabled'] = True
    Config.USER_RATE_LIMIT['requests'] = 3
    Config.USER_RATE_LIMIT['window'] = 5
    Config.IP_RATE_LIMIT['enabled'] = False  # Disable IP-based rate limiting
    
    # Create a new app for user-based rate limiting test
    app = Flask(__name__)
    app.config['TESTING'] = True
    
    @app.route('/test-user')
    @rate_limit(endpoint_name='test-user', user_based=True)
    def test_user_endpoint():
        return jsonify({'message': 'success'})
    
    # Reset Redis before test
    fake_redis.flushall()
    
    with app.test_client() as client:
        with app.app_context():
            g.user_id = 'test_user_123'
            # Make requests up to user limit
            for i in range(Config.USER_RATE_LIMIT['requests']):
                response = client.get('/test-user')
                assert response.status_code == HTTPStatus.OK, f"Request {i+1} failed with status {response.status_code}"
            
            # Next request should be rate limited
            response = client.get('/test-user')
            assert response.status_code == HTTPStatus.TOO_MANY_REQUESTS
            assert response.json['error'] == 'User-based rate limit exceeded'

def test_burst_handling(test_app, fake_redis):
    """Test burst handling functionality"""
    Config.BURST_HANDLING['enabled'] = True
    Config.BURST_HANDLING['max_burst'] = 3
    Config.BURST_HANDLING['burst_window'] = 2
    
    with test_app.test_client() as client:
        # Make burst requests
        start_time = time.time()
        for _ in range(Config.BURST_HANDLING['max_burst']):
            response = client.get('/test-burst')
            assert response.status_code == HTTPStatus.OK
        
        # Next request should use longer window
        response = client.get('/test-burst')
        assert response.status_code == HTTPStatus.TOO_MANY_REQUESTS
        assert time.time() - start_time < Config.BURST_HANDLING['burst_window']

def test_concurrent_request_handling(test_app, fake_redis):
    """Test handling of concurrent requests"""
    import threading
    import queue
    
    results = queue.Queue()
    num_requests = 5
    
    def make_request():
        with test_app.test_client() as client:
            response = client.get('/test')
            results.put(response.status_code)
    
    threads = []
    for _ in range(num_requests):
        thread = threading.Thread(target=make_request)
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    # Check results
    success_count = 0
    while not results.empty():
        if results.get() == HTTPStatus.OK:
            success_count += 1
    
    assert success_count <= 2  # Only 2 requests should succeed due to rate limit

def test_endpoint_specific_rate_limits(test_app, fake_redis):
    """Test endpoint-specific rate limit configurations"""
    # Add test endpoints with specific rate limits
    test_endpoints = {
        'login': {'requests': 5, 'window': 300},
        'register': {'requests': 3, 'window': 3600},
        'refresh-token': {'requests': 5, 'window': 300},
        'verify-token': {'requests': 20, 'window': 60}
    }
    
    # Update rate limits in Config
    Config.RATE_LIMITS.update(test_endpoints)
    
    # Disable IP and user-based rate limiting
    Config.IP_RATE_LIMIT['enabled'] = False
    Config.USER_RATE_LIMIT['enabled'] = False
    
    # Create a new Flask app for endpoint-specific tests
    app = Flask(__name__)
    app.config['TESTING'] = True
    
    # Create test endpoints with unique names
    for endpoint in test_endpoints.keys():
        def create_endpoint(endpoint_name):
            @app.route(f'/{endpoint_name}', endpoint=f'test_endpoint_{endpoint_name}')
            @rate_limit(endpoint_name=endpoint_name)
            def test_endpoint_func():
                return jsonify({'message': 'success'})
            test_endpoint_func.__name__ = f'test_endpoint_{endpoint_name}'
            return test_endpoint_func
        
        create_endpoint(endpoint)
    
    with app.test_client() as client:
        for endpoint, limits in test_endpoints.items():
            # Reset Redis for each endpoint test
            fake_redis.flushall()
            
            # Make requests up to the limit
            for _ in range(limits['requests']):
                response = client.get(f'/{endpoint}')
                assert response.status_code == HTTPStatus.OK
            
            # Next request should be rate limited
            response = client.get(f'/{endpoint}')
            assert response.status_code == HTTPStatus.TOO_MANY_REQUESTS

def test_redis_connection_pool(test_app, fake_redis):
    """Test Redis connection pooling"""
    with test_app.test_client() as client:
        # Simulate multiple requests to test connection pooling
        for _ in range(Config.REDIS_MAX_CONNECTIONS + 1):
            response = client.get('/test')
            assert response.status_code in [HTTPStatus.OK, HTTPStatus.TOO_MANY_REQUESTS]

def test_rate_limit_key_generation():
    """Test rate limit key generation"""
    identifier = "test_identifier"
    endpoint = "test_endpoint"
    
    # Test IP-based key
    ip_key = RateLimiter.get_rate_limit_key('ip', identifier, endpoint)
    assert ip_key.startswith(Config.IP_RATE_LIMIT_PREFIX)
    assert identifier in ip_key
    assert endpoint in ip_key
    
    # Test user-based key
    user_key = RateLimiter.get_rate_limit_key('user', identifier, endpoint)
    assert user_key.startswith(Config.USER_RATE_LIMIT_PREFIX)
    assert identifier in user_key
    assert endpoint in user_key

def test_combined_ip_and_user_rate_limiting(test_app, fake_redis):
    """Test combined IP and user-based rate limiting"""
    # Configure rate limits
    Config.RATE_LIMITS.update({
        'test-combined': {
            'requests': 10,  # High limit to avoid endpoint-specific rate limiting
            'window': 60
        }
    })
    
    # Enable both IP and user rate limiting
    Config.IP_RATE_LIMIT['enabled'] = True
    Config.IP_RATE_LIMIT['requests'] = 3
    Config.IP_RATE_LIMIT['window'] = 5
    
    Config.USER_RATE_LIMIT['enabled'] = True
    Config.USER_RATE_LIMIT['requests'] = 4
    Config.USER_RATE_LIMIT['window'] = 5
    
    # Reset Redis before test
    fake_redis.flushall()
    
    # Create a test client and set up the environment
    client = test_app.test_client()
    client.environ_base['REMOTE_ADDR'] = '192.168.1.2'
    
    # Test IP-based rate limiting first
    # Make requests up to IP limit
    for i in range(Config.IP_RATE_LIMIT['requests']):
        response = client.get('/test-combined')
        assert response.status_code == HTTPStatus.OK
    
    # Next request should be rate limited by IP
    response = client.get('/test-combined')
    assert response.status_code == HTTPStatus.TOO_MANY_REQUESTS
    assert response.json['error'] == 'IP-based rate limit exceeded'
    
    # Wait for IP limit to reset
    time.sleep(5)
    
    # Reset Redis and disable IP-based rate limiting for user test
    fake_redis.flushall()
    Config.IP_RATE_LIMIT['enabled'] = False
    
    # Set up user context for user-based rate limiting test
    ctx = test_app.app_context()
    ctx.push()
    g.user_id = 'test_user_123'
    
    try:
        # Test user-based rate limiting
        # Make requests up to user limit
        for i in range(Config.USER_RATE_LIMIT['requests']):
            response = client.get('/test-combined')
            assert response.status_code == HTTPStatus.OK
        
        # Next request should be rate limited by user
        response = client.get('/test-combined')
        assert response.status_code == HTTPStatus.TOO_MANY_REQUESTS
        assert response.json['error'] == 'User-based rate limit exceeded'
    finally:
        ctx.pop()
        # Re-enable IP-based rate limiting
        Config.IP_RATE_LIMIT['enabled'] = True

def test_burst_window_extension(test_app, fake_redis):
    """Test burst window extension after burst limit is exceeded"""
    Config.BURST_HANDLING['enabled'] = True
    Config.BURST_HANDLING['max_burst'] = 3
    Config.BURST_HANDLING['burst_window'] = 2
    
    with test_app.test_client() as client:
        # Make initial burst requests
        for _ in range(Config.BURST_HANDLING['max_burst']):
            response = client.get('/test-burst')
            assert response.status_code == HTTPStatus.OK
        
        # Record time after burst
        burst_time = time.time()
        
        # Wait for original burst window
        time.sleep(Config.BURST_HANDLING['burst_window'])
        
        # Try another request - should be limited with extended window
        response = client.get('/test-burst')
        assert response.status_code == HTTPStatus.TOO_MANY_REQUESTS
        
        # Verify extended window
        assert response.json['retry_after'] > Config.BURST_HANDLING['burst_window']
        assert response.json['retry_after'] <= Config.BURST_HANDLING['burst_window'] * 2

def test_rate_limit_disabled(test_app, fake_redis):
    """Test behavior when rate limiting is disabled"""
    # Disable rate limiting
    Config.RATE_LIMIT_ENABLED = False
    
    with test_app.test_client() as client:
        # Make many requests - all should succeed
        for _ in range(10):  # More than any configured limit
            response = client.get('/test')
            assert response.status_code == HTTPStatus.OK
            assert response.json == {'message': 'success'}
            
            # Headers should not be present
            assert 'X-RateLimit-Limit' not in response.headers
            assert 'X-RateLimit-Remaining' not in response.headers
            assert 'X-RateLimit-Reset' not in response.headers

def test_redis_reconnection(test_app, monkeypatch):
    """Test rate limiting behavior during Redis reconnection"""
    connection_attempts = 0
    
    def mock_zadd(*args, **kwargs):
        nonlocal connection_attempts
        if connection_attempts == 0:
            connection_attempts += 1
            raise redis.ConnectionError("Connection lost")
        return 1  # Success on retry
    
    with test_app.test_client() as client:
        # Mock Redis connection error
        fake_client = fakeredis.FakeRedis(decode_responses=True)
        monkeypatch.setattr(fake_client, 'zadd', mock_zadd)
        monkeypatch.setattr('src.utils.rate_limit.redis_client', fake_client)
        
        # Request should succeed despite initial connection error
        response = client.get('/test')
        assert response.status_code == HTTPStatus.OK
        assert connection_attempts == 1  # Verify reconnection was attempted
