import time
import logging
import redis
from functools import wraps
from flask import request, jsonify, g
from http import HTTPStatus
from src.config import Config

# Configure logging
logger = logging.getLogger(__name__)

# Initialize Redis client with connection pooling
redis_client = redis.Redis(
    host=Config.REDIS_HOST,
    port=Config.REDIS_PORT,
    db=Config.REDIS_DB,
    password=Config.REDIS_PASSWORD,
    decode_responses=True,
    socket_timeout=Config.REDIS_SOCKET_TIMEOUT,
    retry_on_timeout=Config.REDIS_RETRY_ON_TIMEOUT,
    max_connections=Config.REDIS_MAX_CONNECTIONS
)

class RateLimiter:
    """
    Rate limiter class that implements IP-based and user-based rate limiting
    with burst handling and sliding window algorithm.
    """
    
    @staticmethod
    def get_rate_limit_key(identifier_type, identifier, endpoint):
        """
        Generate a unique rate limit key based on identifier type and value.
        
        Args:
            identifier_type (str): Type of identifier ('ip' or 'user')
            identifier (str): The actual identifier value
            endpoint (str): The endpoint being accessed
            
        Returns:
            str: A unique rate limit key
        """
        prefix = (Config.IP_RATE_LIMIT_PREFIX if identifier_type == 'ip' 
                 else Config.USER_RATE_LIMIT_PREFIX)
        return f"{prefix}{identifier}:{endpoint}"
    
    @staticmethod
    def get_rate_limit_config(endpoint):
        """
        Get rate limit configuration for a specific endpoint.
        
        Args:
            endpoint (str): The endpoint to get configuration for
            
        Returns:
            dict: Rate limit configuration
        """
        return Config.RATE_LIMITS.get(endpoint, Config.RATE_LIMITS['default'])
    
    @staticmethod
    def check_rate_limit(key, max_requests, window, current_time):
        """
        Check if the rate limit has been exceeded.
        
        Args:
            key (str): Rate limit key
            max_requests (int): Maximum allowed requests
            window (int): Time window in seconds
            current_time (int): Current timestamp
            
        Returns:
            tuple: (is_limited, remaining_requests, retry_after)
        """
        pipe = redis_client.pipeline()
        try:
            # Remove old entries
            pipe.zremrangebyscore(key, 0, current_time - window)
            # Count current requests
            pipe.zcard(key)
            # Get oldest request timestamp if any
            pipe.zrange(key, 0, 0, withscores=True)
            results = pipe.execute()
            
            request_count = results[1]
            oldest_request = results[2][0][1] if results[2] else current_time
            
            remaining = max_requests - request_count
            retry_after = window - (current_time - int(oldest_request)) if request_count >= max_requests else 0
            
            return request_count >= max_requests, remaining, retry_after
            
        except redis.RedisError as e:
            logger.error(f"Redis error in check_rate_limit: {str(e)}")
            return False, max_requests, 0
    
    @staticmethod
    def update_rate_limit(key, current_time, window, burst_enabled=False):
        """
        Update rate limit counters and handle burst requests.
        
        Args:
            key (str): Rate limit key
            current_time (int): Current timestamp
            window (int): Time window in seconds
            burst_enabled (bool): Whether burst handling is enabled
        """
        try:
            if burst_enabled and Config.BURST_HANDLING['enabled']:
                burst_key = f"{key}:burst"
                burst_count = redis_client.get(burst_key)
                
                if burst_count is None:
                    # Initialize burst counter
                    redis_client.setex(burst_key, Config.BURST_HANDLING['burst_window'], 1)
                elif int(burst_count) < Config.BURST_HANDLING['max_burst']:
                    # Increment burst counter
                    redis_client.incr(burst_key)
                else:
                    # Burst limit exceeded, use normal window
                    window = max(window, Config.BURST_HANDLING['burst_window'] * 2)
            
            # Add current request to the sorted set
            redis_client.zadd(key, {f"{current_time}:{redis_client.zcard(key)}": current_time})
            redis_client.expire(key, window)
            
        except redis.RedisError as e:
            logger.error(f"Redis error in update_rate_limit: {str(e)}")

def rate_limit(endpoint_name=None, user_based=False):
    """
    Rate limiting decorator with support for IP-based and user-based limiting.
    
    Args:
        endpoint_name (str): Name of the endpoint for custom rate limits
        user_based (bool): Whether to use user-based rate limiting
        
    Returns:
        decorator: Function that implements rate limiting
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not Config.RATE_LIMIT_ENABLED:
                return f(*args, **kwargs)
                
            current_time = int(time.time())
            endpoint = endpoint_name or request.endpoint
            rate_config = RateLimiter.get_rate_limit_config(endpoint)
            
            # Apply user-based rate limiting if enabled and user is authenticated
            if user_based and Config.USER_RATE_LIMIT['enabled'] and hasattr(g, 'user_id'):
                # Use a global user key for overall user rate limiting
                global_user_key = f"{Config.USER_RATE_LIMIT_PREFIX}{g.user_id}"
                
                # Check if rate limited first
                is_limited, remaining, retry_after = RateLimiter.check_rate_limit(
                    global_user_key,
                    Config.USER_RATE_LIMIT['requests'],
                    Config.USER_RATE_LIMIT['window'],
                    current_time
                )
                
                if is_limited:
                    response = jsonify({
                        'error': 'User-based rate limit exceeded',
                        'retry_after': retry_after
                    })
                    response.headers['X-RateLimit-Limit'] = str(Config.USER_RATE_LIMIT['requests'])
                    response.headers['X-RateLimit-Remaining'] = str(remaining)
                    response.headers['X-RateLimit-Reset'] = str(current_time + retry_after)
                    return response, HTTPStatus.TOO_MANY_REQUESTS
                
                # Update user rate limit counter only if not limited
                RateLimiter.update_rate_limit(
                    global_user_key,
                    current_time,
                    Config.USER_RATE_LIMIT['window'],
                    burst_enabled=True
                )
            
            # Apply IP-based rate limiting
            if Config.IP_RATE_LIMIT['enabled']:
                # Use a global IP key for overall IP rate limiting
                global_ip_key = f"{Config.IP_RATE_LIMIT_PREFIX}{request.remote_addr}"
                is_limited, remaining, retry_after = RateLimiter.check_rate_limit(
                    global_ip_key,
                    Config.IP_RATE_LIMIT['requests'],
                    Config.IP_RATE_LIMIT['window'],
                    current_time
                )
                
                if is_limited:
                    response = jsonify({
                        'error': 'IP-based rate limit exceeded',
                        'retry_after': retry_after
                    })
                    response.headers['X-RateLimit-Limit'] = str(Config.IP_RATE_LIMIT['requests'])
                    response.headers['X-RateLimit-Remaining'] = str(remaining)
                    response.headers['X-RateLimit-Reset'] = str(current_time + retry_after)
                    return response, HTTPStatus.TOO_MANY_REQUESTS
                
                RateLimiter.update_rate_limit(global_ip_key, current_time, Config.IP_RATE_LIMIT['window'])
            
            # Apply endpoint-specific rate limiting
            endpoint_key = f"{Config.RATE_LIMIT_KEY_PREFIX}{endpoint}"
            
            is_limited, remaining, retry_after = RateLimiter.check_rate_limit(
                endpoint_key,
                rate_config['requests'],
                rate_config['window'],
                current_time
            )
            
            if is_limited:
                response = jsonify({
                    'error': 'Rate limit exceeded for this endpoint',
                    'retry_after': retry_after
                })
                response.headers['X-RateLimit-Limit'] = str(rate_config['requests'])
                response.headers['X-RateLimit-Remaining'] = str(remaining)
                response.headers['X-RateLimit-Reset'] = str(current_time + retry_after)
                return response, HTTPStatus.TOO_MANY_REQUESTS
            
            RateLimiter.update_rate_limit(
                endpoint_key,
                current_time,
                rate_config['window'],
                burst_enabled=True
            )
            
            # Add rate limit headers to successful response
            response = f(*args, **kwargs)
            if isinstance(response, tuple):
                response_obj, status_code = response
            else:
                response_obj, status_code = response, 200
                
            if hasattr(response_obj, 'headers'):
                response_obj.headers['X-RateLimit-Limit'] = str(rate_config['requests'])
                response_obj.headers['X-RateLimit-Remaining'] = str(remaining)
                response_obj.headers['X-RateLimit-Reset'] = str(current_time + rate_config['window'])
            
            return (response_obj, status_code) if isinstance(response, tuple) else response
                
        return decorated_function
    return decorator
