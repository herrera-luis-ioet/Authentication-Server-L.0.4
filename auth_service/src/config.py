import os
from dotenv import load_dotenv
from typing import Dict

load_dotenv()

class Config:
    # Redis configuration
    REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
    REDIS_DB = int(os.getenv('REDIS_DB', 0))
    REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', None)
    REDIS_SOCKET_TIMEOUT = int(os.getenv('REDIS_SOCKET_TIMEOUT', 5))
    REDIS_RETRY_ON_TIMEOUT = bool(os.getenv('REDIS_RETRY_ON_TIMEOUT', True))
    REDIS_MAX_CONNECTIONS = int(os.getenv('REDIS_MAX_CONNECTIONS', 10))
    
    # Token configuration
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
    TOKEN_BLACKLIST_PREFIX = 'token_blacklist:'
    TOKEN_EXPIRATION_HOURS = int(os.getenv('TOKEN_EXPIRATION_HOURS', 1))
    
    # Rate limiting configuration
    RATE_LIMIT_ENABLED = bool(os.getenv('RATE_LIMIT_ENABLED', True))
    
    # Default rate limits for different endpoints
    RATE_LIMITS: Dict[str, Dict] = {
        'default': {
            'requests': int(os.getenv('DEFAULT_RATE_LIMIT_REQUESTS', 100)),
            'window': int(os.getenv('DEFAULT_RATE_LIMIT_WINDOW', 3600))  # in seconds
        },
        'login': {
            'requests': int(os.getenv('LOGIN_RATE_LIMIT_REQUESTS', 5)),
            'window': int(os.getenv('LOGIN_RATE_LIMIT_WINDOW', 300))  # 5 minutes
        },
        'register': {
            'requests': int(os.getenv('REGISTER_RATE_LIMIT_REQUESTS', 3)),
            'window': int(os.getenv('REGISTER_RATE_LIMIT_WINDOW', 3600))  # 1 hour
        },
        'reset_password': {
            'requests': int(os.getenv('RESET_PASSWORD_RATE_LIMIT_REQUESTS', 3)),
            'window': int(os.getenv('RESET_PASSWORD_RATE_LIMIT_WINDOW', 3600))  # 1 hour
        },
        'logout': {
            'requests': int(os.getenv('LOGOUT_RATE_LIMIT_REQUESTS', 10)),
            'window': int(os.getenv('LOGOUT_RATE_LIMIT_WINDOW', 300))  # 5 minutes
        },
        'refresh_token': {
            'requests': int(os.getenv('REFRESH_TOKEN_RATE_LIMIT_REQUESTS', 5)),
            'window': int(os.getenv('REFRESH_TOKEN_RATE_LIMIT_WINDOW', 300))  # 5 minutes
        },
        'verify_token': {
            'requests': int(os.getenv('VERIFY_TOKEN_RATE_LIMIT_REQUESTS', 20)),
            'window': int(os.getenv('VERIFY_TOKEN_RATE_LIMIT_WINDOW', 60))  # 1 minute
        }
    }
    
    # IP-based rate limiting
    IP_RATE_LIMIT = {
        'enabled': bool(os.getenv('IP_RATE_LIMIT_ENABLED', True)),
        'requests': int(os.getenv('IP_RATE_LIMIT_REQUESTS', 1000)),
        'window': int(os.getenv('IP_RATE_LIMIT_WINDOW', 3600))  # 1 hour
    }
    
    # User-based rate limiting
    USER_RATE_LIMIT = {
        'enabled': bool(os.getenv('USER_RATE_LIMIT_ENABLED', True)),
        'requests': int(os.getenv('USER_RATE_LIMIT_REQUESTS', 100)),
        'window': int(os.getenv('USER_RATE_LIMIT_WINDOW', 3600))  # 1 hour
    }
    
    # Burst handling configuration
    BURST_HANDLING = {
        'enabled': bool(os.getenv('BURST_HANDLING_ENABLED', True)),
        'max_burst': int(os.getenv('MAX_BURST_REQUESTS', 5)),  # Maximum burst size
        'burst_window': int(os.getenv('BURST_WINDOW', 10))  # Window for burst in seconds
    }
    
    # Rate limit key prefixes
    RATE_LIMIT_KEY_PREFIX = 'rate_limit:'
    IP_RATE_LIMIT_PREFIX = 'ip_rate_limit:'
    USER_RATE_LIMIT_PREFIX = 'user_rate_limit:'
    
    @classmethod
    def validate_redis_config(cls) -> bool:
        """
        Validates the Redis configuration parameters.
        
        Returns:
            bool: True if configuration is valid, False otherwise
        """
        try:
            if not cls.REDIS_HOST or not isinstance(cls.REDIS_HOST, str):
                return False
            if not isinstance(cls.REDIS_PORT, int) or not (1 <= cls.REDIS_PORT <= 65535):
                return False
            if not isinstance(cls.REDIS_DB, int) or cls.REDIS_DB < 0:
                return False
            if cls.REDIS_PASSWORD is not None and not isinstance(cls.REDIS_PASSWORD, str):
                return False
            if not isinstance(cls.REDIS_SOCKET_TIMEOUT, int) or cls.REDIS_SOCKET_TIMEOUT <= 0:
                return False
            if not isinstance(cls.REDIS_MAX_CONNECTIONS, int) or cls.REDIS_MAX_CONNECTIONS <= 0:
                return False
            return True
        except Exception:
            return False
