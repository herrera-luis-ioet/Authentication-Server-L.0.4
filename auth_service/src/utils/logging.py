import logging
import json
from datetime import datetime, timezone
from functools import wraps
from flask import request, g

# Configure JSON logger
class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record):
        """Format log record as JSON."""
        log_object = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
        }
        
        # Add extra fields if they exist
        if hasattr(record, 'extra_fields'):
            log_object.update(record.extra_fields)
            
        return json.dumps(log_object)

# PUBLIC_INTERFACE
def setup_logger(name='auth_service', level=logging.INFO):
    """
    Set up and configure the logger.
    
    Args:
        name (str): Logger name
        level (int): Logging level
        
    Returns:
        logging.Logger: Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(JSONFormatter())
    logger.addHandler(console_handler)
    
    return logger

# Create main logger instance
auth_logger = setup_logger()

# PUBLIC_INTERFACE
def log_auth_event(event_type, status, details=None):
    """
    Log authentication events with structured data.
    
    Args:
        event_type (str): Type of auth event (login, logout, etc.)
        status (str): Status of the event (success, failure)
        details (dict, optional): Additional event details
    """
    log_data = {
        'event_type': event_type,
        'status': status,
        'request_id': getattr(g, 'request_id', None),
        'ip_address': request.remote_addr,
        'user_agent': request.user_agent.string,
    }
    
    if details:
        log_data.update(details)
    
    # Set extra fields for the log record
    extra = {'extra_fields': log_data}
    
    if status == 'success':
        auth_logger.info(f"Auth event: {event_type}", extra=extra)
    else:
        auth_logger.error(f"Auth event: {event_type}", extra=extra)

# PUBLIC_INTERFACE
def audit_log_decorator(event_type):
    """
    Decorator to automatically log authentication events.
    
    Args:
        event_type (str): Type of auth event to log
        
    Returns:
        function: Decorated function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
                
                # Extract status code from response
                status_code = result[1] if isinstance(result, tuple) else 200
                
                # Determine if the request was successful
                success = 200 <= status_code < 300
                
                # Log the event
                log_auth_event(
                    event_type=event_type,
                    status='success' if success else 'failure',
                    details={
                        'status_code': status_code,
                        'username': request.get_json().get('username') if request.is_json else None
                    }
                )
                
                return result
                
            except Exception as e:
                # Log the error
                log_auth_event(
                    event_type=event_type,
                    status='failure',
                    details={
                        'error': str(e),
                        'username': request.get_json().get('username') if request.is_json else None
                    }
                )
                raise
                
        return wrapper
    return decorator
