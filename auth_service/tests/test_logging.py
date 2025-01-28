import pytest
import json
import logging
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.utils.logging import setup_logger, log_auth_event, audit_log_decorator
from src.app import app
from flask import g, request
from unittest.mock import patch, MagicMock

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture
def logger():
    return setup_logger('test_logger')

def test_json_formatter(logger):
    """Test JSON formatter output structure"""
    with patch('logging.StreamHandler.emit') as mock_emit:
        logger.info('Test message')
        
        # Get the log record from the mock
        args = mock_emit.call_args[0]
        log_record = args[0]
        
        # Format the record
        formatted = logger.handlers[0].formatter.format(log_record)
        log_dict = json.loads(formatted)
        
        # Check required fields
        assert 'timestamp' in log_dict
        assert 'level' in log_dict
        assert 'message' in log_dict
        assert 'module' in log_dict
        assert 'function' in log_dict
        assert log_dict['level'] == 'INFO'
        assert log_dict['message'] == 'Test message'

def test_log_auth_event_success():
    """Test logging of successful authentication events"""
    with app.test_request_context('/'):
        g.request_id = 'test-request-id'
        with patch('src.utils.logging.auth_logger') as mock_logger:
            log_auth_event('login', 'success', {'user': 'testuser'})
            
            mock_logger.info.assert_called_once()
            call_args = mock_logger.info.call_args[1]
            extra_fields = call_args['extra']['extra_fields']
            
            assert extra_fields['event_type'] == 'login'
            assert extra_fields['status'] == 'success'
            assert extra_fields['request_id'] == 'test-request-id'
            assert extra_fields['user'] == 'testuser'

def test_log_auth_event_failure():
    """Test logging of failed authentication events"""
    with app.test_request_context('/'):
        with patch('src.utils.logging.auth_logger') as mock_logger:
            log_auth_event('login', 'failure', {'error': 'Invalid credentials'})
            
            mock_logger.error.assert_called_once()
            call_args = mock_logger.error.call_args[1]
            extra_fields = call_args['extra']['extra_fields']
            
            assert extra_fields['event_type'] == 'login'
            assert extra_fields['status'] == 'failure'
            assert extra_fields['error'] == 'Invalid credentials'

def test_audit_log_decorator():
    """Test the audit log decorator functionality"""
    with app.test_request_context('/', json={'username': 'testuser'}):
        # Create a mock function to decorate
        @audit_log_decorator('test_event')
        def test_function():
            return {'message': 'success'}, 200
        
        with patch('src.utils.logging.log_auth_event') as mock_log:
            result = test_function()
            
            # Verify the function returned correctly
            assert result[0] == {'message': 'success'}
            assert result[1] == 200
            
            # Verify logging was called correctly
            mock_log.assert_called_once_with(
                event_type='test_event',
                status='success',
                details={
                    'status_code': 200,
                    'username': 'testuser'
                }
            )

def test_audit_log_decorator_failure():
    """Test the audit log decorator with failing function"""
    with app.test_request_context('/', json={'username': 'testuser'}):
        # Create a mock function that raises an exception
        @audit_log_decorator('test_event')
        def failing_function():
            raise ValueError('Test error')
        
        with patch('src.utils.logging.log_auth_event') as mock_log:
            with pytest.raises(ValueError):
                failing_function()
            
            # Verify error was logged
            mock_log.assert_called_once_with(
                event_type='test_event',
                status='failure',
                details={
                    'error': 'Test error',
                    'username': 'testuser'
                }
            )

def test_setup_logger_configuration():
    """Test logger setup and configuration"""
    logger = setup_logger('test_config_logger')
    
    # Verify logger configuration
    assert logger.level == logging.INFO
    assert len(logger.handlers) == 1
    assert isinstance(logger.handlers[0], logging.StreamHandler)
    assert isinstance(logger.handlers[0].formatter, logging.Formatter)

def test_json_formatter_extra_fields():
    """Test JSON formatter with extra fields"""
    logger = setup_logger('test_extra_logger')
    
    with patch('logging.StreamHandler.emit') as mock_emit:
        extra = {'extra_fields': {'user_id': '123', 'action': 'test'}}
        logger.info('Test with extra', extra=extra)
        
        args = mock_emit.call_args[0]
        log_record = args[0]
        formatted = logger.handlers[0].formatter.format(log_record)
        log_dict = json.loads(formatted)
        
        assert 'user_id' in log_dict
        assert log_dict['user_id'] == '123'
        assert log_dict['action'] == 'test'

def test_audit_log_decorator_with_error_response():
    """Test audit log decorator with error response"""
    with app.test_request_context('/', json={'username': 'testuser'}):
        @audit_log_decorator('test_event')
        def error_function():
            return {'error': 'Test error'}, 400
        
        with patch('src.utils.logging.log_auth_event') as mock_log:
            result = error_function()
            
            assert result[1] == 400
            mock_log.assert_called_once_with(
                event_type='test_event',
                status='failure',
                details={
                    'status_code': 400,
                    'username': 'testuser'
                }
            )

def test_log_auth_event_with_request_id():
    """Test logging with request ID"""
    with app.test_request_context('/'):
        g.request_id = 'test-123'
        with patch('src.utils.logging.auth_logger') as mock_logger:
            log_auth_event('test', 'success', {'test_data': 'value'})
            
            call_args = mock_logger.info.call_args[1]
            extra_fields = call_args['extra']['extra_fields']
            
            assert extra_fields['request_id'] == 'test-123'
            assert extra_fields['test_data'] == 'value'

def test_audit_log_decorator_missing_json():
    """Test audit log decorator with missing JSON body"""
    with app.test_request_context('/'):  # No JSON data
        @audit_log_decorator('test_event')
        def test_function():
            return {'message': 'success'}, 200
        
        with patch('src.utils.logging.log_auth_event') as mock_log:
            result = test_function()
            
            assert result[0] == {'message': 'success'}
            mock_log.assert_called_once_with(
                event_type='test_event',
                status='success',
                details={
                    'status_code': 200,
                    'username': None
                }
            )

def test_json_formatter_all_fields():
    """Test all fields in JSON formatter output"""
    logger = setup_logger('test_all_fields')
    
    with patch('logging.StreamHandler.emit') as mock_emit:
        logger.error('Test error message')
        
        args = mock_emit.call_args[0]
        log_record = args[0]
        formatted = logger.handlers[0].formatter.format(log_record)
        log_dict = json.loads(formatted)
        
        required_fields = ['timestamp', 'level', 'message', 'module', 'function']
        for field in required_fields:
            assert field in log_dict
        
        assert log_dict['level'] == 'ERROR'
        assert log_dict['message'] == 'Test error message'
        assert isinstance(log_dict['timestamp'], str)
