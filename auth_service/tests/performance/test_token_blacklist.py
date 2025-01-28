import pytest
import time
import threading
import concurrent.futures
from src.services.auth_service import AuthService
from datetime import datetime, timezone
import psutil
import os

class TestTokenBlacklistPerformance:
    @pytest.fixture
    def auth_service(self):
        service = AuthService()
        # Pre-register a test user
        service.register_user("test_user", "test_password")
        return service

    def test_concurrent_token_invalidation(self, auth_service):
        """Test concurrent token invalidation operations."""
        num_threads = 1000
        tokens = []

        # Generate tokens
        for _ in range(num_threads):
            result = auth_service.authenticate_user("test_user", "test_password")
            tokens.append(result["token"])

        start_time = time.time()
        
        def invalidate_token(token):
            auth_service.invalidate_token(token)
            auth_service.verify_token(token)  # Verify it's actually blacklisted

        # Use ThreadPoolExecutor for concurrent operations
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            list(executor.map(invalidate_token, tokens))

        end_time = time.time()
        duration = end_time - start_time

        # Assertions
        assert duration < 10, f"Token invalidation took too long: {duration} seconds"
        
        # Verify all tokens are blacklisted
        for token in tokens:
            result = auth_service.verify_token(token)
            assert result.get("error") == "Token has been invalidated"

    def test_rapid_token_validation(self, auth_service):
        """Test rapid token validation checks."""
        operations_per_second = 100
        test_duration = 60  # seconds
        
        # Generate a valid token
        token = auth_service.authenticate_user("test_user", "test_password")["token"]
        
        start_time = time.time()
        validation_count = 0
        errors = []

        while time.time() - start_time < test_duration:
            batch_start = time.time()
            
            # Perform validation operations
            for _ in range(operations_per_second):
                try:
                    result = auth_service.verify_token(token)
                    assert result.get("user") is not None
                    validation_count += 1
                except Exception as e:
                    errors.append(str(e))
                
            # Sleep if needed to maintain the desired rate
            elapsed = time.time() - batch_start
            if elapsed < 1:
                time.sleep(1 - elapsed)

        # Assertions
        assert len(errors) == 0, f"Validation errors occurred: {errors}"
        assert validation_count >= operations_per_second * test_duration * 0.95  # Allow 5% margin

    def test_memory_usage_under_load(self, auth_service):
        """Test memory usage during intensive token operations."""
        num_tokens = 1000
        tokens = []
        
        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # Convert to MB
        
        # Generate and blacklist tokens
        for _ in range(num_tokens):
            token = auth_service.authenticate_user("test_user", "test_password")["token"]
            tokens.append(token)
            auth_service.invalidate_token(token)
            
        # Get final memory usage
        final_memory = process.memory_info().rss / 1024 / 1024  # Convert to MB
        memory_increase = final_memory - initial_memory
        
        # Assertions
        assert memory_increase < 100, f"Memory usage increased by {memory_increase}MB, exceeding 100MB limit"
        
        # Verify all tokens are still properly blacklisted
        for token in tokens:
            result = auth_service.verify_token(token)
            assert result.get("error") == "Token has been invalidated"

    def test_response_time_degradation(self, auth_service):
        """Test response time degradation as blacklist grows."""
        num_tokens = 1000
        sample_size = 10
        response_times = []
        
        def measure_validation_time():
            token = auth_service.authenticate_user("test_user", "test_password")["token"]
            start = time.time()
            auth_service.verify_token(token)
            return time.time() - start
        
        # Initial response time measurement
        initial_times = [measure_validation_time() for _ in range(sample_size)]
        initial_avg = sum(initial_times) / len(initial_times)
        
        # Add tokens to blacklist
        tokens = []
        for _ in range(num_tokens):
            token = auth_service.authenticate_user("test_user", "test_password")["token"]
            tokens.append(token)
            auth_service.invalidate_token(token)
            
            if _ % (num_tokens // 10) == 0:  # Measure every 10% of tokens
                times = [measure_validation_time() for _ in range(sample_size)]
                avg_time = sum(times) / len(times)
                response_times.append(avg_time)
                
        # Final response time measurement
        final_times = [measure_validation_time() for _ in range(sample_size)]
        final_avg = sum(final_times) / len(final_times)
        
        # Calculate degradation
        degradation = (final_avg - initial_avg) / initial_avg * 100
        
        # Assertions
        assert degradation < 200, f"Response time degraded by {degradation}%, exceeding 200% threshold"
        assert max(response_times) < 0.1, f"Maximum response time {max(response_times)}s exceeded 0.1s threshold"