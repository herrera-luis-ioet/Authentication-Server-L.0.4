import pytest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_health_check(client):
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json['status'] == 'healthy'
    assert response.json['service'] == 'auth-service'
