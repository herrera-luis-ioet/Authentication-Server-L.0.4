import pytest
import redis
import fakeredis
import sqlite3
from datetime import datetime
from src.app import create_app
from src.models import db, User, AuthLog
from src.config import Config
from src.utils.rate_limit import redis_client as app_redis_client

@pytest.fixture
def app():
    """Create and configure a test Flask application instance."""
    # Configure SQLite to handle datetime with timezone
    sqlite3.register_adapter(datetime, lambda val: val.isoformat())
    sqlite3.register_converter("datetime", lambda val: datetime.fromisoformat(val.decode()))

    app = create_app({
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'TESTING': True,
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SECRET_KEY': 'test_secret_key',
        'SQLALCHEMY_ENGINE_OPTIONS': {
            'connect_args': {
                'detect_types': sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
            }
        }
    })
    with app.app_context():
        db.create_all()
    return app

@pytest.fixture
def client(app):
    """Create a test client for the app."""
    return app.test_client()

@pytest.fixture
def _db(app):
    """Create and initialize the test database."""
    with app.app_context():
        db.create_all()
        yield db
        db.session.remove()
        db.drop_all()

@pytest.fixture
def test_user(_db):
    """Create a test user."""
    user = User(
        username='testuser',
        password_hash='test_hash',
        email='test@example.com'
    )
    _db.session.add(user)
    _db.session.commit()
    return user

@pytest.fixture
def test_auth_log(_db, test_user):
    """Create a test auth log entry."""
    auth_log = AuthLog(
        user_id=test_user.id,
        event_type='login',
        status='success',
        ip_address='127.0.0.1',
        user_agent='Mozilla/5.0',
        details='{"source": "test"}'
    )
    _db.session.add(auth_log)
    _db.session.commit()
    return auth_log

@pytest.fixture
def redis_client(monkeypatch):
    """Create a fake Redis client for testing."""
    fake_redis = fakeredis.FakeRedis(decode_responses=True)
    # Patch the redis client in rate_limit module
    monkeypatch.setattr('src.utils.rate_limit.redis_client', fake_redis)
    return fake_redis

@pytest.fixture
def auth_service(redis_client):
    """Create an AuthService instance with fake Redis for testing."""
    from src.services.auth_service import AuthService
    service = AuthService()
    service.redis_client = redis_client
    return service
