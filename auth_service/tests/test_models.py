import pytest
from datetime import datetime, timezone
from sqlalchemy.exc import IntegrityError
from src.models import User, AuthLog

def test_create_user(_db):
    """Test creating a new user with valid data."""
    user = User(
        username='newuser',
        password_hash='hashed_password',
        email='new@example.com'
    )
    _db.session.add(user)
    _db.session.commit()

    assert user.id is not None
    assert user.username == 'newuser'
    assert user.email == 'new@example.com'
    assert user.is_active is True
    assert isinstance(user.created_at, datetime)
    assert isinstance(user.updated_at, datetime)
    assert user.created_at.tzinfo == timezone.utc
    assert user.updated_at.tzinfo == timezone.utc

def test_user_unique_constraints(_db):
    """Test unique constraints for username and email."""
    user1 = User(
        username='uniqueuser',
        password_hash='hash1',
        email='unique@example.com'
    )
    _db.session.add(user1)
    _db.session.commit()

    # Try creating user with same username
    user2 = User(
        username='uniqueuser',
        password_hash='hash2',
        email='different@example.com'
    )
    _db.session.add(user2)
    with pytest.raises(IntegrityError):
        _db.session.commit()
    _db.session.rollback()

    # Try creating user with same email
    user3 = User(
        username='differentuser',
        password_hash='hash3',
        email='unique@example.com'
    )
    _db.session.add(user3)
    with pytest.raises(IntegrityError):
        _db.session.commit()
    _db.session.rollback()

def test_user_nullable_constraints(_db):
    """Test that required fields cannot be null."""
    user = User(
        username=None,
        password_hash='hash',
        email='test@example.com'
    )
    _db.session.add(user)
    with pytest.raises(IntegrityError):
        _db.session.commit()
    _db.session.rollback()

def test_create_auth_log(_db, test_user):
    """Test creating a new auth log entry."""
    auth_log = AuthLog(
        user_id=test_user.id,
        event_type='login',
        status='success',
        ip_address='192.168.1.1',
        user_agent='Test Browser',
        details='{"method": "password"}'
    )
    _db.session.add(auth_log)
    _db.session.commit()

    assert auth_log.id is not None
    assert auth_log.user_id == test_user.id
    assert auth_log.event_type == 'login'
    assert auth_log.status == 'success'
    assert auth_log.created_at.tzinfo == timezone.utc

def test_auth_log_nullable_fields(_db, test_user):
    """Test that optional fields can be null in auth log."""
    auth_log = AuthLog(
        user_id=test_user.id,
        event_type='logout',
        status='success'
    )
    _db.session.add(auth_log)
    _db.session.commit()

    assert auth_log.ip_address is None
    assert auth_log.user_agent is None
    assert auth_log.details is None

def test_auth_log_required_fields(_db):
    """Test that required fields cannot be null in auth log."""
    auth_log = AuthLog(
        user_id=None,  # This can be null
        event_type=None,  # This cannot be null
        status='success'
    )
    _db.session.add(auth_log)
    with pytest.raises(IntegrityError):
        _db.session.commit()
    _db.session.rollback()

def test_user_auth_log_relationship(_db, test_user):
    """Test the relationship between User and AuthLog models."""
    # Create multiple auth logs for the user
    auth_log1 = AuthLog(
        user_id=test_user.id,
        event_type='login',
        status='success'
    )
    auth_log2 = AuthLog(
        user_id=test_user.id,
        event_type='token_refresh',
        status='success'
    )
    _db.session.add_all([auth_log1, auth_log2])
    _db.session.commit()

    # Query the logs through the database
    logs = AuthLog.query.filter_by(user_id=test_user.id).all()
    assert len(logs) == 2
    assert all(log.user_id == test_user.id for log in logs)

def test_user_repr():
    """Test the string representation of User model."""
    user = User(username='testuser')
    assert str(user) == '<User testuser>'

def test_auth_log_repr():
    """Test the string representation of AuthLog model."""
    auth_log = AuthLog(event_type='login', status='success')
    assert str(auth_log) == '<AuthLog login success>'

def test_user_update(_db, test_user):
    """Test updating user fields."""
    original_updated_at = test_user.updated_at
    test_user.email = 'updated@example.com'
    _db.session.commit()

    assert test_user.email == 'updated@example.com'
    assert test_user.updated_at > original_updated_at

def test_cascade_delete(_db, test_user):
    """Test that deleting a user doesn't delete associated auth logs."""
    auth_log = AuthLog(
        user_id=test_user.id,
        event_type='login',
        status='success'
    )
    _db.session.add(auth_log)
    _db.session.commit()

    # Delete the user
    _db.session.delete(test_user)
    _db.session.commit()

    # Auth log should still exist with null user_id
    log = _db.session.get(AuthLog, auth_log.id)
    assert log is not None
    assert log.user_id is None