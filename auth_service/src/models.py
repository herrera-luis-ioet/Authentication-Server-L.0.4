from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    """User model for storing user credentials and information."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    def __repr__(self):
        return f'<User {self.username}>'

class AuthLog(db.Model):
    """Model for logging authentication requests and activities."""
    __tablename__ = 'auth_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    event_type = db.Column(db.String(50), nullable=False)  # login, logout, token_refresh, etc.
    status = db.Column(db.String(20), nullable=False)  # success, failure
    ip_address = db.Column(db.String(45), nullable=True)  # IPv4/IPv6 address
    user_agent = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    details = db.Column(db.Text, nullable=True)  # Additional event details in JSON format

    def __repr__(self):
        return f'<AuthLog {self.event_type} {self.status}>'
