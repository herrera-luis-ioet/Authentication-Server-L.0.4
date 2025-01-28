import jwt
import redis
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from ..config import Config

class AuthService:
    def __init__(self):
        self.secret_key = Config.JWT_SECRET_KEY
        self.users = {}  # In production, this should be a database
        self.redis_client = redis.Redis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            db=Config.REDIS_DB,
            password=Config.REDIS_PASSWORD,
            decode_responses=True
        )

    def register_user(self, username, password):
        """Register a new user with hashed password."""
        if username in self.users:
            return {"error": "Username already exists"}
        
        self.users[username] = {
            "password": generate_password_hash(password),
            "created_at": datetime.now(timezone.utc)
        }
        return {"message": "User registered successfully"}

    def authenticate_user(self, username, password):
        """Authenticate user and return JWT token."""
        user = self.users.get(username)
        if not user or not check_password_hash(user["password"], password):
            return {"error": "Invalid credentials"}

        token = self._generate_token(username)
        return {"token": token}

    def verify_token(self, token):
        """Verify if the token is valid and not blacklisted."""
        blacklist_key = f"{Config.TOKEN_BLACKLIST_PREFIX}{token}"
        if self.redis_client.exists(blacklist_key):
            return {"error": "Token has been invalidated"}

        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            user = self.users.get(payload["username"])
            if not user:
                return {"error": "User not found"}
            return {"user": {"username": payload["username"]}}
        except jwt.ExpiredSignatureError:
            return {"error": "Token has expired"}
        except jwt.InvalidTokenError:
            return {"error": "Invalid token"}
        except redis.RedisError:
            return {"error": "Service temporarily unavailable"}

    def refresh_token(self, current_token):
        """Generate a new token if the current one is valid."""
        verify_result = self.verify_token(current_token)
        if verify_result.get("error"):
            return verify_result

        username = verify_result["user"]["username"]
        new_token = self._generate_token(username)
        try:
            self.invalidate_token(current_token)
            return {"token": new_token}
        except redis.RedisError:
            return {"error": "Service temporarily unavailable"}

    def invalidate_token(self, token):
        """Add token to blacklist with expiration."""
        try:
            # Decode token to get expiration time
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            exp_timestamp = payload.get("exp")
            if exp_timestamp:
                # Calculate TTL as time until token expiration
                current_timestamp = int(datetime.now(timezone.utc).timestamp())
                ttl = max(0, exp_timestamp - current_timestamp)
                
                blacklist_key = f"{Config.TOKEN_BLACKLIST_PREFIX}{token}"
                self.redis_client.setex(blacklist_key, ttl, "1")
        except (jwt.InvalidTokenError, redis.RedisError) as e:
            raise Exception(f"Failed to invalidate token: {str(e)}")

    def _generate_token(self, username):
        """Generate a new JWT token."""
        import time
        current_time = datetime.now(timezone.utc)
        payload = {
            "username": username,
            "exp": current_time + timedelta(hours=1),
            "iat": int(time.time()),  # Use Unix timestamp for iat
            "jti": str(hash(f"{username}{time.time_ns()}"))  # Use nanosecond precision for uniqueness
        }
        return jwt.encode(payload, self.secret_key, algorithm="HS256")
