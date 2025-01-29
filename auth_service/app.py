from flask import Flask, jsonify
from flask_migrate import Migrate
from src.routes.auth import auth_bp
from src.models import db
from flask_cors import CORS

def create_app(config=None):
    app = Flask(__name__)
    CORS(app)

    # Default configuration
    app.config.update({
        'SQLALCHEMY_DATABASE_URI': 'postgresql://postgres:postgres@localhost:5432/auth_db',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SECRET_KEY': 'dev_key'
    })

    # Override with custom config if provided
    if config:
        app.config.update(config)

    # Initialize extensions
    db.init_app(app)
    migrate = Migrate(app, db)
    app.register_blueprint(auth_bp, url_prefix='/auth')

    return app

app = create_app()

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy", "service": "auth-service"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
