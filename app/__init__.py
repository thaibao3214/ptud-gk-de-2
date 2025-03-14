from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_migrate import Migrate
import os

# Khởi tạo các đối tượng mở rộng
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()

UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your_secret_key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

    # Khởi tạo các thành phần với app
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    migrate = Migrate(app, db)

    login_manager.login_view = 'main.login'
    login_manager.login_message_category = 'info'

    # Import models để tránh lỗi khi migrate
    from app import models  

    # Import và đăng ký Blueprint (import sau khi tạo app)
    from app.routes import main, admin_bp  
    app.register_blueprint(main)
    app.register_blueprint(admin_bp)

    return app
