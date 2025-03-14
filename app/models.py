from app import db, bcrypt
from datetime import datetime
from flask_login import UserMixin
from app import login_manager

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), default='user')
    active_status = db.Column(db.Boolean, default=True)  # Thay thế is_active bằng active_status
    avatar = db.Column(db.String(255), default='default.jpg')
    
    # Mã hóa mật khẩu
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    # Kiểm tra mật khẩu
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    # Kiểm tra quyền admin
    def is_admin(self):
        return self.role == 'admin'

    # Ghi đè lại thuộc tính is_active
    @property
    def is_active(self):
        return self.active_status  # Trả về giá trị của active_status

    @is_active.setter
    def is_active(self, value):
        self.active_status = value  # Gán giá trị cho active_status

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    completed = db.Column(db.Boolean, default=False)  # Thêm trường này
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('tasks', lazy='dynamic', cascade="all, delete"))


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('posts', lazy='dynamic', cascade="all, delete"))
