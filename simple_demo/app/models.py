from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from app import db

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    create_time = db.Column(db.DateTime, default=datetime.now)

    def set_password(self, raw_pwd):
        self.password_hash = generate_password_hash(raw_pwd)

    def check_password(self, raw_pwd):
        return check_password_hash(self.password_hash, raw_pwd)


class Message(db.Model):
    __tablename__ = "messages" # 沿用旧表名！
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)
    create_time = db.Column(db.DateTime, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    user = db.relationship("User", backref=db.backref("messages", lazy=True))