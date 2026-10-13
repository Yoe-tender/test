#%%
from flask import Blueprint, request
from flask_jwt_extended import create_access_token
from app import db
from app.models import User
from app.utils import success, fail

auth_bp = Blueprint("auth", __name__)

# 注册
@auth_bp.route("/register", methods=["POST"])
def register():
    json_data = request.get_json()
    username = json_data.get("username", "").strip()
    password = json_data.get("password", "").strip()
    if not username or not password:
        return fail("用户名和密码不能为空")
    if User.query.filter_by(username=username).first():
        return fail("用户名已被占用")

    new_user = User(username=username)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return success(msg="注册成功，请登录")

# 登录
@auth_bp.route("/login", methods=["POST"])
def login():
    json_data = request.get_json()
    username = json_data.get("username")
    password = json_data.get("password")
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return fail("账号或密码错误")

    access_token = create_access_token(identity=user.id)
    return success(data={
        "token": access_token,
        "user_id": user.id,
        "username": user.username,
        "is_admin": user.is_admin
    }, msg="登录成功")