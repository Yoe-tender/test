from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
import os
from dotenv import load_dotenv

load_dotenv()

db = SQLAlchemy()
jwt = JWTManager()

def create_app():
    # 定位项目根目录
    # __file__ = 当前文件：app/__init__.py
    current_file_path = os.path.abspath(__file__)
    app_folder = os.path.dirname(current_file_path)
    BASE_DIR = os.path.dirname(app_folder)  # simple_demo 根目录
    template_folder_abs = os.path.join(BASE_DIR, "templates")

    # 打印关键路径，调试用！运行后看控制台输出
    print("=== 调试信息 ===")
    print(f"项目根目录: {BASE_DIR}")
    print(f"模板文件夹完整路径: {template_folder_abs}")
    print(f"模板文件夹是否存在: {os.path.exists(template_folder_abs)}")
    print(f"index.html 是否存在: {os.path.exists(os.path.join(template_folder_abs, 'index.html'))}")

    # 手动指定模板目录！！
    app = Flask(__name__, template_folder=template_folder_abs)

    user = os.getenv("MYSQL_USER")
    pwd = os.getenv("MYSQL_PASSWORD")
    host = os.getenv("MYSQL_HOST")
    port = os.getenv("MYSQL_PORT")
    dbname = os.getenv("MYSQL_DB")

    app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+pymysql://{user}:{pwd}@{host}:{port}/{dbname}?charset=utf8mb4"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 3600 * 6

    db.init_app(app)
    jwt.init_app(app)
    CORS(app)

    # 注册蓝图
    from app.routes.auth import auth_bp
    from app.routes.message import msg_bp
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(msg_bp, url_prefix="/api/message")

    @app.route("/")
    def index():
        from flask import render_template
        return render_template("index.html")

    return app