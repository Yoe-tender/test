from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)

# ====================== 数据库配置【自行修改】======================
USER = "root"
PASSWORD = "fyx20050616"
DB_NAME = "message_board"
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{USER}:{PASSWORD}@127.0.0.1:3306/{DB_NAME}?charset=utf8mb4'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# =================================================================

db = SQLAlchemy(app)

# 数据库模型（ORM 映射数据表）
class Message(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)
    create_time = db.Column(db.DateTime, default=datetime.now)

# 程序首次运行自动创建数据表
with app.app_context():
    db.create_all()

# 首页
@app.route('/')
def index():
    return render_template("index.html")

# 1. 获取留言列表【分页】
@app.route("/api/get_msg", methods=["GET"])
def get_msg():
    page = request.args.get("page", 1, type=int)
    page_size = 5
    # 分页查询，时间倒序
    paginate = Message.query.order_by(Message.create_time.desc()).paginate(page=page, per_page=page_size)
    result_list = []
    for item in paginate.items:
        result_list.append({
            "id": item.id,
            "username": item.username,
            "content": item.content,
            "create_time": str(item.create_time)
        })
    return jsonify({
        "code": 200,
        "msg": "success",
        "data": result_list,
        "total": paginate.total,
        "pages": paginate.pages,
        "current_page": page
    })

# 2. 新增留言
@app.route("/api/add_msg", methods=["POST"])
def add_msg():
    data = request.get_json()
    username = data.get("username", "").strip()
    content = data.get("content", "").strip()

    # 后端参数校验
    if not username:
        return jsonify({"code": 400, "msg": "昵称不能为空"})
    if not content:
        return jsonify({"code": 400, "msg": "留言内容不能为空"})
    if len(content) > 300:
        return jsonify({"code": 400, "msg": "留言不能超过300字"})

    new_msg = Message(username=username, content=content)
    db.session.add(new_msg)
    db.session.commit()
    return jsonify({"code": 200, "msg": "留言发布成功"})

# 3. 修改留言
@app.route("/api/update_msg", methods=["POST"])
def update_msg():
    data = request.get_json()
    msg_id = data.get("id")
    new_content = data.get("content", "").strip()

    if not new_content:
        return jsonify({"code": 400, "msg": "内容不能为空"})

    msg = Message.query.get(msg_id)
    if not msg:
        return jsonify({"code": 404, "msg": "该留言不存在"})

    msg.content = new_content
    db.session.commit()
    return jsonify({"code": 200, "msg": "修改成功"})

# 4. 删除留言
@app.route("/api/del_msg", methods=["POST"])
def del_msg():
    data = request.get_json()
    msg_id = data.get("id")
    msg = Message.query.get(msg_id)
    if not msg:
        return jsonify({"code": 404, "msg": "留言不存在"})
    db.session.delete(msg)
    db.session.commit()
    return jsonify({"code": 200, "msg": "删除成功"})


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)