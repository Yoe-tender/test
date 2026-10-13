from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models import Message, User
from app.utils import success, fail

msg_bp = Blueprint("message", __name__)

# 获取留言列表（分页+搜索，兼容新旧数据）
@msg_bp.route("/list", methods=["GET"])
def get_list():
    page = request.args.get("page", 1, type=int)
    size = request.args.get("size", 5, type=int)
    keyword = request.args.get("keyword", "")

    query = Message.query
    if keyword:
        query = query.filter(Message.content.like(f"%{keyword}%"))
    query = query.order_by(Message.create_time.desc())
    page_data = query.paginate(page=page, per_page=size)

    res = []
    for item in page_data.items:
        display_name = item.user.username if item.user else item.username
        res.append({
            "id": item.id,
            "content": item.content,
            "user_id": item.user_id,
            "username": display_name,
            "create_time": str(item.create_time)
        })
    return success(data={
        "list": res,
        "total": page_data.total,
        "pages": page_data.pages,
        "current_page": page
    })

# 新增留言（登录可用）
@msg_bp.route("/add", methods=["POST"])
@jwt_required()
def add_msg():
    uid = int(get_jwt_identity())
    json_data = request.get_json()
    content = json_data.get("content", "").strip()
    if not content:
        return fail("留言内容不能为空")
    user = User.query.get(uid)
    new_msg = Message(
        username=user.username,
        content=content,
        user_id=uid
    )
    db.session.add(new_msg)
    db.session.commit()
    return success(msg="发布成功")

# 修改留言
@msg_bp.route("/update", methods=["POST"])
@jwt_required()
def update_msg():
    uid = int(get_jwt_identity())
    json_data = request.get_json()
    msg_id = json_data.get("id")
    content = json_data.get("content").strip()
    msg = Message.query.get(msg_id)
    if not msg:
        return fail("留言不存在")
    user = User.query.get(uid)
    if msg.user_id != uid and not user.is_admin:
        return fail("无权修改他人留言", code=403)
    msg.content = content
    db.session.commit()
    return success(msg="修改成功")

# 删除留言
@msg_bp.route("/delete", methods=["POST"])
@jwt_required()
def delete_msg():
    uid = int(get_jwt_identity())
    json_data = request.get_json()
    msg_id = json_data.get("id")
    msg = Message.query.get(msg_id)
    if not msg:
        return fail("留言不存在")
    user = User.query.get(uid)
    if msg.user_id != uid and not user.is_admin:
        return fail("无权删除他人留言", code=403)
    db.session.delete(msg)
    db.session.commit()
    return success(msg="删除成功")