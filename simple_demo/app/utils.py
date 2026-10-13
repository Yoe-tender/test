from flask import jsonify

def success(data=None, msg="操作成功", code=200):
    return jsonify({
        "code": code,
        "msg": msg,
        "data": data
    })

def fail(msg="操作失败", code=400):
    return jsonify({
        "code": code,
        "msg": msg,
        "data": None
    })