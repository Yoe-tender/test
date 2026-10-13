from app import create_app, db

app = create_app()

# 仅首次运行自动创建不存在的表，不会覆盖已有表
with app.app_context():
    db.create_all()
    print("数据表校验完成！")

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)