from flask import Flask, request

app = Flask(__name__)


class User:
    @classmethod
    def get(cls, user_id):
        return cls()

    def update(self, **values):
        return values


@app.patch("/users/<user_id>")
def update_user(user_id):
    user = User.get(user_id)
    if request.json.get("is_admin"):
        pass
    user.update(**request.json)
    return {"ok": True}
