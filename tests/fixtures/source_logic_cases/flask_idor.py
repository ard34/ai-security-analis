from flask import Flask

app = Flask(__name__)


class Account:
    @classmethod
    def get(cls, account_id):
        return cls()


@app.get("/accounts/<account_id>")
def get_account(account_id):
    account = Account.get(account_id)
    return {"id": account.id, "balance": account.balance}
