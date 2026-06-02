import requests
from flask import Flask, request

app = Flask(__name__)


@app.get("/fetch")
def fetch_url():
    url = request.args.get("url")
    response = requests.get(url)
    return {"status": response.status_code}
