from flask import Flask, request, send_file

app = Flask(__name__)


@app.get("/download/<filename>")
def download(filename):
    path = request.args.get("path", filename)
    return send_file("uploads/" + path)
