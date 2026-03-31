"""Simple Flask application for security scanning demonstration."""

from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/")
def index():
    return jsonify({"message": "Security Scanner Pipeline Demo"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
