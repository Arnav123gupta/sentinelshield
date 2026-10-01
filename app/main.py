from flask import Flask, jsonify, request

from app.core.request_protection import RequestProtection
from app.models.request import HTTPRequest

app = Flask(__name__)

protection = RequestProtection()


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def protected_request(path: str):
    http_request = HTTPRequest(
        method=request.method,
        path="/" + path,
        headers=dict(request.headers),
        query_params=request.args.to_dict(),
        body=request.get_data(as_text=True) or None,
        client_ip=request.remote_addr or "127.0.0.1",
    )

    decision = protection.check(http_request)

    if decision == "BLOCK":
        return jsonify({
            "status": "blocked",
            "message": "Request blocked by SentinelShield",
        }), 403

    return jsonify({
        "status": "allowed",
        "message": "Request passed SentinelShield protection",
        "path": http_request.path,
    }), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
