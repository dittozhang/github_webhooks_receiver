import hashlib
import hmac
from flask import Flask, request
from configparser import ConfigParser


CONFIG_FILE_PATH = "./config.ini"


def verify_signature(payload_body, secret_token, signature_header):
    """Verify that the payload was sent from GitHub by validating SHA256.

    Raise and return 403 if not authorized.

    Args:
        payload_body: original request body to verify (request.body())
        secret_token: GitHub app webhook token (WEBHOOK_SECRET)
        signature_header: header received from GitHub (x-hub-signature-256)
    """
    if not signature_header:
        return "[Error]x-hub-signature-256 header is missing!", 403
    hash_object = hmac.new(secret_token.encode('utf-8'),
                           msg=payload_body,
                           digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    if not hmac.compare_digest(expected_signature, signature_header):
        return "[Error]Request signatures didn't match!", 403
    return "ok", 200


def create_app():
    app = Flask(__name__)

    config = ConfigParser()
    config.read(CONFIG_FILE_PATH)
    secret_token = config["github_webhook"]["secret_token"]

    @app.route("/", methods=["POST"])
    def receiver():
        return verify_signature(request.data,
                                secret_token,
                                request.headers["X-Hub-Signature-256"])

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=8080, ssl_context="adhoc")
