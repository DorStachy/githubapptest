import subprocess
import hashlib
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run_command():
    cmd = request.args.get("cmd", "echo hello")
    result = subprocess.check_output(cmd, shell=True)  # command injection
    return result


@app.route("/hash")
def hash_value():
    data = request.args.get("data", "")
    digest = hashlib.md5(data.encode()).hexdigest()  # weak hash
    return digest


if __name__ == "__main__":
    app.run(debug=True)