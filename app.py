from flask import Flask, request, jsonify, render_template
from scanner import scan_single_ip, scan_range

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target = data.get("target")

    if not target:
        return jsonify({"error": "No target provided"}), 400

    # RANGE SCAN
    if "-" in target:
        base = target.split(".")[:-1]
        base_ip = ".".join(base)

        start, end = target.split(".")[-1].split("-")

        result = scan_range(base_ip, int(start), int(end))

    # SINGLE IP SCAN
    else:
        result = scan_single_ip(target)

    return jsonify({"open_ports": result})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)